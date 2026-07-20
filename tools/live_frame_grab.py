#!/usr/bin/env python3
"""Grab raw decrypted sensor frames from the Goodix 27c6:5584 live.

Establishes the TLS-PSK session (same self-hosted replay server as
tls_manual_server.py), uploads the MCU config, then captures a baseline
frame (36 + 20) and a finger frame (32 FDT-down + 20), decrypting both
with the session keys. Raw 14256-byte 12-bit frames are written out for
offline decode/geometry experiments.

Usage:
    .venv/bin/python tools/live_frame_grab.py --psk HEX [--finger-out FILE]
        [--baseline-out FILE] [--no-finger]
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
import time

import usb.core
import usb.util

sys.path.insert(0, str(__file__.rsplit("/", 1)[0]))
import rtsec_codec as codec
from tls_capture_decrypt import derive_keys, decrypt_record, p_hash
from tls_manual_server import (
    SERVER_HELLO,
    SERVER_HELLO_DONE,
    CHANGE_CIPHER_SPEC,
    open_device,
    usb_write,
    usb_read_pack,
    read_tls_record,
    encrypt_record,
)

FDT_MODE_WARM = bytes.fromhex(
    "0d0180a780be80bb80aa80ad80ca80c080b180a380bd80b880a9")
FDT_DOWN = bytes.fromhex(
    "0c0180b080c480ba80a680b780c780c080aa80b480c480ba80a6")
DEVICE_CONFIG = bytes.fromhex(
    "6011607124952cc114d510e500e514f9030402000008001111ba000180ca0007"
    "008400c0b38600bbc48800baba8a00b2b28c00aaaa8e00c1c19000bbbb9200b1"
    "b1940000a8960000b6980000bf9a0000ba50000105d000000070000000720078"
    "56740034122600001220001040120003042a0102002200012024003200800001"
    "005c008000560008205800010032002c028200800cba000180ca0007002a0182"
    "03200010402200012024001400800005005c0000015600082058000300820080"
    "142a0108005c0080006200090364001800220000202a0108005c000001520008"
    "0054000001000000000000000000000000000000000000000000000000009a69")


def send_command(device, command: int, payload: bytes, read_data=True,
                 quiet=False, timeout_ms=5000):
    usb_write(device, codec.encode_command(command, payload))
    name = codec.COMMAND_NAMES.get(command, f"CMD_{command:02x}")
    while True:
        pack = usb_read_pack(device, timeout_ms)
        if pack is None:
            raise SystemExit(f"timeout waiting for {name} response")
        if pack.flags != codec.FLAGS_MESSAGE_PROTOCOL:
            continue
        inner = codec.decode_inner(pack.payload)
        if inner.command == codec.COMMAND_ACK:
            if not quiet:
                print(f"  {name} ACK {inner.payload.hex()}")
            if not read_data:
                return inner.payload
            continue
        if not quiet:
            print(f"  {name} {inner.payload[:16].hex()}")
        return inner.payload


def establish_tls(device, psk: bytes):
    usb_write(device, codec.encode_command(
        codec.COMMAND_REQUEST_TLS_CONNECTION, b"\x00\x00"))
    send_ack = usb_read_pack(device, 3000)
    inner = codec.decode_inner(send_ack.payload)
    print(f"TLS request ACK: {codec.decode_ack(inner.payload)}")

    hello_record = read_tls_record(device, 3000, "ClientHello")
    hello = codec.parse_tls_handshake(hello_record.fragment)
    client_random = hello.body[2:34]

    usb_write(device, codec.encode_outer(
        SERVER_HELLO, codec.FLAGS_TRANSPORT_LAYER_SECURITY))
    time.sleep(0.02)
    usb_write(device, codec.encode_outer(
        SERVER_HELLO_DONE, codec.FLAGS_TRANSPORT_LAYER_SECURITY))

    cke_record = read_tls_record(device, 10000, "ClientKeyExchange")
    cke = codec.parse_tls_handshake(cke_record.fragment)
    assert codec.psk_identity(cke) == b"Client_identity"
    ccs = read_tls_record(device, 5000, "ChangeCipherSpec")
    assert ccs.content_type == codec.TLS_CHANGE_CIPHER_SPEC

    server_random = SERVER_HELLO[11:43]
    keys = derive_keys(psk, client_random, server_random)

    finished_record = read_tls_record(device, 5000, "Finished")
    finished_body = decrypt_record(finished_record, 0, keys["client_key"],
                                   keys["client_mac"])

    messages = (hello_record.fragment + SERVER_HELLO[5:86]
                + SERVER_HELLO_DONE[5:] + cke_record.fragment)
    master = p_hash(
        struct.pack(">H", 32) + bytes(32) + struct.pack(">H", 32) + psk,
        b"master secret" + client_random + server_random, 48)
    expected = p_hash(
        master, b"client finished" + hashlib.sha256(messages).digest(), 12)
    assert finished_body == b"\x14\x00\x00\x0c" + expected, "Finished mismatch"
    print("device Finished verified")

    server_verify = p_hash(
        master, b"server finished"
        + hashlib.sha256(messages + finished_body).digest(), 12)
    usb_write(device, codec.encode_outer(
        CHANGE_CIPHER_SPEC, codec.FLAGS_TRANSPORT_LAYER_SECURITY))
    time.sleep(0.02)
    usb_write(device, codec.encode_outer(
        encrypt_record(codec.TLS_HANDSHAKE, 0, b"\x14\x00\x00\x0c"
                       + server_verify,
                       keys["server_key"], keys["server_mac"]),
        codec.FLAGS_TRANSPORT_LAYER_SECURITY))
    print("TLS session established")
    return keys


def grab_image(device, keys, seq: int, label: str) -> bytes:
    usb_write(device, codec.encode_command(
        codec.COMMAND_MCU_GET_IMAGE, b"\x01\x00"))
    while True:
        pack = usb_read_pack(device, 30000)
        if pack is None:
            raise SystemExit(f"timeout waiting for {label} image")
        if pack.flags == codec.FLAGS_MESSAGE_PROTOCOL:
            continue  # ACK
        if pack.flags != codec.FLAGS_TRANSPORT_LAYER_SECURITY_DATA:
            print(f"  unexpected pack {pack.flags:#04x}")
            continue
        record = codec.parse_image_record(pack.payload).tls
        body = decrypt_record(record, seq, keys["client_key"],
                              keys["client_mac"])
        print(f"  {label}: {len(body)} bytes decrypted (HMAC ok)")
        return body[:-4]  # strip trailer -> 14256 raw bytes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--psk", required=True)
    parser.add_argument("--baseline-out", default="captures/grab-baseline.raw")
    parser.add_argument("--finger-out", default="captures/grab-finger.raw")
    parser.add_argument("--no-finger", action="store_true")
    args = parser.parse_args()
    psk = bytes.fromhex(args.psk)

    device = open_device()
    print("claimed device")
    try:
        send_command(device, codec.COMMAND_NOP, b"\x00" * 4, read_data=False)
        send_command(device, codec.COMMAND_RESET, bytes.fromhex("0514"))
        send_command(device, codec.COMMAND_UPLOAD_CONFIG_MCU, DEVICE_CONFIG)
        keys = establish_tls(device, psk)

        send_command(device, codec.COMMAND_MCU_SWITCH_TO_FDT_MODE,
                     FDT_MODE_WARM)
        baseline = grab_image(device, keys, seq=1, label="baseline")
        with open(args.baseline_out, "wb") as handle:
            handle.write(baseline)
        print(f"baseline frame -> {args.baseline_out}")

        if not args.no_finger:
            print("place finger ON the sensor and hold")
            send_command(device, codec.COMMAND_MCU_SWITCH_TO_FDT_MODE,
                         FDT_MODE_WARM)
            finger_mode = grab_image(device, keys, seq=2, label="finger-36")
            out = args.finger_out.replace(".raw", "-36.raw")
            with open(out, "wb") as handle:
                handle.write(finger_mode)
            print(f"finger frame (36 mode) -> {out}")

            send_command(device, codec.COMMAND_MCU_SWITCH_TO_FDT_MODE,
                         FDT_MODE_WARM)
            send_command(device, codec.COMMAND_MCU_SWITCH_TO_IDLE_MODE,
                         b"\x14\x00", read_data=False)
            send_command(device, codec.COMMAND_READ_SENSOR_REGISTER,
                         bytes.fromhex("0082000200"))
            send_command(device, codec.COMMAND_MCU_SWITCH_TO_FDT_DOWN,
                         FDT_DOWN, timeout_ms=240000)
            finger_down = grab_image(device, keys, seq=3, label="finger-32")
            with open(args.finger_out, "wb") as handle:
                handle.write(finger_down)
            print(f"finger frame (32 fdt-down) -> {args.finger_out}")
        return 0
    finally:
        usb.util.release_interface(device, 0)


if __name__ == "__main__":
    sys.exit(main())
