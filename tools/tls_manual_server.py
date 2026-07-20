#!/usr/bin/env python3
"""Live TLS-PSK session with the Goodix 27c6:5584 using a self-hosted
replay server — no openssl in the loop.

Sends 0xd0 (REQUEST_TLS_CONNECTION), answers the device ClientHello with a
fixed ServerHello + ServerHelloDone (the byte-exact records Windows used,
with a fixed server random), then completes TLS 1.2
TLS_PSK_WITH_AES_128_CBC_SHA256 in-process: verifies the device Finished
against the recovered PSK and sends our own CCS + Finished.

Because the server random is chosen by us, the session keys are known; a
verified device Finished proves the full session was established from Linux.

No persistent device-state changes: only 0xd0 plus TLS records are sent.

Usage:
    .venv/bin/python tools/tls_manual_server.py --psk HEX [--timeout 15]
"""

from __future__ import annotations

import argparse
import hashlib
import hmac as hmac_mod
import os
import struct
import sys
import time

import usb.core
import usb.util
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

sys.path.insert(0, str(__file__.rsplit("/", 1)[0]))
import rtsec_codec as codec
from tls_capture_decrypt import derive_keys, decrypt_record, MAC_LEN, KEY_LEN

VID, PID = 0x27C6, 0x5584
EP_OUT, EP_IN = 0x01, 0x82

# Byte-exact ServerHello + ServerHelloDone as sent by the Windows driver
# (capture frames 8008/8012). The server random inside is fixed; this is a
# local interoperability diagnostic, not a production endpoint.
SERVER_HELLO = bytes.fromhex(
    "16030300510200004d0303c5d64262389e721ed4c7408e9852a4609d3fe03abc0412"
    "59c7e9d25855a4d3e2201ef31862a0210ce7decfd967deddf49dd52ee05a4b3e7424"
    "edeed8e59e11368b00ae000005ff01000100")
SERVER_HELLO_DONE = bytes.fromhex("16030300040e000000")
CHANGE_CIPHER_SPEC = bytes.fromhex("140303000101")


def open_device():
    device = usb.core.find(idVendor=VID, idProduct=PID)
    if device is None:
        raise SystemExit(f"device {VID:04x}:{PID:04x} not found")
    if device.is_kernel_driver_active(0):
        device.detach_kernel_driver(0)
    device.set_configuration()
    usb.util.claim_interface(device, 0)
    return device


def usb_write(device, frame: bytes) -> None:
    # Windows submits bulk OUT as separate 64-byte URBs (capture frames
    # 6748/6750); a single URB larger than 64 bytes is not accepted by the
    # MCU receive path.
    padded = frame + bytes((-len(frame)) % 64)
    for offset in range(0, len(padded), 64):
        device.write(EP_OUT, padded[offset:offset + 64], timeout=2000)


def usb_read_pack(device, timeout_ms: int):
    try:
        data = bytes(device.read(EP_IN, 65536, timeout=timeout_ms))
    except usb.core.USBTimeoutError:
        return None
    return codec.decode_outer(data)


def read_tls_record(device, timeout_ms: int, label: str):
    pack = usb_read_pack(device, timeout_ms)
    if pack is None:
        raise SystemExit(f"timeout waiting for {label}")
    if pack.flags != codec.FLAGS_TRANSPORT_LAYER_SECURITY:
        raise SystemExit(f"expected TLS pack for {label}, got {pack.flags:#04x}")
    return codec.parse_tls_record(pack.payload)


def encrypt_record(content_type: int, seq: int, body: bytes, key: bytes,
                   mac_secret: bytes) -> bytes:
    header = struct.pack(">QBHH", seq, content_type, 0x0303, len(body))
    mac = hmac_mod.new(mac_secret, header + body, hashlib.sha256).digest()
    padded = body + mac
    pad_len = KEY_LEN - (len(padded) % KEY_LEN)
    padded += bytes([pad_len - 1]) * pad_len
    iv = os.urandom(KEY_LEN)
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    fragment = iv + encryptor.update(padded) + encryptor.finalize()
    return struct.pack(">BHH", content_type, 0x0303, len(fragment)) + fragment


def drain(device, first_timeout_ms=3000, quiet=False):
    """Read packs until the response window closes; returns the last pack."""
    last = None
    timeout = first_timeout_ms
    while True:
        pack = usb_read_pack(device, timeout)
        if pack is None:
            return last
        timeout = 250
        last = pack
        if quiet:
            continue
        if pack.flags == codec.FLAGS_MESSAGE_PROTOCOL:
            inner = codec.decode_inner(pack.payload)
            name = codec.COMMAND_NAMES.get(inner.command,
                                           f"CMD_{inner.command:02x}")
            print(f"  {name} {inner.payload[:24].hex()}")
        else:
            print(f"  pack flags={pack.flags:#04x} len={len(pack.payload)}")


def warm_up(device):
    """Read-only prefix of the captured Windows warm-boot sequence:
    NOP, version x2, PSK TLV reads, version, IAP, version,
    register read, NOP, OTP read."""
    steps = [
        (codec.COMMAND_NOP, b"\x00\x00\x00\x00"),
        (codec.COMMAND_FIRMWARE_VERSION, b"\x00\x00"),
        (codec.COMMAND_FIRMWARE_VERSION, b"\x00\x00"),
        (codec.COMMAND_PRESET_PSK_READ_R, codec.encode_psk_read(0xBB010002)),
        (codec.COMMAND_PRESET_PSK_READ_R, codec.encode_psk_read(0xBB020007)),
        (codec.COMMAND_FIRMWARE_VERSION, b"\x00\x00"),
        (codec.COMMAND_GET_IAP_VERSION, b"\x19\x00"),
        (codec.COMMAND_FIRMWARE_VERSION, b"\x00\x00"),
        # Sensor-chip reset (approved by user): reset_sensor=True,
        # soft_reset_mcu=False, 20 ms — the exact payload Windows sends at
        # every init. Volatile; no persistent state change.
        (codec.COMMAND_RESET, bytes.fromhex("0514")),
        (codec.COMMAND_READ_SENSOR_REGISTER,
         bytes.fromhex("0000000400")),
        (codec.COMMAND_NOP, b"\x00\x00\x00\x00"),
        (codec.COMMAND_READ_OTP, b"\x00\x00"),
    ]
    for command, payload in steps:
        name = codec.COMMAND_NAMES.get(command, f"CMD_{command:02x}")
        print(f"warm-up: {name}")
        usb_write(device, codec.encode_command(command, payload))
        drain(device)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--psk", required=True, help="hex-encoded 32-byte PSK")
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--warmup", action="store_true",
                        help="send the read-only Windows warm-boot command "
                             "sequence before the TLS request")
    args = parser.parse_args()
    psk = bytes.fromhex(args.psk)
    if len(psk) != 32:
        raise SystemExit("PSK must be 32 bytes")

    device = open_device()
    print("claimed device")
    try:
        if args.warmup:
            warm_up(device)
        usb_write(device, codec.encode_command(
            codec.COMMAND_REQUEST_TLS_CONNECTION, b"\x00\x00"))
        ack = usb_read_pack(device, 3000)
        inner = codec.decode_inner(ack.payload)
        print(f"TLS request ACK: {codec.decode_ack(inner.payload)}")

        hello_record = read_tls_record(device, 3000, "ClientHello")
        hello = codec.parse_tls_handshake(hello_record.fragment)
        client_random = hello.body[2:34]
        print(f"ClientHello: random={client_random.hex()}")

        server_random = SERVER_HELLO[11:43]
        # Answer immediately; Windows responds ~2 ms after the hello.
        usb_write(device, codec.encode_outer(
            SERVER_HELLO, codec.FLAGS_TRANSPORT_LAYER_SECURITY))
        time.sleep(0.02)
        usb_write(device, codec.encode_outer(
            SERVER_HELLO_DONE, codec.FLAGS_TRANSPORT_LAYER_SECURITY))
        print("sent ServerHello + ServerHelloDone")

        cke_record = read_tls_record(device, int(args.timeout * 1000),
                                     "ClientKeyExchange")
        cke = codec.parse_tls_handshake(cke_record.fragment)
        identity = codec.psk_identity(cke)
        print(f"ClientKeyExchange: identity={identity!r}")
        if identity != b"Client_identity":
            raise SystemExit("unexpected PSK identity")

        ccs = read_tls_record(device, 5000, "ChangeCipherSpec")
        if ccs.content_type != codec.TLS_CHANGE_CIPHER_SPEC:
            raise SystemExit("expected ChangeCipherSpec")

        keys = derive_keys(psk, client_random, server_random)
        finished_record = read_tls_record(device, 5000, "Finished")
        finished_body = decrypt_record(finished_record, 0, keys["client_key"],
                                       keys["client_mac"])
        print("decrypted device Finished (HMAC ok)")

        handshake_messages = (hello_record.fragment + SERVER_HELLO[5:86]
                              + SERVER_HELLO_DONE[5:] + cke_record.fragment)
        from tls_capture_decrypt import p_hash
        master = p_hash(
            struct.pack(">H", 32) + bytes(32) + struct.pack(">H", 32) + psk,
            b"master secret" + client_random + server_random, 48)
        digest = hashlib.sha256(handshake_messages).digest()
        expected_verify = p_hash(master, b"client finished" + digest, 12)
        if finished_body != b"\x14\x00\x00\x0c" + expected_verify:
            raise SystemExit("device Finished verify_data mismatch")
        print("device Finished verify_data matches — session keys confirmed")

        server_verify = p_hash(
            master, b"server finished"
            + hashlib.sha256(handshake_messages + finished_body).digest(), 12)
        usb_write(device, codec.encode_outer(
            CHANGE_CIPHER_SPEC, codec.FLAGS_TRANSPORT_LAYER_SECURITY))
        time.sleep(0.02)
        our_finished = encrypt_record(codec.TLS_HANDSHAKE, 0,
                                      b"\x14\x00\x00\x0c" + server_verify,
                                      keys["server_key"], keys["server_mac"])
        usb_write(device, codec.encode_outer(
            our_finished, codec.FLAGS_TRANSPORT_LAYER_SECURITY))
        print("sent our CCS + Finished")
        print("TLS-PSK session established from Linux (self-hosted server)")
        return 0
    finally:
        usb.util.release_interface(device, 0)


if __name__ == "__main__":
    sys.exit(main())
