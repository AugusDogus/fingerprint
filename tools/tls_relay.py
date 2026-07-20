#!/usr/bin/env python3
"""Establish a live TLS-PSK session with the Goodix 27c6:5584 from Linux.

Mirrors the Windows driver flow proven by the usbmon capture and the public
goodix-fp-dump tool: send MCU command 0xd0 (REQUEST_TLS_CONNECTION), then
relay TLS records between the USB bulk endpoints (outer type 0xb0) and a
local `openssl s_server -psk` process. The device is the TLS client and
presents the PSK identity "Client_identity".

Read-only with respect to persistent device state: sends only the 0xd0
session request plus TLS records.

Usage:
    .venv/bin/python tools/tls_relay.py --psk HEX [--timeout 15]
"""

from __future__ import annotations

import argparse
import os
import select
import socket
import subprocess
import sys
import time

import usb.core
import usb.util

sys.path.insert(0, str(__file__.rsplit("/", 1)[0]))
import rtsec_codec as codec

VID, PID = 0x27C6, 0x5584
EP_OUT, EP_IN = 0x01, 0x82
PORT = 4433
HANDSHAKE_DONE_MARKERS = ("CIPHER", "Secure Renegotiation")


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


def usb_read_frame(device, timeout_ms: int):
    try:
        data = bytes(device.read(EP_IN, 65536, timeout=timeout_ms))
    except usb.core.USBTimeoutError:
        return None
    return codec.decode_outer(data)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--psk", required=True, help="hex-encoded 32-byte PSK")
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--one-pack", action="store_true",
                        help="forward each socket read as one 0xb0 pack "
                             "(goodix-fp-dump style) instead of one pack per "
                             "TLS record (Windows style)")
    args = parser.parse_args()

    psk = bytes.fromhex(args.psk)
    if len(psk) != 32:
        raise SystemExit("PSK must be 32 bytes")

    device = open_device()
    print("claimed device")

    server = subprocess.Popen(
        ["openssl", "s_server", "-nocert", "-psk", args.psk,
         "-port", str(PORT)],
        # s_server closes the accepted connection on stdin EOF; keep a pipe
        # open (never written) so the handshake can complete.
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        bufsize=1)
    assert server.stdout is not None
    try:
        time.sleep(0.5)
        tls = socket.create_connection(("127.0.0.1", PORT), timeout=5)
        tls.setblocking(False)

        # REQUEST_TLS_CONNECTION (0xd0), payload 00 00, exactly as captured.
        usb_write(device, codec.encode_command(
            codec.COMMAND_REQUEST_TLS_CONNECTION, b"\x00\x00"))
        ack = usb_read_frame(device, 3000)
        if ack is None:
            raise SystemExit("no ACK for TLS request")
        inner = codec.decode_inner(ack.payload)
        cmd, status = codec.decode_ack(inner.payload)
        print(f"TLS request ACK: cmd={cmd:#04x} status={status:#04x}")

        hello = usb_read_frame(device, 3000)
        if hello is None or hello.flags != codec.FLAGS_TRANSPORT_LAYER_SECURITY:
            raise SystemExit("no ClientHello from device")
        tls.sendall(hello.payload)
        print("relayed device ClientHello -> TLS server")

        deadline = time.monotonic() + args.timeout
        success = False
        os.set_blocking(server.stdout.fileno(), False)
        log_buffer = ""
        while time.monotonic() < deadline and not success:
            # socket -> device
            ready, _, _ = select.select([tls, server.stdout], [], [], 0.05)
            if tls in ready:
                data = tls.recv(65536)
                if not data:
                    print("TLS socket closed")
                    break
                while data:
                    length = int.from_bytes(data[3:5], "big") + 5
                    if args.one_pack:
                        # public goodix-fp-dump style: each socket read goes
                        # out as a single 0xb0 pack, records concatenated
                        length = len(data)
                    frame = codec.encode_outer(
                        data[:length], codec.FLAGS_TRANSPORT_LAYER_SECURITY)
                    usb_write(device, frame)
                    print(f"relayed TLS record(s) -> device ({length} bytes) "
                          f"type={data[0]:#04x}")
                    data = data[length:]
                    if data:
                        # The MCU may drop back-to-back bulk OUT transfers;
                        # Windows spaces consecutive records by ~15 ms.
                        time.sleep(0.02)
            if server.stdout in ready:
                chunk = server.stdout.read()
                if chunk:
                    log_buffer += chunk
                    while "\n" in log_buffer:
                        line, log_buffer = log_buffer.split("\n", 1)
                        print(f"s_server: {line}")
                        if any(marker in line
                               for marker in HANDSHAKE_DONE_MARKERS):
                            success = True
                        if "error" in line.lower() or "alert" in line.lower():
                            print("server reported an error")
                            return 1

            # device -> socket
            pack = usb_read_frame(device, 50)
            if pack is not None:
                if pack.flags != codec.FLAGS_TRANSPORT_LAYER_SECURITY:
                    print(f"unexpected pack flags={pack.flags:#04x}")
                    continue
                tls.sendall(pack.payload)
                print(f"relayed TLS record -> server "
                      f"({len(pack.payload)} bytes)")

        if success:
            print("TLS-PSK handshake completed from Linux")
            return 0
        print("handshake did not complete before timeout")
        return 1
    finally:
        server.terminate()
        usb.util.release_interface(device, 0)


if __name__ == "__main__":
    sys.exit(main())
