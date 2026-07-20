#!/usr/bin/env python3
"""Replay a Goodix RTSEC usbmon capture as a semantic protocol transcript.

Read-only offline analysis: rebuilds logical frames with parse_goodix_pcap,
decodes them with rtsec_codec, prints one line per frame, and finishes with
a validation summary. Exits non-zero if any frame fails checksum or
structural validation.
"""

from __future__ import annotations

import argparse
import sys

import parse_goodix_pcap as pcap
import rtsec_codec as codec

TLS_CONTENT_NAMES = {
    codec.TLS_CHANGE_CIPHER_SPEC: "change_cipher_spec",
    codec.TLS_ALERT: "alert",
    codec.TLS_HANDSHAKE: "handshake",
    codec.TLS_APPLICATION_DATA: "application_data",
}


def describe_tls(payload: bytes, encrypted: bool) -> str:
    record = codec.parse_tls_record(payload)
    kind = TLS_CONTENT_NAMES.get(record.content_type,
                                 f"type_{record.content_type:#04x}")
    detail = (f"tls {kind} ver={record.version:#06x} "
              f"len={len(record.fragment)}")
    if record.content_type == codec.TLS_HANDSHAKE:
        if encrypted:
            # Post-ChangeCipherSpec records are encrypted; the handshake
            # header is not plaintext.
            return detail + " (encrypted)"
        handshake = codec.parse_tls_handshake(record.fragment)
        name = codec.TLS_HANDSHAKE_NAMES.get(handshake.msg_type,
                                             f"msg_{handshake.msg_type:#04x}")
        detail += f" {name}"
        if handshake.msg_type == 0x10:  # client_key_exchange
            detail += f" identity={codec.psk_identity(handshake)!r}"
    return detail


def describe_inner(direction: str, inner: codec.InnerFrame) -> str:
    name = codec.COMMAND_NAMES.get(inner.command, f"CMD_{inner.command:02x}")
    tag = name
    if not inner.checksummed:
        tag += "(no-checksum)"
    if inner.command == codec.COMMAND_ACK:
        cmd, status = codec.decode_ack(inner.payload)
        acked = codec.COMMAND_NAMES.get(cmd, f"CMD_{cmd:02x}")
        return f"{tag} {acked} status={status:#04x}"
    if inner.command == codec.COMMAND_PRESET_PSK_READ_R:
        if direction == "OUT":
            import struct
            flags, _ = struct.unpack("<II", inner.payload)
            return f"{tag} flags={flags:#010x}"
        result = codec.decode_psk_read_response(inner.payload)
        return (f"{tag} flags={result.flags:#010x} "
                f"data[{len(result.data)}]={result.data[:16].hex()}...")
    if inner.command in (codec.COMMAND_FIRMWARE_VERSION,
                         codec.COMMAND_GET_IAP_VERSION) and direction == "IN":
        return f"{tag} {inner.payload.split(bytes([0]))[0]!r}"
    return f"{tag} payload[{len(inner.payload)}]={inner.payload[:24].hex()}"


def describe_frame(frame: pcap.LogicalFrame, encrypted: set) -> str:
    direction = "OUT" if frame.endpoint == 0x01 else "IN "
    pack = codec.decode_outer(frame.data)
    prefix = f"{frame.frame_number:5d} {frame.epoch:.6f} {direction}"
    if pack.flags == codec.FLAGS_MESSAGE_PROTOCOL:
        return f"{prefix} {describe_inner(direction.strip(), codec.decode_inner(pack.payload))}"
    if pack.flags == codec.FLAGS_TRANSPORT_LAYER_SECURITY:
        detail = describe_tls(pack.payload, direction in encrypted)
        record = codec.parse_tls_record(pack.payload)
        if record.content_type == codec.TLS_CHANGE_CIPHER_SPEC:
            encrypted.add(direction)
        return f"{prefix} {detail}"
    if pack.flags == codec.FLAGS_TRANSPORT_LAYER_SECURITY_DATA:
        record = codec.parse_image_record(pack.payload)
        return (f"{prefix} IMAGE prefix={record.prefix.hex()} "
                f"tls_app_data[{len(record.tls.fragment)}]")
    return f"{prefix} outer={pack.flags:#04x} payload[{len(pack.payload)}]"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture")
    parser.add_argument("--start-epoch", type=float)
    parser.add_argument("--end-epoch", type=float)
    args = parser.parse_args()

    chunks = pcap.read_chunks(args.capture, args.start_epoch, args.end_epoch)
    frames = pcap.logical_frames(chunks, 0x01) + pcap.logical_frames(chunks, 0x82)
    frames.sort(key=lambda item: (item.epoch, item.frame_number))

    failures = 0
    encrypted: set = set()
    for frame in frames:
        try:
            print(describe_frame(frame, encrypted))
        except codec.CodecError as error:
            failures += 1
            print(f"{frame.frame_number:5d} {frame.epoch:.6f} "
                  f"DECODE-ERROR {error} raw={frame.data[:24].hex()}")

    print(f"\n{len(frames)} logical frames, {failures} validation failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
