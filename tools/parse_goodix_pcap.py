#!/usr/bin/env python3
"""Extract Goodix logical frames from a Linux usbmon pcapng capture."""

from __future__ import annotations

import argparse
import dataclasses
import subprocess
from collections.abc import Iterable


@dataclasses.dataclass
class UsbChunk:
    frame_number: int
    epoch: float
    endpoint: int
    data: bytes


@dataclasses.dataclass
class LogicalFrame:
    frame_number: int
    epoch: float
    endpoint: int
    data: bytes


def read_chunks(capture: str, start: float | None, end: float | None) -> list[UsbChunk]:
    display_filter = [
        "usb.bus_id == 1",
        "usb.device_address == 2",
        "usb.transfer_type == 3",
        "usb.data_len > 0",
    ]
    if start is not None:
        display_filter.append(f"frame.time_epoch >= {start}")
    if end is not None:
        display_filter.append(f"frame.time_epoch <= {end}")

    command = [
        "tshark",
        "-r",
        capture,
        "-Y",
        " && ".join(display_filter),
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-e",
        "frame.number",
        "-e",
        "frame.time_epoch",
        "-e",
        "usb.endpoint_address",
        "-e",
        "usb.capdata",
    ]
    result = subprocess.run(command, check=True, capture_output=True, text=True)

    chunks: list[UsbChunk] = []
    for line in result.stdout.splitlines():
        columns = line.split("\t")
        if len(columns) != 4 or not columns[3]:
            continue
        chunks.append(
            UsbChunk(
                frame_number=int(columns[0]),
                epoch=float(columns[1]),
                endpoint=int(columns[2], 0),
                data=bytes.fromhex(columns[3]),
            )
        )
    return chunks


def logical_frames(chunks: Iterable[UsbChunk], endpoint: int) -> list[LogicalFrame]:
    frames: list[LogicalFrame] = []
    pending = bytearray()
    expected = 0
    first_chunk: UsbChunk | None = None

    for chunk in chunks:
        if chunk.endpoint != endpoint:
            continue

        if not pending:
            if len(chunk.data) < 4:
                continue
            first_chunk = chunk
            expected = 4 + int.from_bytes(chunk.data[1:3], "little")
            if expected < 4:
                continue

        needed = expected - len(pending)
        pending.extend(chunk.data[:needed])
        if len(pending) == expected and first_chunk is not None:
            frames.append(
                LogicalFrame(
                    frame_number=first_chunk.frame_number,
                    epoch=first_chunk.epoch,
                    endpoint=endpoint,
                    data=bytes(pending),
                )
            )
            pending.clear()
            expected = 0
            first_chunk = None

    return frames


def printable(data: bytes, limit: int = 48) -> str:
    return "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in data[:limit])


def describe(frame: LogicalFrame) -> str:
    data = frame.data
    direction = "OUT" if frame.endpoint == 0x01 else "IN "
    outer_ok = len(data) >= 4 and ((data[0] + data[1] + data[2]) & 0xFF) == data[3]
    outer_type = data[0] if data else 0
    header = (
        f"{frame.frame_number:5d} {frame.epoch:.6f} {direction} "
        f"outer={outer_type:02x} len={len(data):5d} outer_ck={'ok' if outer_ok else 'BAD'}"
    )

    if len(data) >= 8 and outer_type & 0xF0 == 0xA0:
        inner = data[4:]
        command = inner[0]
        declared = int.from_bytes(inner[1:3], "little")
        payload = inner[3:-1]
        checksum = inner[-1]
        expected_checksum = (0xAA - sum(inner[:-1])) & 0xFF
        return (
            f"{header} cmd={command:02x} inner_len={declared:4d} "
            f"inner_ck={'ok' if checksum == expected_checksum else 'BAD'} "
            f"payload={payload[:48].hex()} ascii={printable(payload)}"
        )

    payload = data[4:]
    tls = ""
    if len(payload) >= 5 and payload[0] in (0x14, 0x15, 0x16, 0x17):
        tls_length = int.from_bytes(payload[3:5], "big")
        tls = f" tls_type={payload[0]:02x} tls_ver={payload[1:3].hex()} tls_len={tls_length}"
    return f"{header}{tls} payload={payload[:48].hex()} ascii={printable(payload)}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("capture")
    parser.add_argument("--start-epoch", type=float)
    parser.add_argument("--end-epoch", type=float)
    args = parser.parse_args()

    chunks = read_chunks(args.capture, args.start_epoch, args.end_epoch)
    frames = logical_frames(chunks, 0x01) + logical_frames(chunks, 0x82)
    for frame in sorted(frames, key=lambda item: (item.epoch, item.frame_number)):
        print(describe(frame))


if __name__ == "__main__":
    main()
