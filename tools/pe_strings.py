#!/usr/bin/env python3
"""Minimal PE string locator for Windows driver reverse engineering."""

from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Section:
    name: str
    vaddr: int
    vsize: int
    raw_ptr: int
    raw_size: int


def read_c_string(data: bytes) -> str:
    return data.split(b"\0", 1)[0].decode("ascii", errors="replace")


def parse_pe(data: bytes) -> tuple[int, list[Section]]:
    if data[:2] != b"MZ":
        raise ValueError("not an MZ executable")

    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off:pe_off + 4] != b"PE\0\0":
        raise ValueError("not a PE executable")

    coff = pe_off + 4
    section_count = struct.unpack_from("<H", data, coff + 2)[0]
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    optional = coff + 20
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic == 0x20B:
        image_base = struct.unpack_from("<Q", data, optional + 24)[0]
    elif magic == 0x10B:
        image_base = struct.unpack_from("<I", data, optional + 28)[0]
    else:
        raise ValueError(f"unknown PE optional header magic 0x{magic:x}")

    sections: list[Section] = []
    section_off = optional + optional_size
    for idx in range(section_count):
        off = section_off + idx * 40
        name = read_c_string(data[off:off + 8])
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
        sections.append(Section(name, vaddr, vsize, raw_ptr, raw_size))

    return image_base, sections


def file_offset_to_rva(sections: list[Section], off: int) -> int | None:
    for sec in sections:
        if sec.raw_ptr <= off < sec.raw_ptr + sec.raw_size:
            return sec.vaddr + (off - sec.raw_ptr)
    return None


def iter_ascii(data: bytes, minimum: int):
    start = None
    for idx, byte in enumerate(data + b"\0"):
        valid = byte in (9, 10, 13) or 32 <= byte < 127
        if valid and start is None:
            start = idx
        elif not valid and start is not None:
            if idx - start >= minimum:
                yield start, data[start:idx].decode("ascii", errors="replace")
            start = None


def iter_utf16le(data: bytes, minimum: int):
    start = None
    chars: list[int] = []
    for idx in range(0, len(data) - 1, 2):
        code = data[idx] | (data[idx + 1] << 8)
        valid = code in (9, 10, 13) or 32 <= code < 127
        if valid:
            if start is None:
                start = idx
                chars = []
            chars.append(code)
        elif start is not None:
            if len(chars) >= minimum:
                yield start, "".join(chr(ch) for ch in chars)
            start = None
            chars = []


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("pe", type=Path)
    parser.add_argument("terms", nargs="*", help="case-insensitive substrings to match")
    parser.add_argument("--min", type=int, default=5, help="minimum string length")
    parser.add_argument("--all", action="store_true", help="print all strings")
    args = parser.parse_args()

    data = args.pe.read_bytes()
    image_base, sections = parse_pe(data)
    terms = [term.lower() for term in args.terms]

    rows = []
    for encoding, iterator in (("ascii", iter_ascii), ("utf16le", iter_utf16le)):
        for off, text in iterator(data, args.min):
            lowered = text.lower()
            if not args.all and terms and not any(term in lowered for term in terms):
                continue
            if not args.all and not terms:
                continue
            rva = file_offset_to_rva(sections, off)
            va = image_base + rva if rva is not None else None
            rows.append((va if va is not None else 0, off, encoding, text))

    for va, off, encoding, text in sorted(rows):
        va_text = f"0x{va:016x}" if va else "n/a"
        print(f"{va_text} file=0x{off:x} {encoding:7} {text}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
