#!/usr/bin/env python3
"""Extract the pairing-key inputs from `goodix-probe rt-psk-read` output.

The probe prints every USB read as a hex dump. This finds the two
PRESET_PSK_READ_R (0xe4) responses and writes:

- the DPAPI-encrypted PSK blob (TLV 0xbb010002), to decrypt in Windows with
  tools/windows/unseal-psk.ps1, and
- the PSK hash (TLV 0xbb020007), the second line of psk.hex.

Usage:
    ./build/goodix-probe rt-psk-read > captures/psk-read.txt
    python3 tools/extract_psk.py captures/psk-read.txt \\
        --blob captures/psk_dpapi_blob.bin --hash captures/psk_hash.hex
"""

import argparse
import re
import sys

import rtsec_codec as codec

TLV_DPAPI_BLOB = 0xBB010002
TLV_PSK_HASH = 0xBB020007
# Every DPAPI blob starts with version 1 and the DPAPI provider GUID
# {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}.
DPAPI_PREFIX = bytes.fromhex("01000000d08c9ddf0115d1118c7a00c04fc297eb")

READ_HEADER = re.compile(r"^read \((\d+) bytes\):")
HEX_LINE = re.compile(r"^\s+[0-9a-f]{4}:((?: [0-9a-f]{2})+)\s*$")


def read_dumps(text: str) -> list[bytes]:
    """Return the payload of every `read (N bytes):` dump, in order."""
    dumps: list[bytes] = []
    current: bytearray | None = None
    expected = 0
    for line in text.splitlines():
        header = READ_HEADER.match(line)
        if header:
            current = bytearray()
            expected = int(header.group(1))
            dumps.append(b"")
            continue
        hex_line = HEX_LINE.match(line)
        if current is not None and hex_line:
            current.extend(bytes.fromhex(hex_line.group(1).replace(" ", "")))
            dumps[-1] = bytes(current)
            continue
        if current is not None and len(current) != expected:
            raise SystemExit(
                f"extract_psk: a read dump ended after {len(current)} of "
                f"{expected} bytes. Re-run the probe; the output looks cut off.")
        current = None
    return dumps


def find_tlvs(dumps: list[bytes]) -> dict[int, bytes]:
    tlvs: dict[int, bytes] = {}
    for dump in dumps:
        try:
            frame = codec.decode_command(dump)
        except codec.CodecError:
            continue  # ACKs and other packs are not PSK read responses
        if frame.command != codec.COMMAND_PRESET_PSK_READ_R:
            continue
        result = codec.decode_psk_read_response(frame.payload)
        tlvs[result.flags] = result.data
    return tlvs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("probe_output", help="saved `goodix-probe rt-psk-read` output")
    parser.add_argument("--blob", required=True, help="where to write the DPAPI blob")
    parser.add_argument("--hash", required=True, help="where to write the PSK hash (hex)")
    args = parser.parse_args()

    with open(args.probe_output, encoding="utf-8") as f:
        tlvs = find_tlvs(read_dumps(f.read()))

    blob = tlvs.get(TLV_DPAPI_BLOB)
    psk_hash = tlvs.get(TLV_PSK_HASH)
    missing = [name for name, value in
               (("DPAPI blob (TLV 0xbb010002)", blob), ("PSK hash (TLV 0xbb020007)", psk_hash))
               if value is None]
    if missing:
        print(f"extract_psk: no {' or '.join(missing)} in {args.probe_output}. "
              "Check that the probe reported both reads without errors, and "
              "that fprintd was not using the reader at the time.", file=sys.stderr)
        return 1
    if not blob.startswith(DPAPI_PREFIX):
        print("extract_psk: TLV 0xbb010002 is not a DPAPI blob, so this reader "
              "was not paired by the Windows driver (or uses another key "
              "scheme). Nothing was written.", file=sys.stderr)
        return 1
    if len(psk_hash) != 32:
        print(f"extract_psk: expected a 32-byte PSK hash, got {len(psk_hash)} "
              "bytes. Nothing was written.", file=sys.stderr)
        return 1

    with open(args.blob, "wb") as f:
        f.write(blob)
    with open(args.hash, "w", encoding="ascii") as f:
        f.write(psk_hash.hex() + "\n")
    print(f"wrote {len(blob)}-byte DPAPI blob to {args.blob}")
    print(f"wrote PSK hash to {args.hash}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
