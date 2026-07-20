#!/usr/bin/env python3
"""Decrypt TLS-PSK image records from a Goodix RTSEC usbmon capture.

TLS 1.2 with TLS_PSK_WITH_AES_128_CBC_SHA256 has no forward secrecy: given
the PSK and the client/server randoms visible in the capture, every
application-data record can be decrypted offline. The device is the TLS
client, so device->host records use the client-write keys.

Self-check: every decrypted record's HMAC-SHA256 is verified; a wrong PSK
or key schedule fails loudly instead of producing garbage.

Usage:
    python3 tls_capture_decrypt.py CAPTURE --psk HEX [--out DIR]
"""

from __future__ import annotations

import argparse
import hashlib
import hmac as hmac_mod
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import parse_goodix_pcap as pcap
import rtsec_codec as codec

MAC_LEN = 32  # SHA-256
KEY_LEN = 16  # AES-128
SENSOR_WIDTH = 88
SENSOR_HEIGHT = 108


def p_hash(secret: bytes, seed: bytes, size: int) -> bytes:
    out = b""
    a = seed
    while len(out) < size:
        a = hmac_mod.new(secret, a, hashlib.sha256).digest()
        out += hmac_mod.new(secret, a + seed, hashlib.sha256).digest()
    return out[:size]


def derive_keys(psk: bytes, client_random: bytes,
                server_random: bytes) -> dict:
    # RFC 4279 section 2, pure PSK: the premaster secret is
    # uint16(N) || N zero octets || uint16(N) || psk, with N = len(psk).
    premaster = struct.pack(">H", len(psk)) + bytes(len(psk)) \
        + struct.pack(">H", len(psk)) + psk
    master = p_hash(premaster, b"master secret" + client_random + server_random, 48)
    block = p_hash(master, b"key expansion" + server_random + client_random,
                   2 * MAC_LEN + 2 * KEY_LEN)
    return {
        "client_mac": block[0:MAC_LEN],
        "server_mac": block[MAC_LEN:2 * MAC_LEN],
        "client_key": block[2 * MAC_LEN:2 * MAC_LEN + KEY_LEN],
        "server_key": block[2 * MAC_LEN + KEY_LEN:],
    }


def decrypt_record(record: codec.TlsRecord, seq: int, key: bytes,
                   mac_secret: bytes) -> bytes:
    fragment = record.fragment
    iv, ciphertext = fragment[:KEY_LEN], fragment[KEY_LEN:]
    if len(ciphertext) % KEY_LEN or not ciphertext:
        raise codec.CodecError("ciphertext is not a non-empty AES block multiple")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    pad_len = padded[-1] + 1
    body, received_mac = padded[:-pad_len - MAC_LEN], padded[-pad_len - MAC_LEN:-pad_len]
    header = struct.pack(">QBHH", seq, record.content_type, record.version,
                         len(body))
    expected_mac = hmac_mod.new(mac_secret, header + body,
                                hashlib.sha256).digest()
    if not hmac_mod.compare_digest(received_mac, expected_mac):
        raise codec.CodecError(f"record seq={seq} HMAC verification failed")
    return body


def collect_sessions(capture: str):
    """Group TLS records per handshake: (client_random, server_random,
    [(direction, record, encrypted_seq)]) in wire order."""
    chunks = pcap.read_chunks(capture, None, None)
    frames = pcap.logical_frames(chunks, 0x01) + pcap.logical_frames(chunks, 0x82)
    frames.sort(key=lambda item: (item.epoch, item.frame_number))

    sessions = []
    current = None
    for frame in frames:
        pack = codec.decode_outer(frame.data)
        if pack.flags not in (codec.FLAGS_TRANSPORT_LAYER_SECURITY,
                              codec.FLAGS_TRANSPORT_LAYER_SECURITY_DATA):
            continue
        payload = pack.payload
        if pack.flags == codec.FLAGS_TRANSPORT_LAYER_SECURITY_DATA:
            payload = payload[codec.IMAGE_RECORD_PREFIX_LEN:]
        record = codec.parse_tls_record(payload)
        direction = "OUT" if frame.endpoint == 0x01 else "IN"

        if record.content_type == codec.TLS_HANDSHAKE:
            try:
                hs = codec.parse_tls_handshake(record.fragment)
            except codec.CodecError:
                hs = None  # encrypted handshake record
            if hs is not None and hs.msg_type == 0x01:
                current = {"client_random": hs.body[2:34],
                           "server_random": None, "records": []}
                sessions.append(current)
            elif hs is not None and hs.msg_type == 0x02 and current:
                current["server_random"] = hs.body[2:34]
        if current is not None:
            current["records"].append((direction, record, frame.frame_number))
    return sessions


def decrypt_session(session: dict, psk: bytes, out_dir: Path, tag: str) -> int:
    keys = derive_keys(psk, session["client_random"], session["server_random"])
    seq = {"IN": 0, "OUT": 0}  # encrypted-record counters per direction
    images = 0
    for direction, record, frame_number in session["records"]:
        if record.content_type == codec.TLS_CHANGE_CIPHER_SPEC:
            continue
        encrypted = record.content_type == codec.TLS_APPLICATION_DATA or (
            record.content_type == codec.TLS_HANDSHAKE
            and len(record.fragment) > 4
            and record.fragment[0] not in codec.TLS_HANDSHAKE_NAMES)
        if not encrypted:
            continue
        key = keys["client_key"] if direction == "IN" else keys["server_key"]
        mac = keys["client_mac"] if direction == "IN" else keys["server_mac"]
        body = decrypt_record(record, seq[direction], key, mac)
        seq[direction] += 1
        if record.content_type != codec.TLS_APPLICATION_DATA:
            print(f"  frame {frame_number}: decrypted handshake record "
                  f"({len(body)} bytes, HMAC ok)")
            continue
        images += 1
        image_bytes, trailer = body[:-4], body[-4:]
        pixels = codec.decode_image(image_bytes)
        raw_path = out_dir / f"{tag}-image-{images}.bin"
        pgm_path = out_dir / f"{tag}-image-{images}.pgm"
        raw_path.write_bytes(image_bytes)
        with pgm_path.open("w") as handle:
            handle.write(f"P2\n{SENSOR_WIDTH} {SENSOR_HEIGHT}\n4095\n")
            for row in range(SENSOR_HEIGHT):
                start = row * SENSOR_WIDTH
                handle.write(" ".join(str(v) for v in pixels[start:start + SENSOR_WIDTH]))
                handle.write("\n")
        print(f"  frame {frame_number}: image {images} decrypted "
              f"({len(image_bytes)} bytes, HMAC ok, trailer={trailer.hex()}) "
              f"-> {pgm_path}")
    return images


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture")
    parser.add_argument("--psk", required=True, help="hex-encoded 32-byte PSK")
    parser.add_argument("--out", default="captures/decrypted")
    args = parser.parse_args()

    psk = bytes.fromhex(args.psk)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    sessions = collect_sessions(args.capture)
    print(f"{len(sessions)} TLS session(s) found")
    total = 0
    for index, session in enumerate(sessions, 1):
        if session["server_random"] is None:
            print(f"session {index}: incomplete handshake, skipped")
            continue
        print(f"session {index}:")
        total += decrypt_session(session, psk, out_dir, f"session-{index}")
    print(f"{total} image record(s) decrypted")
    return 0 if total else 1


if __name__ == "__main__":
    sys.exit(main())
