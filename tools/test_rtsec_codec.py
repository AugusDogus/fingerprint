#!/usr/bin/env python3
"""Unit tests for rtsec_codec, using capture-confirmed byte strings.

Every literal here appears in captures/windows-init-20260713-131745.pcapng
or in the confirmed frame list in docs/protocol-notes.md.
"""

import unittest

from rtsec_codec import (
    CodecError,
    COMMAND_FIRMWARE_VERSION,
    COMMAND_NOP,
    COMMAND_PRESET_PSK_READ_R,
    COMMAND_REQUEST_TLS_CONNECTION,
    TLS_PSK_WITH_AES_128_CBC_SHA256,
    decode_ack,
    decode_command,
    decode_image,
    decode_inner,
    decode_outer,
    decode_psk_read_response,
    encode_command,
    encode_psk_read,
    parse_image_record,
    parse_tls_handshake,
    parse_tls_record,
    psk_identity,
)

# Confirmed logical frames (docs/protocol-notes.md)
NOP_FRAME = bytes.fromhex("a00800a800050000000000a5")
VERSION_FRAME = bytes.fromhex("a00600a6a803000000ff")
TLS_REQUEST_FRAME = bytes.fromhex("a00600a6d003000000d7")

# Confirmed responses (usbmon capture / live probe)
NOP_ACK_COLD = bytes.fromhex("a00600a6b003000003f4")  # status 0x03
VERSION_ACK_WARM = bytes.fromhex("a00600a6b00300a8014e")
VERSION_RESPONSE = bytes.fromhex(
    "a01b00bba818004746333236385f52545345435f4150505f31303034320014")

# Capture frame 8006: device ClientHello TLS record (from the 0xb0 pack)
CLIENT_HELLO_RECORD = bytes.fromhex(
    "160303002f0100002b030302d087186b9d5695c582234693811099434ea8008cad"
    "f4d5bdd88447ec8acc4700000400ae00ff0100")

# Capture frame 8014: device ClientKeyExchange carrying the PSK identity
CLIENT_KEY_EXCHANGE_RECORD = bytes.fromhex(
    "160303001510000011000f436c69656e745f6964656e74697479")

# Capture frames 7948/7958: read of the PMK-hash TLV 0xbb020007
PSK_HASH_READ_REQUEST = bytes.fromhex("a00c00ace40900070002bb00000000f9")
PSK_HASH_READ_RESPONSE_PAYLOAD = bytes.fromhex(
    "00070002bb20000000"
    "071b91b10f83c89e0893376b4c20fc68d063e316e7e9476175a092c358c0022e")


class TestCommandEncode(unittest.TestCase):
    def test_nop_frame(self):
        self.assertEqual(
            encode_command(COMMAND_NOP, b"\x00\x00\x00\x00"), NOP_FRAME)

    def test_version_frame(self):
        self.assertEqual(
            encode_command(COMMAND_FIRMWARE_VERSION, b"\x00\x00"),
            VERSION_FRAME)

    def test_tls_request_frame(self):
        self.assertEqual(
            encode_command(COMMAND_REQUEST_TLS_CONNECTION, b"\x00\x00"),
            TLS_REQUEST_FRAME)

    def test_psk_hash_read_frame(self):
        frame = encode_command(COMMAND_PRESET_PSK_READ_R,
                               encode_psk_read(0xBB020007))
        self.assertEqual(frame, PSK_HASH_READ_REQUEST)


class TestCommandDecode(unittest.TestCase):
    def test_roundtrip(self):
        for payload in (b"", b"\x00", b"\x01\x02\x03", bytes(range(256))):
            frame = encode_command(0x42, payload)
            inner = decode_command(frame)
            self.assertEqual(inner.command, 0x42)
            self.assertEqual(inner.payload, payload)
            self.assertTrue(inner.checksummed)

    def test_no_checksum_terminator(self):
        # The public driver sends NOP with the 0x88 terminator; the device
        # accepts it, so the decoder must too.
        frame = encode_command(COMMAND_NOP, b"\x00" * 4, checksum=False)
        inner = decode_command(frame)
        self.assertFalse(inner.checksummed)
        self.assertEqual(inner.payload, b"\x00" * 4)

    def test_bad_outer_checksum_rejected(self):
        with self.assertRaises(CodecError):
            decode_outer(bytes.fromhex("a00600a7a803000000ff"))

    def test_bad_inner_checksum_rejected(self):
        with self.assertRaises(CodecError):
            decode_inner(bytes.fromhex("a803000000fe"))

    def test_version_response(self):
        inner = decode_command(VERSION_RESPONSE)
        self.assertEqual(inner.command, COMMAND_FIRMWARE_VERSION)
        self.assertEqual(inner.payload.split(b"\x00")[0],
                         b"GF3268_RTSEC_APP_10042")

    def test_ack_decode(self):
        inner = decode_command(NOP_ACK_COLD)
        self.assertEqual(inner.command, 0xB0)
        self.assertEqual(decode_ack(inner.payload), (COMMAND_NOP, 0x03))
        inner = decode_command(VERSION_ACK_WARM)
        self.assertEqual(decode_ack(inner.payload),
                         (COMMAND_FIRMWARE_VERSION, 0x01))

    def test_psk_read_response(self):
        result = decode_psk_read_response(PSK_HASH_READ_RESPONSE_PAYLOAD)
        self.assertEqual(result.flags, 0xBB020007)
        self.assertEqual(len(result.data), 32)
        self.assertEqual(result.data.hex(),
                         "071b91b10f83c89e0893376b4c20fc68d063e316e7e94761"
                         "75a092c358c0022e")


class TestTls(unittest.TestCase):
    def test_client_hello(self):
        record = parse_tls_record(CLIENT_HELLO_RECORD)
        self.assertEqual(record.content_type, 0x16)
        self.assertEqual(record.version, 0x0303)
        handshake = parse_tls_handshake(record.fragment)
        self.assertEqual(handshake.msg_type, 0x01)
        # session id length at body[34] (2-byte version + 32-byte random),
        # then the cipher suite list
        self.assertEqual(handshake.body[34], 0)
        suites_len = int.from_bytes(handshake.body[35:37], "big")
        suites = handshake.body[37:37 + suites_len]
        self.assertEqual(
            suites,
            TLS_PSK_WITH_AES_128_CBC_SHA256.to_bytes(2, "big") + b"\x00\xff")

    def test_psk_identity(self):
        record = parse_tls_record(CLIENT_KEY_EXCHANGE_RECORD)
        handshake = parse_tls_handshake(record.fragment)
        self.assertEqual(psk_identity(handshake), b"Client_identity")


class TestImageRecord(unittest.TestCase):
    def test_parse_prefix_and_tls(self):
        # Structure from capture frames 8050/8072 (b2 image records):
        # 9-byte prefix, then a TLS application-data record.
        tls_fragment = b"\x11" * 14320
        tls_record = b"\x17\x03\x03" + len(tls_fragment).to_bytes(2, "big") \
            + tls_fragment
        prefix = bytes.fromhex("0020fa370000000000")
        record = parse_image_record(prefix + tls_record)
        self.assertEqual(record.prefix_length, 0x37FA)
        self.assertEqual(record.tls.content_type, 0x17)
        self.assertEqual(len(record.tls.fragment), 14320)

    def test_decode_image_vector(self):
        chunk = bytes.fromhex("123456789abc")
        self.assertEqual(decode_image(chunk), [0x234, 0x781, 0xC56, 0x9AB])

    def test_decode_image_rejects_ragged_data(self):
        with self.assertRaises(CodecError):
            decode_image(b"\x00" * 7)


if __name__ == "__main__":
    unittest.main()
