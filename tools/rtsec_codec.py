"""Passive codec for the Goodix RTSEC USB protocol (27c6:5584, GF32xx_RTSEC_APP_1004x).

Pure encode/decode helpers plus structured parsers. No device I/O lives here;
this module is safe to use against captures and is unit-tested against
capture-confirmed byte strings from docs/protocol-notes.md.

Wire format (confirmed by captures/windows-init-20260713-131745.pcapng):

  outer pack:  flags(1) | payload_len(2, LE) | sum(bytes 0..2) & 0xff | payload
  inner frame: cmd(1) | payload_len+1(2, LE) | payload | terminator
               terminator = (0xaa - sum(cmd..payload end)) & 0xff,
               or the literal 0x88 when the sender disables the checksum

Bulk OUT transfers are padded to 64-byte boundaries on the wire; that padding
is transport noise and is stripped by the capture parser, not by this codec.
"""

from __future__ import annotations

import struct
import dataclasses

# Outer pack flags
FLAGS_MESSAGE_PROTOCOL = 0xA0
FLAGS_TRANSPORT_LAYER_SECURITY = 0xB0
FLAGS_TRANSPORT_LAYER_SECURITY_DATA = 0xB2

# Command IDs (names match goodix-fp-dump goodix.py, which the Windows
# capture confirms for every command seen on this device)
COMMAND_NOP = 0x00
COMMAND_MCU_GET_IMAGE = 0x20
COMMAND_MCU_SWITCH_TO_FDT_DOWN = 0x32
COMMAND_MCU_SWITCH_TO_FDT_UP = 0x34
COMMAND_MCU_SWITCH_TO_FDT_MODE = 0x36
COMMAND_MCU_SWITCH_TO_SLEEP_MODE = 0x60
COMMAND_MCU_SWITCH_TO_IDLE_MODE = 0x70
COMMAND_WRITE_SENSOR_REGISTER = 0x80
COMMAND_READ_SENSOR_REGISTER = 0x82
COMMAND_UPLOAD_CONFIG_MCU = 0x90
COMMAND_SWITCH_TO_SLEEP_MODE = 0x92
COMMAND_RESET = 0xA2
COMMAND_MCU_ERASE_APP = 0xA4
COMMAND_READ_OTP = 0xA6
COMMAND_FIRMWARE_VERSION = 0xA8
COMMAND_ACK = 0xB0
COMMAND_REQUEST_TLS_CONNECTION = 0xD0
COMMAND_TLS_SUCCESSFULLY_ESTABLISHED = 0xD4
COMMAND_PRESET_PSK_WRITE_R = 0xE0
COMMAND_PRESET_PSK_READ_R = 0xE4
COMMAND_WRITE_FIRMWARE = 0xF0
COMMAND_CHECK_FIRMWARE = 0xF4
COMMAND_GET_IAP_VERSION = 0xF6

NO_CHECKSUM_TERMINATOR = 0x88

COMMAND_NAMES = {
    COMMAND_NOP: "NOP",
    COMMAND_MCU_GET_IMAGE: "MCU_GET_IMAGE",
    COMMAND_MCU_SWITCH_TO_FDT_DOWN: "MCU_SWITCH_TO_FDT_DOWN",
    COMMAND_MCU_SWITCH_TO_FDT_UP: "MCU_SWITCH_TO_FDT_UP",
    COMMAND_MCU_SWITCH_TO_FDT_MODE: "MCU_SWITCH_TO_FDT_MODE",
    COMMAND_MCU_SWITCH_TO_SLEEP_MODE: "MCU_SWITCH_TO_SLEEP_MODE",
    COMMAND_MCU_SWITCH_TO_IDLE_MODE: "MCU_SWITCH_TO_IDLE_MODE",
    COMMAND_WRITE_SENSOR_REGISTER: "WRITE_SENSOR_REGISTER",
    COMMAND_READ_SENSOR_REGISTER: "READ_SENSOR_REGISTER",
    COMMAND_UPLOAD_CONFIG_MCU: "UPLOAD_CONFIG_MCU",
    COMMAND_SWITCH_TO_SLEEP_MODE: "SWITCH_TO_SLEEP_MODE",
    COMMAND_RESET: "RESET",
    COMMAND_MCU_ERASE_APP: "MCU_ERASE_APP",
    COMMAND_READ_OTP: "READ_OTP",
    COMMAND_FIRMWARE_VERSION: "FIRMWARE_VERSION",
    COMMAND_ACK: "ACK",
    COMMAND_REQUEST_TLS_CONNECTION: "REQUEST_TLS_CONNECTION",
    COMMAND_TLS_SUCCESSFULLY_ESTABLISHED: "TLS_SUCCESSFULLY_ESTABLISHED",
    COMMAND_PRESET_PSK_WRITE_R: "PRESET_PSK_WRITE_R",
    COMMAND_PRESET_PSK_READ_R: "PRESET_PSK_READ_R",
    COMMAND_WRITE_FIRMWARE: "WRITE_FIRMWARE",
    COMMAND_CHECK_FIRMWARE: "CHECK_FIRMWARE",
    COMMAND_GET_IAP_VERSION: "GET_IAP_VERSION",
}

# TLS content types
TLS_CHANGE_CIPHER_SPEC = 0x14
TLS_ALERT = 0x15
TLS_HANDSHAKE = 0x16
TLS_APPLICATION_DATA = 0x17

TLS_HANDSHAKE_NAMES = {
    0x01: "client_hello",
    0x02: "server_hello",
    0x0B: "certificate",
    0x0C: "server_key_exchange",
    0x0E: "server_hello_done",
    0x10: "client_key_exchange",
    0x14: "finished",
}

# TLS_PSK_WITH_AES_128_CBC_SHA256, the only suite the device offers
TLS_PSK_WITH_AES_128_CBC_SHA256 = 0x00AE

# Length of the Goodix prefix prepended to TLS records inside 0xb2 packs
IMAGE_RECORD_PREFIX_LEN = 9


class CodecError(ValueError):
    """Raised when a frame fails structural or checksum validation."""


@dataclasses.dataclass
class OuterPack:
    flags: int
    payload: bytes


@dataclasses.dataclass
class InnerFrame:
    command: int
    payload: bytes
    checksummed: bool  # False when the 0x88 no-checksum terminator was used


@dataclasses.dataclass
class TlsRecord:
    content_type: int
    version: int  # 0x0303 for TLS 1.2
    fragment: bytes


@dataclasses.dataclass
class TlsHandshake:
    msg_type: int
    body: bytes


@dataclasses.dataclass
class ImageRecord:
    """A 0xb2 pack: 9-byte Goodix prefix followed by one TLS record."""

    prefix: bytes
    prefix_length: int  # little-endian u16 at prefix[2:4]
    tls: TlsRecord


@dataclasses.dataclass
class PskReadResult:
    """Decoded PRESET_PSK_READ_R response payload."""

    flags: int
    data: bytes


def encode_outer(payload: bytes, flags: int = FLAGS_MESSAGE_PROTOCOL) -> bytes:
    header = struct.pack("<BH", flags, len(payload))
    return header + struct.pack("<B", sum(header) & 0xFF) + payload


def decode_outer(data: bytes) -> OuterPack:
    if len(data) < 4:
        raise CodecError(f"outer pack too short: {len(data)} bytes")
    if sum(data[0:3]) & 0xFF != data[3]:
        raise CodecError(
            f"bad outer checksum: got {data[3]:#04x}, "
            f"want {sum(data[0:3]) & 0xFF:#04x}")
    length = struct.unpack("<H", data[1:3])[0]
    if len(data) - 4 < length:
        raise CodecError(
            f"outer pack truncated: {len(data) - 4} of {length} payload bytes")
    return OuterPack(flags=data[0], payload=data[4:4 + length])


def _inner_terminator(prefix: bytes, checksum: bool) -> int:
    if not checksum:
        return NO_CHECKSUM_TERMINATOR
    return (0xAA - sum(prefix)) & 0xFF


def encode_inner(command: int, payload: bytes, checksum: bool = True) -> bytes:
    body = struct.pack("<BH", command, len(payload) + 1) + payload
    return body + struct.pack("<B", _inner_terminator(body, checksum))


def decode_inner(data: bytes) -> InnerFrame:
    if len(data) < 4:
        raise CodecError(f"inner frame too short: {len(data)} bytes")
    length = struct.unpack("<H", data[1:3])[0]
    if len(data) < 2 + length:
        raise CodecError(
            f"inner frame truncated: {len(data)} bytes, declared {2 + length}")
    body, terminator = data[:2 + length], data[2 + length]
    if terminator == NO_CHECKSUM_TERMINATOR:
        return InnerFrame(command=data[0], payload=data[3:2 + length],
                          checksummed=False)
    if terminator != _inner_terminator(body, True):
        raise CodecError(
            f"bad inner checksum: got {terminator:#04x}, "
            f"want {_inner_terminator(body, True):#04x}")
    return InnerFrame(command=data[0], payload=data[3:2 + length],
                      checksummed=True)


def encode_command(command: int, payload: bytes,
                   checksum: bool = True) -> bytes:
    """Full logical frame: outer 0xa0 pack wrapping an inner command frame."""
    return encode_outer(encode_inner(command, payload, checksum))


def decode_command(data: bytes) -> InnerFrame:
    """Decode a full logical frame; rejects non-0xa0 outer packs."""
    pack = decode_outer(data)
    if pack.flags != FLAGS_MESSAGE_PROTOCOL:
        raise CodecError(f"not a command pack: flags {pack.flags:#04x}")
    return decode_inner(pack.payload)


def decode_ack(payload: bytes) -> tuple[int, int]:
    """Decode an ACK inner payload into (acked_command, status byte).

    The status byte always has bit 0 set. On this device 0x03 is seen in the
    cold/pre-initialized state and 0x01 after full Windows initialization;
    the public driver treats bit 1 as a success flag, which does not hold
    here, so the raw byte is returned instead of a boolean.
    """
    if len(payload) != 2:
        raise CodecError(f"ACK payload must be 2 bytes, got {len(payload)}")
    if not payload[1] & 0x1:
        raise CodecError(f"invalid ACK status byte: {payload[1]:#04x}")
    return payload[0], payload[1]


def encode_psk_read(flags: int) -> bytes:
    """PRESET_PSK_READ_R request payload for a full-TLV read."""
    return struct.pack("<II", flags, 0)


def decode_psk_read_response(payload: bytes) -> PskReadResult:
    if len(payload) < 9:
        raise CodecError(f"PSK read response too short: {len(payload)} bytes")
    if payload[0] != 0x00:
        raise CodecError(f"PSK read failed with status {payload[0]:#04x}")
    flags, length = struct.unpack("<II", payload[1:9])
    if len(payload) - 9 < length:
        raise CodecError(
            f"PSK read response truncated: {len(payload) - 9} of {length}")
    return PskReadResult(flags=flags, data=payload[9:9 + length])


def parse_tls_record(data: bytes) -> TlsRecord:
    if len(data) < 5:
        raise CodecError(f"TLS record too short: {len(data)} bytes")
    content_type, version, length = struct.unpack(">BHH", data[:5])
    if len(data) - 5 < length:
        raise CodecError(
            f"TLS record truncated: {len(data) - 5} of {length} fragment bytes")
    return TlsRecord(content_type=content_type, version=version,
                     fragment=data[5:5 + length])


def parse_tls_handshake(fragment: bytes) -> TlsHandshake:
    if len(fragment) < 4:
        raise CodecError(f"TLS handshake fragment too short: {len(fragment)}")
    msg_type = fragment[0]
    length = int.from_bytes(fragment[1:4], "big")
    if len(fragment) - 4 < length:
        raise CodecError(
            f"TLS handshake body truncated: {len(fragment) - 4} of {length}")
    return TlsHandshake(msg_type=msg_type, body=fragment[4:4 + length])


def psk_identity(handshake: TlsHandshake) -> bytes:
    """Extract the PSK identity from a client_key_exchange handshake body."""
    if handshake.msg_type != 0x10:
        raise CodecError("not a client_key_exchange handshake")
    if len(handshake.body) < 2:
        raise CodecError("client_key_exchange body too short")
    length = int.from_bytes(handshake.body[:2], "big")
    if len(handshake.body) - 2 < length:
        raise CodecError("PSK identity truncated")
    return handshake.body[2:2 + length]


def parse_image_record(payload: bytes) -> ImageRecord:
    """Split a 0xb2 pack payload into the Goodix prefix and the TLS record."""
    if len(payload) < IMAGE_RECORD_PREFIX_LEN + 5:
        raise CodecError(f"image record too short: {len(payload)} bytes")
    prefix = payload[:IMAGE_RECORD_PREFIX_LEN]
    prefix_length = struct.unpack("<H", prefix[2:4])[0]
    return ImageRecord(prefix=prefix, prefix_length=prefix_length,
                       tls=parse_tls_record(payload[IMAGE_RECORD_PREFIX_LEN:]))


def decode_image(data: bytes) -> list[int]:
    """Unpack the sensor's 12-bit pixel format: 4 pixels per 6 bytes.

    Matches goodix-fp-dump tool.decode_image. len(data) must be a multiple
    of 6; an 88x108 frame is 14256 bytes after the 4-byte TLS plaintext
    trailer is stripped.
    """
    if len(data) % 6 != 0:
        raise CodecError(
            f"image data length {len(data)} is not a multiple of 6")
    pixels: list[int] = []
    for i in range(0, len(data), 6):
        chunk = data[i:i + 6]
        pixels.append(((chunk[0] & 0xF) << 8) + chunk[1])
        pixels.append((chunk[3] << 4) + (chunk[0] >> 4))
        pixels.append(((chunk[5] & 0xF) << 8) + chunk[2])
        pixels.append((chunk[4] << 4) + (chunk[5] >> 4))
    return pixels
