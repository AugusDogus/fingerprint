# Protocol Notes

## Driver Files

Extracted from `PC-FS1_Goodix_Fingerprint_Driver_For_Windows_By_Lenovo.exe`
into ignored local directory `windows-drivers/goodix`:

- `WbdiUsb.inf`: Windows install metadata for `USB\Vid_27C6&Pid_5584`.
- `Wbdi.dll`: UMDF/WinUSB driver, USB transport, MCU logic, firmware/TLS handling.
- `GoodixEngineAdapter.dll`: Windows Biometric Framework engine adapter and algorithm exports.
- `SessionService.exe`: Windows service used by the driver package.
- `AdapterEnclave.signed.dll`, `WbdiEnclave.signed.dll`: Intel SGX enclave payloads.
- `sgx_white_list_cert.bin`: SGX whitelist certificate data.

## Confirmed INF Details

`WbdiUsb.inf` maps these IDs to the Goodix UMDF driver:

- `USB\Vid_27C6&Pid_5584`
- `USB\Vid_27C6&Pid_55B4`
- `USB\Vid_0BDA&Pid_5811`

The driver stack is:

- `WinUSB.sys` lower filter/transport
- `WUDFRd.sys` UMDF reflector
- `wbdi.dll` as `%12%\UMDF\wbdi.dll`
- `GoodixEngineAdapter.dll` as the WinBio engine plugin

## Important Static Strings

Likely transport/protocol terms from `Wbdi.dll`:

- `UsbPipeWrite`
- `readPipe, maxPackSize: %d`
- `writePipe, maxPackSize: %d`
- `IoHubWriteRaw`
- `IoHubReadReg`
- `IoHubWriteReg`
- `IoHubMcuSendCmd2`
- `IoHubWriteTls`
- `McuGetFirmwareVersion`
- `McuStartTls`
- `McuStopTls`
- `McuGetTlsStatusStub`
- `PresetPskReadG`
- `PresetPskWriteG`
- `ProcessPsk`
- `TLS-PSK-WITH-AES-128-CBC-SHA256`
- `goodix_tls_client`
- `MILAN_GM168SEC_IAP_100071`
- `MILAN_GM168SEC_IAP_200031`

## Existing libfprint Probe Result

A local patched `goodixmoc` build was able to claim `27c6:5584` after endpoint and
serial quirks, but the first MOC `GET_VERSION` request timed out. This strongly
suggests the PC-FS1 uses the Windows driver's MCU/TLS protocol rather than the
open Goodix MOC protocol already in libfprint.

## Safety

Avoid unknown write commands that mention firmware, IAP, PSK, erase, update,
reset, or production provisioning until the packet format and command IDs are
understood. Start with passive descriptor inspection and known read/version
paths only.

## Confirmed MCU Version Command

`McuGetFirmwareVersion` in `Wbdi.dll` calls `IoHubMcuSendCmd2` with:

- command ID `0x00a8`
- two-byte payload `00 00`
- caller-provided output buffer and output length pointer

Earlier probing used this 7-byte packet:

```text
f0 00 a8 00 01 00 00
```

That frame belongs to the Geneva SPI path (`mcu\geneva\geneva.c`), not the
external WinUSB/Malibu path, and timed out on `27c6:5584`.

Runtime test on `27c6:5584`:

- `./build/goodix-probe version` successfully wrote `f0 00 a8 00 01 00 00`.
- The follow-up bulk IN read on endpoint `0x82` timed out after 2s.
- This suggests the packet was the wrong transport framing for this USB unit.

## Candidate Malibu USB Version Frame

The likely external USB path is the Malibu command table whose `IoHub` slot
`+0x58` points to `0x18009bf40`. For non-`0x80xx` command IDs, that function
calls the small Malibu frame builder at `0x18009d220`, then writes the resulting
buffer through the context's raw USB write callback.

The small Malibu frame builder creates:

- 8-byte header
- payload
- 4-byte CRC32 over `header || payload`, stored little-endian

Header layout observed at `0x18009de20`:

- bytes 0-1: command ID, big-endian
- byte 2: sequence/index byte, `0` for the normal small command path
- byte 3: `0`
- bytes 4-7: `payload_len + 4`, little-endian

For `McuGetFirmwareVersion` (`0x00a8`, payload `00 00`), the candidate USB bulk
OUT packet is:

```text
00 a8 00 00 06 00 00 00 00 00 9f ab af 6a
```

The checksum bytes `9f ab af 6a` are standard CRC32 over:

```text
00 a8 00 00 06 00 00 00 00 00
```

Receive parsing is still being traced, so the Linux probe currently dumps the raw
bulk IN response.

Runtime tests on `27c6:5584` after switching `goodix-probe` to this candidate
Malibu framing:

- `./build/goodix-probe version` successfully wrote
  `00 a8 00 00 06 00 00 00 00 00 9f ab af 6a`.
- The follow-up bulk IN read on endpoint `0x82` timed out after 2s.

## Candidate Malibu USB NOP Frame

`McuSendNop` calls the same MCU send path with:

- command ID `0x0000`
- four-byte payload `00 00 00 00`

Using the same Malibu small-frame layout, the candidate USB bulk OUT packet is:

```text
00 00 00 00 08 00 00 00 00 00 00 00 da dd 30 a8
```

Runtime test on `27c6:5584`:

- `./build/goodix-probe wake-version` successfully wrote the candidate NOP frame.
- The follow-up bulk IN read on endpoint `0x82` timed out after 2s.
- It then successfully wrote the candidate version frame.
- The final bulk IN read on endpoint `0x82` timed out after 6s.

This suggests either the selected runtime backend/framing is still wrong, or the
Windows driver performs additional USB/device startup before bulk MCU commands
respond.

## Realtek / RTSEC Backend Findings

Static tracing now points away from Malibu for this Windows package's default USB
path:

- The device factory at `0x18004e72d` loads the global descriptor pointer at
  `0x1802207c0`.
- The static value of that pointer is `0x18022ad70`, whose first callback is the
  Realtek context creator at `0x1800a63f0`.
- The Realtek descriptor's `IoHub` callback table is `0x18022ace0`.
- After `IoHubSetIo` copies that table into the hub context, MCU command type `4`
  dispatches through copied offset `+0x10`, i.e. function `0x1800a6730`.
- The Malibu send function `0x18009bf40` remains present, but is not the default
  descriptor selected by the static global path above.

`IoHubMcuSendCmd2` builds command type `4` and dispatches it with:

- `r8w`: command ID
- `r9`: payload pointer
- first stack argument: payload length
- second stack argument: checksum flag `1`

Static analysis correctly recovered the inner Realtek packet but initially
misidentified its surrounding transport bytes as `0a 0a 0a 0a`. A Windows
usbmon capture on 2026-07-13 established the complete wire format.

Plain command frames have a four-byte outer header:

- byte 0: `0xa0`
- bytes 1-2: length of the inner packet, little-endian
- byte 3: `(byte0 + byte1 + byte2) & 0xff`

The inner packet is:

- byte 4: low byte of command ID
- bytes 5-6: `payload_len + 1`, little-endian
- payload at byte 7
- final byte: inner checksum

The checksum helper at `0x18009f740` starts with:

```text
cmd_low + len_lo + len_hi + sum(payload)
```

Then returns:

```text
0xaa - sum
```

with all arithmetic effectively modulo 256.

For `McuGetFirmwareVersion` (`0x00a8`, payload `00 00`), the confirmed logical
frame is:

```text
a0 06 00 a6 a8 03 00 00 00 ff
```

For `McuSendNop` (`0x0000`, payload `00 00 00 00`), the confirmed logical frame
is:

```text
a0 08 00 a8 00 05 00 00 00 00 00 a5
```

Windows pads each bulk OUT transfer to a 64-byte boundary. The reader returns
only the logical response length on bulk IN. Commands normally receive a
10-byte `0xb0` ACK frame before their data response.

`goodix-probe` now has separate Realtek-framed modes:

- `rt-version`
- `rt-nop`
- `rt-wake-version`

The earlier `0a 0a 0a 0a` candidate wrote successfully at the libusb layer but
timed out because it lacked the valid outer header. After updating the probe to
the capture-confirmed frames, padding them to 64 bytes, and reading both ACK and
data packets, Linux succeeded:

- NOP ACK: `a0 06 00 a6 b0 03 00 00 01 f6`
- version ACK: `a0 06 00 a6 b0 03 00 a8 01 4e`
- version response:
  `a0 1b 00 bb a8 18 00 47 46 33 32 36 38 5f 52 54 53 45 43 5f 41 50 50 5f 31 30 30 34 32 00 14`
- decoded firmware: `GF3268_RTSEC_APP_10042`

The initial Windows cold-start capture reported `GF3208_RTSEC_APP_10042`; after
the first full driver initialization, a controlled PnP restart and the Linux
probe both reported `GF3268_RTSEC_APP_10042`. The transition needs more analysis.

The capture also confirms:

- IAP version: `MILAN_RTSEC_IAP_10027`
- TLS request command: `0x00d0`, payload `00 00`
- TLS records use outer type `0xb0`
- a large encrypted/image response used outer type `0xb2`
- the TLS PSK identity sent by the device is `Client_identity`

## Windows USB Capture

Host-side `usbmon1` captured the Goodix traffic while the physical reader was
passed through to the existing Windows 11 QEMU guest. The signed package loaded
as `oem17.inf`; Windows reported `Goodix fingerprint`, class `Biometric`, status
`OK`, and `CM_PROB_NONE`.

Capture metadata:

- local file: `captures/windows-init-20260713-131745.pcapng` (ignored)
- 8,718 packets, zero drops
- SHA-256: `1d159d2b7b8756edf22ec9ca1ce0a9d2b5d56e3adeacec72772fdeb3f52b4830`
- controlled disable: Windows wall time `13:33:24.7597315`
- controlled enable: Windows wall time `13:33:27.5207122`
- healthy again: Windows wall time `13:33:40.1908842`

The command order at the start of the clean enable was:

```text
00, a8, a8, e4, e4, a8, f6, a8, a2, 82, 00, a6, d0
```

After `d0`, the device and driver performed a TLS 1.2 PSK handshake. Later
commands included `90`, `36`, `20`, `70`, and `82`; large `0xb2` responses
contained TLS application data carrying 14,328-byte encrypted image records.

Static call-site correlation gives the following command map. These labels are
from the driver routines that construct each command, rather than guesses based
only on packet contents:

| ID | Driver routine | Observed role | Linux live-probe policy |
|---:|---|---|---|
| `00` | `McuSendNop` | Liveness check | allowed |
| `20` | `_FpMcuGetImage` | Acquire encrypted image | blocked pending TLS |
| `36` | `_HvMcuGetFdtManualBase` | Read FDT/manual baseline values | blocked pending TLS |
| `70` | `FpMcuSwitchToIdleMode` | Put the sensor in idle mode | blocked |
| `82` | `_FpMcuReadRegister` | Read fingerprint-chip register(s) | blocked |
| `90` | `FpMcuDownloadChipConfig` | Download the sensor configuration | blocked |
| `a2` | `FpMcuResetFingerPrint` | Reset the fingerprint sensor (`05 14`) | blocked |
| `a6` | `FpMcuGetOtp` | Read 32 bytes of sensor OTP/calibration data | blocked |
| `a8` | `McuGetFirmwareVersion` | Read application firmware version | allowed |
| `d0` | `_McuReqTlsConnection` / `McuStartTls` | Begin TLS-PSK session | blocked until host PSK handling is understood |
| `e0` | `PresetPskWriteG` / `PresetPskWriteR` path | Write PSK-related storage | never probe directly |
| `e4` | `PresetPskReadG` / `PresetPskReadR` path | Read PSK-related TLVs/hashes | blocked; sensitive lifecycle data |
| `f6` | `McuGetIapVersion` | Read IAP firmware version | blocked until cold-start behavior is understood |

The warm image/calibration phase observed after TLS was:

```text
90, 36, 20, 36, 70, 82, 20, 36
```

The two `20` requests each produced a 14,338-byte outer `b2` packet: a 10-byte
Goodix image-record prefix followed by a 14,328-byte TLS application record.
The `36` responses contained a status prefix and a sequence of little-endian
16-bit baseline values. Decrypting either requires reproducing the Windows
host's PSK retrieval/unsealing path; the USB capture alone does not reveal the
session key.

The helper `tools/parse_goodix_pcap.py` reconstructs logical frames from the
64-byte-padded bulk OUT chunks and validates both outer and inner checksums.

## Device Start Trace

`OnDeviceStart` at `0x1800afbd0` does not directly send MCU version/NOP commands.
It validates global context, calls a registered module callback from the global
at `0x180266288` with `dl = 1`, then runs a logging/hook callback.

That global belongs to the `pwrbtnshield` module table, not the primary USB/MCU
transport. The static table at file offset `0x238080` / VA `0x180238080` starts
with:

- `0x1800af660`: module init
- `0x1800af9d0`: module teardown
- `0x1800afbd0`: `OnDeviceStart`
- `0x1800afdb0`: `OnDeviceStop`

This path eventually forwards through callbacks and `McuSetPovCfg`; it is not the
missing safe NOP/version-style USB startup sequence.

The logic path that logs `device started` is around `0x1800922ea`. Before that
log, it calls a context callback at `[ctx + 0x18]` with timeout `0x2710` (10s)
and checks whether `[ctx + 0xc8]` changed from zero. The next static target for
startup sequencing is that registered callback, not USB prepare or
`OnDeviceStart` itself.

Further trace:

- The logic globals are initialized at `0x180263768` and `0x180263770`.
- `0x180263768` points at the selected logic callback table.
- `0x180263770` points at the selected logic context whose `+0xc8` flag means
  started.
- `0x180080ee0` selects one of four logic series tables by device config value:
  `1 -> 0x180229d58`, `2 -> 0x180229e28`, `3 -> 0x180229ca8`,
  `4 -> 0x180229ea0`.
- The common callback at table offset `+0x18` is `0x18007e210`, which is
  `LogicWaitForStartEvent`. It only waits/checks state; it is not the command
  sender.
- The series-4 table includes direct MCU entries such as `McuSendNop` at
  `0x1800a2130` and `McuGetFirmwareVersion` at `0x18009ff10`, and carries RTSEC
  firmware strings. This makes it the current best match for the Realtek/RTSEC
  backend path.

## RTSEC TLS Startup Trace

The series-4 startup path reaches `McuStartTls` at `0x1800a2b60`. It performs
host-side RTSEC/TLS setup and then calls helper `0x1800a5f90`, logged as
`_McuReqTlsConnection`.

`_McuReqTlsConnection` sends an MCU command through `IoHubMcuSendCmd2` with:

- command ID `0x00d0`
- two-byte payload `00 00`
- output buffer/length pointers supplied by the caller

The Windows capture confirms that the outer-wrapped logical frame is:

```text
a0 06 00 a6 d0 03 00 00 00 d7
```

Checksum calculation:

```text
0xaa - (0xd0 + 0x03 + 0x00 + 0x00 + 0x00) = 0xd7
```

Windows received an ACK and immediately completed a TLS 1.2 PSK handshake using
outer `0xb0` records and the device identity `Client_identity`. This frame has
not been sent by the Linux probe because it remains outside the NOP/version-only
live probing boundary.

After `_McuReqTlsConnection`, `McuStartTls` initializes the TLS library and loops
up to 10 times through the TLS handshake/status path. On success it logs
`tls handshake success`, sets `[ctx + 0xc8] = 1`, sleeps 10 ms, and returns
success. On handshake-in-progress statuses it retries; other errors fail the
logic start.

## Linux TLS Session Established (2026-07-19)

The full legitimate session was established from Linux without any
persistent device-state change:

1. Read-only `e4` read of TLV `0xbb010002` recovered the DPAPI blob
   (`./build/goodix-probe rt-psk-read`).
2. The blob was unsealed inside the owning Windows VM (DPAPI CurrentUser
   scope under SYSTEM — the WinBio service context) yielding the 32-byte
   PSK. Scripts: `~/Windows/GoodixRE/unseal-psk.ps1` and `run-unseal.ps1`.
3. `tools/tls_manual_server.py` sends the captured warm-boot sequence
   (NOP, version x2, PSK TLV reads, version, IAP, version, `a2 05 14`
   sensor reset, register read, NOP, OTP), then `d0`, then completes TLS
   1.2 PSK in-process using a fixed ServerHello (byte-exact copy of the
   Windows one). The device Finished decrypted and its `verify_data`
   matched, proving both sides derived identical session keys from the
   recovered PSK.

**Critical transport finding — bulk OUT URB chunking:** Windows submits
bulk OUT writes as separate 64-byte URBs (capture frames 6748/6750). A
single URB larger than 64 bytes is silently ignored by the MCU receive
path. This blocked every early TLS attempt: the 90-byte ServerHello pack
(128 bytes padded) must be written as two 64-byte URBs. All earlier
failures ("device ignores ServerHello") traced to this, not to TLS
content, packing, timing, or missing warm-up commands.

**openssl `s_server` caveat:** it closes the accepted connection on stdin
EOF, so any relay using it must keep its stdin pipe open
(`tools/tls_relay.py` does).

## Offline Capture Decryption (2026-07-19)

TLS 1.2 PSK-CBC has no forward secrecy: with the PSK, every record in the
usbmon capture decrypts offline. `tools/tls_capture_decrypt.py` implements
the RFC 4279 premaster (`len || zeros || len || psk`), the TLS 1.2 PRF,
AES-128-CBC record decryption, and HMAC-SHA256 verification (a wrong PSK
or key schedule fails loudly). Results on the 2026-07-13 capture:

- 2 TLS sessions, 4 encrypted Finished records and 4 image records
  decrypted, all HMAC-verified.
- Image plaintext: 14,256 bytes + 4-byte trailer = 88x108 12-bit sensor
  frames; decoded via `rtsec_codec.decode_image` to
  `captures/decrypted/session-*-image-{1,2}.pgm` (plausible no-finger
  baseline frames, matching the init-time capture context).

## Firmware 10042 vs goodix-fp-dump 55x4 (offline comparison, 2026-07-20)

Compared the capture against the public `goodix-fp-dump` `driver_55x4.py` /
`goodix.py` / `tool.py` (github.com/goodix-fp-linux-dev/goodix-fp-dump).
That project targets `GF3268_RTSEC_APP_10041`; its `VALID_FIRMWARE` regex
(`GF32[0-9]{2}_RTSEC_APP_100[0-9]{2}`) matches this device's 10042, and the
IAP string matches exactly (`MILAN_RTSEC_IAP_10027`).

Verified identical between the Windows capture and the public implementation:

- All command IDs seen in the capture (`00 20 36 70 82 90 a2 a6 a8 d0 e0 e4
  f6`) exist in the public table with the same roles.
- `a2` payload `05 14` = `reset(reset_sensor=True, soft_reset_mcu=False,
  sleep_time=20)`, bit-for-bit the public encoding.
- The `90` UPLOAD_CONFIG_MCU payload equals the public `DEVICE_CONFIG`
  constant byte-for-byte (256 bytes).
- `82` READ_SENSOR_REGISTER at `0x0000` len 4 (chip ID; response `0ca10022`)
  and at `0x0082` len 2, same as the public `run_driver` flow. Difference:
  the 10042 request carries a trailing `00` byte (5-byte payload) that the
  public encoder does not emit.
- Post-TLS pipeline `90, 36, 20, 36, 70, 82, 20, 36` is exactly the public
  `run_driver` sequence minus its sleep/finger-wait phase.
- `b2` image record = 9-byte Goodix prefix + one TLS 1.2 application-data
  record. Sizes line up with AES-128-CBC-SHA256: 14,320-byte fragment =
  16-byte explicit IV + (14,256-byte image + 4-byte trailer + 32-byte HMAC +
  padding). 14,256 bytes = 88 x 108 pixels x 12 bpp; the public
  `tool.decode_image` unpacking (4 pixels per 6 bytes) applies.
- TLS roles: the device is the TLS *client* (sends ClientHello offering
  `0x00ae` TLS_PSK_WITH_AES_128_CBC_SHA256 plus the `0x00ff` SCSV), the host
  runs the server (public tool uses `openssl s_server -nocert -psk`).
  Identity in the device ClientKeyExchange is `Client_identity`.

## PSK Provisioning Analysis (2026-07-20)

The `e0`/`e4` PSK storage is TLV based. Capture decoding shows:

- `e4` request payload: `flags(4 LE) + 00 00 00 00`. Response payload:
  `status(1) + flags(4 LE) + length(4 LE) + data`.
- TLV `0xbb010002` (324 bytes): a Windows DPAPI blob. It starts with the
  DPAPI provider GUID `d08c9ddf-0115-d111-8c7a-00c04fc297eb`, i.e. the PSK
  encrypted by the Windows installation that provisioned the device.
- TLV `0xbb010003` (96 bytes): the device-side "white box" PSK encoding.
  The first 16 bytes match the public `PSK_WHITE_BOX` constant; the
  remaining 80 bytes differ, so this device has its own unique PSK.
- TLV `0xbb020007` (32 bytes): a PMK/PSK hash, `071b91b1...` on this device,
  different from the public `PMK_HASH` (`81b8ff49...`). The hash
  construction is unknown: neither `sha256((len16be || psk) * 2)` nor the
  firmware-HMAC chain from the public updater reproduces the public hash.
- Windows wrote both PSK TLVs once in the cold session (single `e0` frame
  carrying both TLVs), then only read them in the warm session. The hash was
  identical in both sessions, so the PSK was stable after that write.

Consequence: the public tool's `write_psk` (provisioning its known PSK)
would overwrite this device's pairing — that is the destructive step to
avoid. The non-destructive route to a Linux TLS session is to read TLV
`0xbb010002` (read-only) and unseal the DPAPI blob inside the owning Windows
VM, then run the host-side TLS server with that PSK.

## ACK Status Byte Observation

`b0` ACK payloads are `cmd status`. Status `0x03` appears on a cold device
(including the live Linux probe on 2026-07-20); status `0x01` dominates the
post-initialization warm session. The public decoder treats bit 1 as a
success flag, which does not fit this device (successful commands show both
values). Exact semantics unknown; treat it as a device-state byte.

## GF3208 vs GF3268 Version String

- Cold device (capture session 1, and the live Linux probe on 2026-07-20):
  `GF3208_RTSEC_APP_10042`, ACK status `0x03`.
- After full Windows initialization (capture session 2):
  `GF3268_RTSEC_APP_10042`, ACK status `0x01`.
- TLS ran successfully in session 1 while the string still read GF3208, so
  the difference does not gate TLS. Which command flips the string (reset
  `a2`, config `90`, or the PnP restart) is unknown.

## New Tooling (2026-07-20)

- `tools/rtsec_codec.py`: pure codec (outer pack, inner frame, ACK, PSK TLV,
  TLS record/handshake, `b2` image record, 12-bit image unpacking).
- `tools/test_rtsec_codec.py`: 16 unit tests against capture-confirmed byte
  strings. Run: `cd tools && python3 -m unittest test_rtsec_codec`.
- `tools/replay_capture.py`: semantic transcript + checksum validation of a
  usbmon capture. Current result: 145 logical frames, 0 validation failures.

## Realtek Receive Parsing

The Realtek receive/parser path starts through the table rooted at
`0x180231de0`; the first callback is `0x1800a6a20`, which calls the packet
validator at `0x1800aac30`.

The validator requires at least 8 bytes and then checks:

- high nibble of byte 0 is `0xa` or `0xb`
- byte 3 equals `byte0 + byte1 + byte2` modulo 256

For packets whose byte 0 high nibble is `0xa`, the parser treats the data after
the 4-byte outer header as an inner packet:

- byte 4: command/status byte, masked with `0xfe` for routing
- bytes 5-6: payload length, little-endian
- byte 7 onward: payload bytes

The parser queues up to `min(payload_len, received_len - 7)` bytes into the
matching command object. Later validation accepts a final byte of `0x88` as a
special case; otherwise it uses the same `0xaa - sum` checksum helper over the
inner command/length/payload fields.

Related static init findings:

- Several init paths call `McuGetFirmwareVersion` with an `0x80` byte output
  buffer.
- On failure, the STM32 path logs `get firmware version failed, reset mcu...`,
  calls a reset helper at `0x1800ae2f0`, then retries the version command.
- That reset helper toggles a one-byte lower-level control path through context
  field `+0x38` with values `00`, sleep 10ms, then `01`, then sleeps 100ms.
- The helper at `0x180038800` formats those one-byte writes as a WDF request,
  not as an MCU bulk frame. It reaches `WdfIoTargetFormatRequestForIoctl` with
  IOCTL code `0x480004`, then submits with `WdfRequestSend`.
- The target is opened in `_devicespi.c` through `SpbPeripheralOpen`, using
  `\\.\RESOURCE_HUB\` and `RESOURCE_HUB_CREATE_PATH_FROM_ID`.
- Static strings distinguish the two Resource Hub targets:
  `open spi target failed, status: 0x%x` for the SPI target and
  `open gpio target failed` for the GPIO target. The reset helper's failure path
  logs `gpio target not set`.
- Therefore this reset/wakeup dependency is an ACPI GPIO Resource Hub IOCTL, not
  a USB request. It should not be added to `goodix-probe` as a libusb bulk or
  control transfer.
- On the current Linux host, udev exposes `27c6:5584` as an external USB device
  with sysfs ancestry under the USB host controller and no obvious Goodix/GDIX
  ACPI device. This suggests the GPIO reset path is shared Windows driver code
  for other integrated variants, not necessarily the missing init for this USB
  unit.
