# Goodix 27c6:5584 Linux RE Notes

This workspace tracks reverse engineering for the Screek PC-FS1 / Goodix
`27c6:5584` USB fingerprint reader.

The Windows driver payload is stored locally but ignored by git at:

`windows-drivers/goodix`

Current findings:

- The device is `USB\VID_27C6&PID_5584`.
- Lenovo/Screek's Windows package supports it via `WbdiUsb.inf`.
- The Windows stack uses WinUSB plus a UMDF driver (`Wbdi.dll`).
- The algorithm/WBF adapter is `GoodixEngineAdapter.dll`.
- The protocol is not compatible with libfprint's existing `goodixmoc` driver.
- Static strings show MCU commands, firmware update paths, TLS-PSK, and SGX/enclave support.
- A Windows usbmon capture recovered the complete RTSEC transport framing.
- Linux can now send the non-destructive NOP/version startup sequence and read
  firmware version `GF3268_RTSEC_APP_10042` successfully. (A cold device
  reports `GF3208_RTSEC_APP_10042`; see docs/protocol-notes.md.)
- The Windows PSK provisioning is decoded: the device stores a DPAPI-encrypted
  PSK blob (TLV `0xbb010002`), a white-box PSK encoding (TLV `0xbb010003`),
  and a PSK hash (TLV `0xbb020007`). The device PSK is unique, not the public
  goodix-fp-dump one.
- The PSK was recovered non-destructively (read-only TLV read + DPAPI unseal
  inside the owning Windows VM) and a full TLS 1.2 PSK session was
  established from Linux with a self-hosted server; the device Finished
  verified against the recovered PSK.
- Bulk OUT writes must be submitted as separate 64-byte URBs; larger single
  URBs are silently ignored by the MCU.
- A working libfprint driver exists as `patches/goodixtls55x4-5584.patch`
  (base: TheWeirdDev/libfprint `55b4-experimental`). It completes activation,
  the TLS-PSK session, live image capture, and NBIS minutiae detection
  (`MINUTIAE_COUNT=10` on a live finger scan). Image quality still needs
  tuning; see `patches/README.md`.
- Passive codec, unit tests, capture replay, offline TLS decryption, and the
  live session tooling live in `tools/` (`rtsec_codec.py`,
  `test_rtsec_codec.py`, `replay_capture.py`, `tls_capture_decrypt.py`,
  `tls_relay.py`, `tls_manual_server.py`). Live tools need the local venv:
  `.venv/bin/python tools/tls_manual_server.py --psk <hex> --warmup`.
- The traced Windows reset retry path is not USB: it toggles an ACPI GPIO
  Resource Hub target via IOCTL `0x480004`. The current unit appears as an
  external USB device, so this may be shared code for other integrated variants.

Immediate goal: decode the remaining initialization and TLS/image paths, then
turn the proven transport into a clean libfprint driver.

Build and passive probe:

```sh
make
./build/goodix-probe
```

Known-safe NOP followed by the firmware-version query:

```sh
./build/goodix-probe rt-wake-version
```

The expected response is a NOP ACK, a version ACK, and a frame containing the
ASCII firmware string.
