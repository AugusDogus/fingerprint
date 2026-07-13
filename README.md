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
  firmware version `GF3268_RTSEC_APP_10042` successfully.
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
