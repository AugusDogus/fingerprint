# Goodix 27c6:5584 fingerprint reader on Linux

Linux support for the Screek PC-FS1 USB fingerprint reader (Goodix
`27c6:5584`, Milan die, firmware `GF32x8_RTSEC_APP_10042`), built by
reverse engineering the Windows driver.

The result is a patched libfprint driver that works with `fprintd`: enroll,
verify, and PAM/polkit prompts. It reuses the reader's existing Windows pairing key, so the
reader keeps working in Windows too.

## Status

Working on Arch Linux with `fprintd`.

- **Driver:** `goodixtls55x4` from
  [TheWeirdDev/libfprint](https://github.com/TheWeirdDev/libfprint)
  (`55b4-experimental`, pinned at `d1ca62a`), plus
  [`patches/goodixtls55x4-5584.patch`](patches/goodixtls55x4-5584.patch).
- **Matching:** SIGFM (OpenCV keypoints). NBIS finds too few minutiae on
  this small 108x88 sensor.
- **Finger detection:** done from frame contents. The sensor's FDT trigger
  can fire without a finger, and the driver has no finger-lift event. It
  ignores empty triggers, keeps the firmest of three frames per touch, waits
  for the finger to lift before the next scan, and only calibrates on an
  empty sensor.
- **Enrollment:** 10 touches.

## Setup

### 1. Recover the pairing key (one time)

Windows pairs with the reader using a random per-device pre-shared key
(PSK). The reader stores it encrypted with Windows DPAPI, so it can be
recovered without changing anything on the reader:

1. On Linux, read the encrypted key (TLV `0xbb010002`) and the key's hash
   (TLV `0xbb020007`) from the reader. Both reads are read-only. Stop
   `fprintd` first so it isn't holding the reader:

   ```sh
   make
   mkdir -p captures
   sudo systemctl stop fprintd
   ./build/goodix-probe rt-psk-read > captures/psk-read.txt
   python3 tools/extract_psk.py captures/psk-read.txt \
       --blob captures/psk_dpapi_blob.bin --hash captures/psk_hash.hex
   ```

2. In the Windows install that paired the reader, decrypt the blob as
   `SYSTEM` (the Windows Biometric Service context). Copy
   `captures/psk_dpapi_blob.bin` and `tools/windows/` over, then run from an
   elevated PowerShell:

   ```powershell
   powershell -ExecutionPolicy Bypass -File tools\windows\unseal-as-system.ps1 -BlobPath psk_dpapi_blob.bin
   ```

   It prints the 32-byte PSK as hex. These scripts are cleaned-up versions of
   the ones used for this unit and haven't been re-run since.

3. Back on Linux, combine the PSK and the hash into `captures/psk.hex` (PSK
   on the first line, hash on the second) and install it for `fprintd`:

   ```sh
   printf '%s\n' '<psk hex from step 2>' > captures/psk.hex
   cat captures/psk_hash.hex >> captures/psk.hex
   sudo install -Dm600 -o root -g root captures/psk.hex /etc/goodix5584/psk.hex
   ```

The frames and TLV layout behind these steps are in
[docs/protocol-notes.md](docs/protocol-notes.md#psk-provisioning-analysis-2026-07-20).

The driver looks for the file at `$GOODIX5584_SECRETS_FILE`, then
`/etc/goodix5584/psk.hex`, then `captures/psk.hex` relative to the working
directory. `captures/` is gitignored; never commit the key.

### 2. Build and install the driver

```sh
cd packaging
makepkg -si
sudo pacman -S --needed fprintd
```

The package replaces `libfprint`, so `fprintd` uses it directly. See
[packaging/README.md](packaging/README.md) for details and rollback.

### 3. Enroll a finger

```sh
fprintd-enroll -f right-index-finger
fprintd-verify
```

Or use a graphical enrollment screen. COSMIC has none yet, but KDE's works
from any desktop: `systemsettings kcm_users`, then **Configure Fingerprint
Authentication**.

### 4. Use it for polkit prompts (optional)

To accept a fingerprint in polkit authentication prompts, create
`/etc/pam.d/polkit-1`:

```
#%PAM-1.0
auth       sufficient   pam_fprintd.so
auth       include      system-auth
account    include      system-auth
password   include      system-auth
session    include      system-auth
```

The password still works if the fingerprint fails or times out.

## Maintenance

**OpenCV updates break the driver.** The package links against versioned
OpenCV libraries, so after a major OpenCV update `fprintd` fails to start
with an error like `libopencv_core.so.500: cannot open shared object file`.
Rebuild and reinstall:

```sh
cd packaging && makepkg -Cfsi
```

**Debug logging:** to see match scores and finger detection, add
`Environment=G_MESSAGES_DEBUG=all` to an `fprintd.service` drop-in, restart
`fprintd`, and read `journalctl -u fprintd`.

## Repository layout

| Path | Contents |
| --- | --- |
| `patches/` | The driver patch and notes on what it changes |
| `packaging/` | PKGBUILD that builds the patched libfprint as a pacman package |
| `docs/protocol-notes.md` | Protocol reverse-engineering notes |
| `src/goodix_probe.c` | Small libusb probe: NOP, firmware version, PSK read |
| `tools/` | Key extraction, RTSEC codec and tests, capture replay, offline TLS decryption, live TLS session tools |
| `tools/windows/` | PowerShell scripts that decrypt the pairing key as `SYSTEM` |

Gitignored and kept local: `captures/` (USB captures and the key),
`windows-drivers/` (the Windows driver payload), and enrolled test prints.

## Protocol highlights

Full details in [docs/protocol-notes.md](docs/protocol-notes.md).

- **Transport:** Goodix RTSEC framing over USB bulk. Bulk OUT writes must be
  split into 64-byte transfers; larger ones are silently ignored.
- **Session:** TLS 1.2 PSK (`PSK-AES128-CBC-SHA256`). The reader is the TLS
  client and the host runs the server. There is no forward secrecy, so USB
  captures decrypt offline with the PSK.
- **Images:** 108x88 pixels, 12 bits per pixel.
- **Firmware name:** a cold reader reports `GF3208_RTSEC_APP_10042`, and
  `GF3268_RTSEC_APP_10042` after Windows initializes it. Both work.
- **Not compatible** with libfprint's stock `goodixmoc` driver.

## Related projects

[libfprint-goodix55b4-milan](https://github.com/TheWeirdDev/libfprint-goodix55b4-milan)
(from October 2026) also supports `27c6:5584`, with Goodix's own matcher. It
requires overwriting the reader's pairing key with zeros, after which Windows
no longer pairs with it. This driver keeps the Windows key.

## License

LGPL-2.1-or-later, the same as libfprint. See [LICENSE](LICENSE).
