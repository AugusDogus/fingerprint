# Driver patch: goodixtls55x4 for 27c6:5584

`goodixtls55x4-5584.patch` adapts the goodixtls 55x4 libfprint driver for
the Goodix `27c6:5584` unit tracked by this repository.

## Base

- Repo: `https://github.com/TheWeirdDev/libfprint.git`
- Branch: `55b4-experimental`
- Commit: `d1ca62a` ("Do not cancel read because in gnome lock screen after
  one unsuccessful attempt it stops working")

## Apply and build

```sh
git clone https://github.com/TheWeirdDev/libfprint.git
cd libfprint
git checkout 55b4-experimental   # d1ca62a
git apply ../patches/goodixtls55x4-5584.patch
meson setup build -Ddrivers=goodixtls55x4 -Ddoc=false -Dintrospection=false \
    -Dudev_rules=disabled -Dudev_hwdb=disabled -Dinstalled-tests=false
ninja -C build
```

## Runtime requirements

- The per-device PSK and PSK hash are read from `captures/psk.hex`
  (two 64-hex-char lines: PSK, then PMK hash), relative to the process
  working directory, or from `$GOODIX5584_SECRETS_FILE`. This file is
  gitignored and must never be committed.
- USB access for the invoking user (see `tools/70-goodix-re.rules`).

## Test programs

- `build/examples/img-capture <out.pgm>` — capture one frame.
- `build/examples/capture-minutiae <out.pgm>` — capture one frame, run
  NBIS minutiae detection, print `MINUTIAE_COUNT=N`, exit 0 iff N >= 10.

Run from the repository root so the default secrets path resolves, e.g.:

```sh
LD_LIBRARY_PATH=libfprint/build/libfprint \
    libfprint/build/examples/capture-minutiae captures/live-finger.pgm
```

## What the patch changes

- Registers VID/PID `27c6:5584` in the 55x4 `id_table`.
- Accepts the `GF32xx_RTSEC_APP_100xx` firmware family (unit reports both
  `GF3208_...` cold and `GF3268_...` after Windows init).
- Loads the per-device PSK + PSK hash from the gitignored secrets file
  instead of using the public goodix-fp-dump credentials.
- Removes commands outside the observed Windows set: `enable_chip` (0x96),
  FDT down/up (0x32/0x34), and sleep-mode (0x60/0x92) are no longer sent.
- Scan pipeline mirrors the Windows capture: 36, 20, 36, 70, 82, 20, 36,
  with NOP keepalives while waiting for the finger (the MCU drops off the
  bus after several idle seconds).
- FDT baseline values set to the per-unit values captured from Windows.
- Uses NBIS/mindtct matching; SIGFM is replaced by a stub when opencv4 is
  unavailable.
- Adds the `capture-minutiae` example used for the goal proof.
