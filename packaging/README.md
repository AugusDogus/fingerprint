# Packaging: libfprint-goodix5584

Repeatable, pacman-managed install of the patched libfprint for the
Goodix `27c6:5584` reader. Everything is built from pinned sources:

- Upstream: `TheWeirdDev/libfprint`, branch `55b4-experimental`, commit
  `d1ca62a801aa565e67d1a2a47aaa7a33232b7990` (pinned in the PKGBUILD).
- Patch: `goodixtls55x4-5584.patch` (kept in sync with `../patches/`).
- Udev rule: `70-goodix-5584.rules` (user-group access for local tools;
  fprintd itself runs as root).

## Install

```sh
cd packaging
makepkg -si            # builds, then installs via pacman (asks for sudo)
sudo pacman -S --needed fprintd
```

Rebuilds after changing the patch: `makepkg -Csf` (`-C` cleans the
already-patched source checkout, which `git apply` would otherwise refuse).

The package `provides`/`conflicts` `libfprint`, so `fprintd` and anything
else linking `libfprint-2.so.2` uses the patched build directly. No
`LD_LIBRARY_PATH` hacks, no files outside pacman's database.

## Runtime secrets

The driver needs the per-device PSK + hash at runtime (gitignored, never
packaged). Resolution order: `$GOODIX5584_SECRETS_FILE`, then
`/etc/goodix5584/psk.hex`, then `captures/psk.hex` relative to the cwd.
For fprintd (runs as root), install it once with:

```sh
sudo install -Dm600 -o root -g root captures/psk.hex /etc/goodix5584/psk.hex
```

For repo-local tools (probe, examples) nothing is needed when run from
the repository root.

## Rollback

```sh
sudo pacman -R libfprint-goodix5584
sudo pacman -S --asdeps libfprint   # restore the stock library
sudo rm -f /etc/goodix5584/psk.hex  # optional: remove the device secrets
```

## Notes

- `sha256sums` are `SKIP` on purpose: the upstream commit is pinned by
  full git hash and the patch/rule files are local to this repo.
- Enrolled prints live in `/var/lib/fprint` (fprintd) and are not part
  of the package or this repository.
