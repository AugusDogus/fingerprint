# Recovering the reader's pairing key

The reader talks to the host over TLS with a pre-shared key (PSK). Windows
generates a random PSK when it first pairs with the reader and stores it on
the reader, encrypted with Windows DPAPI. The Linux driver needs that same
PSK to talk to the reader.

You recover it once. Nothing here changes the reader, so the reader keeps
working in Windows afterwards. Two things come off the reader (read-only):

- the **DPAPI-encrypted PSK blob** (TLV `0xbb010002`), still sealed by
  Windows, and
- the **PSK hash** (TLV `0xbb020007`), which the driver checks before each
  session.

Decrypting the blob needs a Windows secret. You can do that decryption on
Linux (Option A) or on Windows (Option B). Both produce the same 32-byte
PSK. The end result is `captures/psk.hex`: the PSK on line 1, the hash on
line 2.

> The PSK is the reader's key. Treat the recovered value and `psk.hex` like a
> password: keep them off shared storage and out of git. `captures/` is
> gitignored for this reason.

## Step 1: read the blob and hash off the reader (Linux)

`fprintd` must not be using the reader, and your user needs USB access to it
(`tools/70-goodix-re.rules`).

```sh
make
mkdir -p captures
sudo systemctl stop fprintd
./build/goodix-probe rt-psk-read > captures/psk-read.txt
python3 tools/extract_psk.py captures/psk-read.txt \
    --blob captures/psk_dpapi_blob.bin --hash captures/psk_hash.hex
```

This writes `captures/psk_dpapi_blob.bin` (the sealed blob) and
`captures/psk_hash.hex` (the hash). Decrypt the blob with Option A or B.

## Option A: decrypt on Linux, Windows stays off

The reader's blob is sealed by the Windows Biometric Service (the `SYSTEM`
account) with DPAPI. DPAPI can be decrypted offline from the Windows
filesystem, so Windows never has to boot. You need read access to the
Windows partition that paired the reader.

Requires [impacket](https://github.com/fortra/impacket)
(`pip install impacket`, ideally in a virtualenv) and read access to the
Windows filesystem.

1. Mount the Windows partition read-only:

   ```sh
   sudo mount -o ro /dev/nvmeXnYpZ /mnt/win
   ```

   If the Windows drive uses BitLocker, unlock it first (for example with
   `dislocker` and your recovery key); an encrypted volume cannot be read
   otherwise.

2. Recover the PSK and write `psk.hex`:

   ```sh
   python3 tools/recover_psk.py \
       --blob captures/psk_dpapi_blob.bin --windows /mnt/win \
       --hash captures/psk_hash.hex --out captures/psk.hex
   ```

   `recover_psk.py` reads three files from the Windows install: the `SYSTEM`
   and `SECURITY` registry hives and the `SYSTEM` account's DPAPI master key
   named in the blob. It reads them read-only and prints where it wrote
   `psk.hex`. If you have those three files already (for example from an
   image with The Sleuth Kit's `icat`), pass them with `--system`,
   `--security` and `--masterkey` instead of `--windows`.

3. Unmount:

   ```sh
   sudo umount /mnt/win
   ```

## Option B: decrypt on Windows

If you would rather not mount the Windows filesystem from Linux, decrypt the
blob on the Windows install itself. This needs no impacket.

1. Copy `captures/psk_dpapi_blob.bin` and the `tools/windows/` scripts to the
   Windows install that paired the reader.
2. In an elevated (Administrator) PowerShell:

   ```powershell
   powershell -ExecutionPolicy Bypass -File tools\windows\unseal-as-system.ps1 -BlobPath psk_dpapi_blob.bin
   ```

   `unseal-as-system.ps1` runs the decryption as `SYSTEM` through a one-off
   scheduled task (DPAPI only unseals the blob in that account's context),
   prints the 32-byte PSK as hex, and removes its temporary files.

   > These scripts are cleaned-up versions of the ones used for this unit and
   > have not been re-run since.

3. Back on Linux, assemble `psk.hex` from the printed PSK and the hash:

   ```sh
   printf '%s\n' '<psk hex from Windows>' > captures/psk.hex
   cat captures/psk_hash.hex >> captures/psk.hex
   ```

## Step 3: install the key for fprintd

```sh
sudo install -Dm600 -o root -g root captures/psk.hex /etc/goodix5584/psk.hex
```

The driver looks for the key at `$GOODIX5584_SECRETS_FILE`, then
`/etc/goodix5584/psk.hex`, then `captures/psk.hex` relative to the working
directory.

## How it works

The frames, TLV layout, and DPAPI blob structure behind these steps are in
[protocol-notes.md](protocol-notes.md#psk-provisioning-analysis-2026-07-20).
