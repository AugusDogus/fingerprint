#!/usr/bin/env python3
"""Recover the reader's pairing key (PSK) from a Windows install, on Linux.

The reader's PSK is sealed with Windows DPAPI by the Windows Biometric
Service (the SYSTEM account). This decrypts it offline from the Windows
filesystem, so Windows never has to boot. It is read-only: it reads the
blob you pulled off the reader (see extract_psk.py) and three files from the
Windows install, and changes nothing.

It needs, from the Windows install that paired the reader:
  - the SYSTEM and SECURITY registry hives (Windows/System32/config/), and
  - the SYSTEM account's DPAPI master key named in the blob
    (Windows/System32/Microsoft/Protect/S-1-5-18/...).

Point --windows at a mounted Windows filesystem to find them automatically,
or pass --system/--security/--masterkey explicitly.

Example:
    sudo mount -o ro /dev/nvme0n1p3 /mnt/win
    python3 tools/recover_psk.py \\
        --blob captures/psk_dpapi_blob.bin --windows /mnt/win \\
        --hash captures/psk_hash.hex --out captures/psk.hex

Requires impacket (`pip install impacket`). The printed value is the pairing
key; treat it like a password.
"""

import argparse
import os
import sys
import uuid

try:
    from impacket.dpapi import MasterKeyFile, MasterKey, DPAPI_BLOB
    from impacket.examples.secretsdump import LocalOperations, LSASecrets
except ImportError:
    sys.exit("recover_psk: impacket is required. Install it with "
             "`pip install impacket` (ideally in a venv).")

# A DPAPI blob is: 4-byte version, 16-byte provider GUID, 4-byte masterkey
# version, then the 16-byte masterkey GUID that names the key we need.
_MASTERKEY_GUID_OFFSET = 24


def masterkey_guid(blob: bytes) -> str:
    if len(blob) < _MASTERKEY_GUID_OFFSET + 16:
        raise ValueError(
            f"DPAPI blob is only {len(blob)} bytes; it is truncated or not a "
            "DPAPI blob. Re-run extract_psk.py.")
    return str(uuid.UUID(bytes_le=blob[_MASTERKEY_GUID_OFFSET:_MASTERKEY_GUID_OFFSET + 16]))


def find_in_windows(root: str, guid: str) -> tuple[str, str, str]:
    """Locate the SYSTEM/SECURITY hives and the masterkey file under a root."""
    def one(pattern: str, what: str) -> str:
        # Windows paths are case-insensitive; match case-insensitively.
        matches = _iglob(root, pattern)
        if not matches:
            raise FileNotFoundError(
                f"could not find {what} under {root} (looked for {pattern}). "
                "Is this the root of the Windows install that paired the reader?")
        return matches[0]

    system = one("Windows/System32/config/SYSTEM", "the SYSTEM hive")
    security = one("Windows/System32/config/SECURITY", "the SECURITY hive")
    # The SYSTEM account's masterkeys live under S-1-5-18, sometimes in a
    # User/ subfolder; search both for a file named exactly the GUID.
    mk_matches = _iglob(root, f"Windows/System32/Microsoft/Protect/S-1-5-18/**/{guid}")
    if not mk_matches:
        raise FileNotFoundError(
            f"could not find master key {guid} under "
            f"{root}/Windows/System32/Microsoft/Protect/S-1-5-18. The reader "
            "may have been paired by a different Windows install, or re-paired "
            "since this blob was read.")
    return system, security, mk_matches[0]


def _iglob(root: str, rel: str) -> list[str]:
    """Case-insensitive recursive glob of `rel` under `root`."""
    parts = rel.split("/")
    candidates = [root]
    for part in parts:
        nxt: list[str] = []
        for base in candidates:
            if part == "**":
                for dirpath, _dirs, _files in os.walk(base):
                    nxt.append(dirpath)
                continue
            try:
                entries = os.listdir(base)
            except (NotADirectoryError, FileNotFoundError):
                continue
            nxt.extend(os.path.join(base, e) for e in entries
                       if e.lower() == part.lower())
        candidates = nxt
    return [c for c in candidates if os.path.exists(c)]


def dpapi_system_keys(system_hive: str, security_hive: str) -> dict:
    """Recover the machine and user DPAPI_SYSTEM keys from the hives."""
    keys: dict[str, bytes] = {}

    def on_secret(_secret_type, secret):
        # LSASecrets formats DPAPI_SYSTEM as two labelled hex lines.
        if secret.startswith("dpapi_machinekey:"):
            machine, user = secret.splitlines()
            keys["MachineKey"] = bytes.fromhex(machine.split(":")[1].strip()[2:])
            keys["UserKey"] = bytes.fromhex(user.split(":")[1].strip()[2:])

    boot_key = LocalOperations(system_hive).getBootKey()
    lsa = LSASecrets(security_hive, boot_key, None, isRemote=False,
                     history=False, perSecretCallback=on_secret)
    lsa.dumpSecrets()
    if "UserKey" not in keys:
        raise ValueError(
            "no DPAPI_SYSTEM secret in the SECURITY hive; it does not pair with "
            "the SYSTEM hive, or the hives are from a different install.")
    return keys


def decrypt_masterkey(mk_path: str, dpapi_system: dict) -> bytes:
    data = open(mk_path, "rb").read()
    mkf = MasterKeyFile(data)
    data = data[len(mkf):]
    if mkf["MasterKeyLen"] <= 0:
        raise ValueError(f"master key file {mk_path} has no master key blob.")
    mk = MasterKey(data[:mkf["MasterKeyLen"]])
    for name in ("UserKey", "MachineKey"):
        decrypted = mk.decrypt(dpapi_system[name])
        if decrypted:
            return decrypted
    raise ValueError(
        f"neither DPAPI_SYSTEM key decrypted master key {os.path.basename(mk_path)}. "
        "The hives and the master key must come from the same Windows install.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--blob", required=True,
                        help="DPAPI blob from extract_psk.py (captures/psk_dpapi_blob.bin)")
    parser.add_argument("--windows", help="root of a mounted Windows filesystem")
    parser.add_argument("--system", help="SYSTEM hive (instead of --windows)")
    parser.add_argument("--security", help="SECURITY hive (instead of --windows)")
    parser.add_argument("--masterkey", help="the master key file named by the blob")
    parser.add_argument("--hash", help="PSK hash from extract_psk.py, for --out")
    parser.add_argument("--out", help="write psk.hex (PSK line, then hash line)")
    args = parser.parse_args()

    blob = open(args.blob, "rb").read()
    guid = masterkey_guid(blob)

    if args.windows:
        system, security, masterkey = find_in_windows(args.windows, guid)
    elif args.system and args.security and args.masterkey:
        system, security, masterkey = args.system, args.security, args.masterkey
    else:
        return _fail("pass --windows <mounted root>, or all of --system, "
                     "--security and --masterkey.")

    if args.out and not args.hash:
        return _fail("--out needs --hash so psk.hex gets both lines the driver "
                     "expects (PSK, then hash).")

    try:
        dpapi_system = dpapi_system_keys(system, security)
        key = decrypt_masterkey(masterkey, dpapi_system)
        psk = DPAPI_BLOB(blob).decrypt(key)
    except (ValueError, FileNotFoundError, OSError) as exc:
        return _fail(str(exc))

    if psk is None or len(psk) != 32:
        return _fail(f"decryption produced {0 if psk is None else len(psk)} "
                     "bytes, expected a 32-byte PSK. The master key decrypted, "
                     "but this blob is not the PSK blob (TLV 0xbb010002).")

    psk_hex = psk.hex()
    if args.out:
        psk_hash = open(args.hash).read().strip()
        with open(args.out, "w", encoding="ascii") as f:
            f.write(f"{psk_hex}\n{psk_hash}\n")
        os.chmod(args.out, 0o600)
        print(f"wrote {args.out} (PSK and hash). Install it with:\n"
              f"  sudo install -Dm600 -o root -g root {args.out} /etc/goodix5584/psk.hex")
    else:
        print(psk_hex)
    return 0


def _fail(message: str) -> int:
    print(f"recover_psk: {message}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
