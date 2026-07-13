#!/usr/bin/env python3
"""Type ASCII text into the running omarchy-windows guest through QEMU HMP."""

import argparse
import subprocess
import time


SHIFTED = {
    "~": "grave_accent",
    "!": "1",
    "@": "2",
    "#": "3",
    "$": "4",
    "%": "5",
    "^": "6",
    "&": "7",
    "*": "8",
    "(": "9",
    ")": "0",
    "_": "minus",
    "+": "equal",
    "{": "bracket_left",
    "}": "bracket_right",
    "|": "backslash",
    ":": "semicolon",
    '"': "apostrophe",
    "<": "comma",
    ">": "dot",
    "?": "slash",
}

PLAIN = {
    " ": "spc",
    "\n": "ret",
    "\t": "tab",
    "-": "minus",
    "=": "equal",
    "[": "bracket_left",
    "]": "bracket_right",
    "\\": "backslash",
    ";": "semicolon",
    "'": "apostrophe",
    "`": "grave_accent",
    ",": "comma",
    ".": "dot",
    "/": "slash",
}


def key_for(character: str) -> str:
    if character in SHIFTED:
        return f"shift-{SHIFTED[character]}"
    if character in PLAIN:
        return PLAIN[character]
    if character.isascii() and character.isalpha():
        return f"shift-{character.lower()}" if character.isupper() else character
    if character.isascii() and character.isdigit():
        return character
    raise ValueError(f"unsupported character: {character!r}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("text")
    parser.add_argument("--enter", action="store_true")
    parser.add_argument("--delay", type=float, default=0.08)
    args = parser.parse_args()

    text = args.text + ("\n" if args.enter else "")
    process = subprocess.Popen(
        [
            "podman",
            "exec",
            "-i",
            "omarchy-windows",
            "nc",
            "-w",
            "2",
            "127.0.0.1",
            "7100",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert process.stdin is not None
    for character in text:
        process.stdin.write(f"sendkey {key_for(character)} 40\n")
        process.stdin.flush()
        time.sleep(args.delay)
    process.stdin.close()

    stderr = process.stderr.read() if process.stderr is not None else ""
    return_code = process.wait()
    if return_code != 0:
        raise SystemExit(stderr or f"QEMU monitor connection failed: {return_code}")


if __name__ == "__main__":
    main()
