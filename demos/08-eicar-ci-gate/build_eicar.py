#!/usr/bin/env python3
"""Materialize the EICAR anti-malware test file at scan time.

The 68-byte EICAR string is harmless by design, but real-time AV will
quarantine it the instant it touches disk in its canonical form — which would
delete a committed copy and break this demo on protected machines. So we ship
the string in two halves and join them here; run this once to write
`eicar.com.txt` locally, then scan it.

    python demos/08-eicar-ci-gate/build_eicar.py
    python -m yararun scan demos/08-eicar-ci-gate/eicar.com.txt

See https://www.eicar.org/download-anti-malware-testfile/ for the spec.
"""
import os

# Standard EICAR test string, split so an on-write AV scan does not flag the
# source file itself. Joining yields the exact 68-byte test artifact.
_A = r"X5O!P%@AP[4\PZX54(P^)7CC)7}"
_B = r"$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def main() -> None:
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "eicar.com.txt")
    with open(out, "wb") as fh:
        fh.write((_A + _B).encode("ascii") + b"\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
