# 02-deep — YARA-subset triage of a suspicious dropper

This demo runs the YARARUN rule engine against a synthetic-but-realistic
malware artifact (`suspicious_sample.bin`) using both the bundled triage
pack and a custom ruleset (`triage.yar`) that exercises the harder engine
features: **hex strings with wildcards/jumps**, **regex strings**,
**`#count` comparisons**, **offset anchoring**, **`N of (...)`** set
conditions, the **`xor` modifier**, the **`entropy` / `filetype` module
variables**, and **`uint16()` integer functions**.

## The sample

`suspicious_sample.bin` is hand-built (no live malware) to trip several
detections at once:

- an `MZ … PE\0\0` header with a wildcarded DOS stub + jump region (`MZ` at offset 0)
- UPX packer markers (`UPX0` / `UPX1` / `UPX!`)
- an encoded PowerShell download-cradle (`powershell -enc IEX … DownloadString … FromBase64String`)
- two hardcoded C2 URLs plus a `.onion` fallback
- a **single-byte XOR-encoded** copy of the `MZ` + DOS-mode stub (key `0x5a`)
- a 2 KB high-entropy (≈7.9 bits/byte) packed-payload region

## Run it

File intelligence only (entropy / type / hashes, the VirusTotal-style triage signal):

```
python -m yararun info demos/02-deep/suspicious_sample.bin
```

Scan with the bundled triage pack (human table):

```
python -m yararun scan demos/02-deep/suspicious_sample.bin
```

Scan with the custom ruleset, JSON output (machine-readable, non-zero exit
when actionable findings exist):

```
python -m yararun --format json scan -r demos/02-deep/triage.yar \
    demos/02-deep/suspicious_sample.bin
echo "exit=$?"          # -> 1, because high/critical matches were found
```

Validate a ruleset before deploying it, and list every loaded rule:

```
python -m yararun compile demos/02-deep/triage.yar
python -m yararun rules
python -m yararun --format json rules -r demos/02-deep/triage.yar
```

## Expected matches (custom ruleset)

| Rule                          | Severity | Why it fires                                          |
|-------------------------------|----------|-------------------------------------------------------|
| `XOR_Hidden_Executable`       | critical | XOR-encoded `MZ` + DOS stub recovered by key search   |
| `Dropper_PowerShell_Chain`    | high     | `powershell` + 3 of enc/DownloadString/b64/IEX        |
| `C2_Beacon_URL`               | high     | one `.onion` + `#url >= 2`                             |
| `Embedded_PE_via_HexHeader`   | medium   | `{ 4D 5A ?? ?? [4-64] 50 45 00 00 }` + `uint16(0)==0x5A4D` |
| `Packed_Payload_Entropy`      | medium   | `entropy >= 7.5 and filetype == "pe"`                 |

Max severity is **critical** and the scan exits non-zero. A clean text file
produces zero matches and a `0` exit code, so YARARUN slots cleanly into CI /
pre-commit malware gates.
