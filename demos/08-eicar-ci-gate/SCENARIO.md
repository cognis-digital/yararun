# Demo 08 — EICAR test file as a CI / pre-commit malware gate

## Context (defensive / authorized testing)

You want to prove your build pipeline *actually* blocks malicious artifacts
without ever using live malware. The
[EICAR test string](https://www.eicar.org/download-anti-malware-testfile/) is
the industry-standard, completely harmless 68-byte file that every scanner is
required to flag.

Because on-access antivirus quarantines the canonical EICAR bytes the moment
they hit disk, this demo **generates** the file locally instead of committing
it:

```
python demos/08-eicar-ci-gate/build_eicar.py     # writes eicar.com.txt
```

This demo doubles as the reference for YARARUN's CI exit-code contract and the
new `--fail-on` severity gate.

## Run it — the gate

EICAR maps to severity **low**, so the default gate trips:

```
python -m yararun scan demos/08-eicar-ci-gate/eicar.com.txt
echo "exit=$?"          # -> 1 (any actionable finding)
```

Raise the bar so only high/critical findings break the build — EICAR (low)
now passes, which is how you tune noise out of CI:

```
python -m yararun scan --fail-on high demos/08-eicar-ci-gate/eicar.com.txt
echo "exit=$?"          # -> 0 (low finding is below the 'high' threshold)
```

Emit SARIF for GitHub code-scanning / Advanced Security:

```
python -m yararun --format sarif scan demos/08-eicar-ci-gate/eicar.com.txt \
    > eicar.sarif
```

## Expected

- `EICAR_Test_File` fires at severity **low**.
- Default exit `1`; with `--fail-on high`, exit `0`.
- The SARIF run validates against SARIF 2.1.0 and shows one `note`-level result.

## Use in a workflow

```yaml
- run: pip install cognis-yararun
- run: yararun --format sarif scan ./artifacts/* > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: results.sarif }
```
