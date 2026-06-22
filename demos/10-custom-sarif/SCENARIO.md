# Demo 10 — Custom ruleset + SARIF export for code-scanning

## Context (defensive / authorized review)

A platform team wants a lightweight pre-merge check that catches hardcoded
secrets and unsafe config flags, and surfaces them in the GitHub
**Security → Code scanning** tab like any other static-analysis tool. YARARUN
ships a generic rule pack, but secret-hunting is org-specific, so this demo
uses a **custom ruleset** (`secrets.yar`) and YARARUN's **SARIF 2.1.0** output.

`settings.py` is a sample config that "accidentally" committed:

- an AWS access key id (the value is AWS's *own published example key*,
  `AKIAIOSFODNN7EXAMPLE`, not a live credential)
- a generic `api_key = "..."` assignment
- `DEBUG = True`, `ALLOWED_HOSTS = ['*']`, and `verify=False`

All values are placeholders — only the *patterns* are real.

## Run it

Human triage:

```
python -m yararun scan -r demos/10-custom-sarif/secrets.yar \
    demos/10-custom-sarif/settings.py
```

Validate the ruleset, then emit SARIF for upload:

```
python -m yararun compile demos/10-custom-sarif/secrets.yar
python -m yararun --format sarif scan -r demos/10-custom-sarif/secrets.yar \
    demos/10-custom-sarif/settings.py > settings.sarif
```

Gate the merge only on the worst issues:

```
python -m yararun scan --fail-on critical -r demos/10-custom-sarif/secrets.yar \
    demos/10-custom-sarif/settings.py
echo "exit=$?"          # -> 1 (the AWS key + PEM rule are critical)
```

## Expected

- `AWS_Access_Key_Id` (**critical**), `Generic_Api_Secret` (**high**), and
  `Debug_Backdoor_Flag` (**medium**) all fire on `settings.py`.
- The SARIF run carries one `reportingDescriptor` per matched rule, each with a
  `security-severity` property GitHub uses to rank the alert; results point at
  `settings.py` with a byte-offset region.

## Wire into CI

```yaml
- run: pip install cognis-yararun
- run: yararun --format sarif scan -r secrets.yar $(git ls-files) > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: results.sarif }
```
