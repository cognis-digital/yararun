# Demo 01 - Basic hunt over a suspicious script drop

## Context (defensive / authorized triage)

An incident responder pulled a folder of files off a quarantined host and
wants to triage it for known-bad indicators before deeper analysis. YARARUN
lets them run a small ruleset and immediately see which files and offsets hit.

This is a **detection / analysis** workflow only. YARARUN reads files and
reports matches; it never executes, modifies, or transmits anything.

## Files

- `rules.yar` - three example rules (text, regex with nocase, hex magic bytes).
- `samples/dropper.ps1` - a benign sample crafted to trip the rules
  (contains the literal indicator strings, not real malware).
- `samples/clean.txt` - a clean file that should not match.

## Run it

```
python -m yararun --format table scan demos/01-basic/samples -r demos/01-basic/rules.yar
```

JSON output (for pipelines):

```
python -m yararun --format json scan demos/01-basic/samples -r demos/01-basic/rules.yar
```

## Expected

- `dropper.ps1` matches `SuspiciousPowerShell` (the `$enc` + `$dl` strings)
  and `MZHeaderText`-style indicators.
- `clean.txt` produces no matches.
- Exit code is `1` because findings were produced (useful as a tripwire).
