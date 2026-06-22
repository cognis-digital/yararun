# Demo 05 — Ransom note dropped across a file share

## Context (defensive / authorized triage)

Users report that documents on a shared drive were replaced with a
`README_RECOVER_FILES.txt` and now carry an unknown extension. Before
anything else, the SOC wants a fast, scriptable confirmation that this is a
ransomware note (and not a phishing prank) so they can trigger the IR runbook.

The note here is sanitized — the BTC address is an obvious placeholder — but
the *language* is the real signal: "your files have been encrypted",
"decrypt", "bitcoin", "BTC wallet", "pay the ransom", "private key".

## Run it

```
python -m yararun scan demos/05-ransom-note/README_RECOVER_FILES.txt
python -m yararun --format json scan demos/05-ransom-note/README_RECOVER_FILES.txt
echo "exit=$?"
```

## Expected

- `Ransom_Note` fires at severity **critical**; `max_severity` is `critical`.
- Exit code `1`.

## How to act

Isolate affected hosts immediately, identify patient zero from the earliest
note timestamp, preserve a copy of one encrypted file + the note for the
recovery vendor, and check backups before considering any payment (which is
usually the wrong call). Sweep the rest of the estate for the same note with:

```
python -m yararun --format json scan /mnt/share/**/README_RECOVER_FILES.txt
```
