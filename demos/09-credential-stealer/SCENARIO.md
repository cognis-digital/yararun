# Demo 09 — Infostealer credential-harvesting indicators

## Context (defensive / authorized triage)

An EDR alert flagged an unsigned binary that briefly ran from
`C:\Users\Public`. Rather than detonate it, an analyst ran `strings` over it
and saved the output. They want a quick verdict on whether it targets browser
and wallet credential stores (the hallmark of an infostealer family).

`stealer_strings.txt` is that `strings` dump. The bundled `Credential_Theft`
rule keys on the well-known artifact paths: Chrome `Login Data`, Firefox
`key3.db` / `logins.json`, and `wallet.dat`.

## Run it

```
python -m yararun scan demos/09-credential-stealer/stealer_strings.txt
python -m yararun --format json scan demos/09-credential-stealer/stealer_strings.txt
```

## Expected

- `Credential_Theft` fires at severity **high** (≥2 of the credential-store
  paths present).
- Exit code `1`.

## How to act

Treat every credential reachable from that endpoint as exposed: force
password resets and session-token revocation for the user, check for
exfil (the `zip -r ... loot.zip` line is a staging tell), and hunt the same
artifact-path strings fleet-wide to scope the stealer's spread.
