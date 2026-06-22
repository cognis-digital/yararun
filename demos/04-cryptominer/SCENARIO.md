# Demo 04 — Cryptojacking miner config on a compromised server

## Context (defensive / authorized triage)

A Linux web server showed sustained 100% CPU at night. A responder found a
JSON file under `/var/tmp/.cache/` and wants to confirm it is a coin-miner
configuration before pulling the host. `config.json` here is the classic
[XMRig](https://xmrig.com/) layout: a `stratum+tcp://` pool URL, a
`donate-level`, and the `cryptonight` algorithm — the exact strings the
bundled `Cryptominer_Config` rule keys on.

The pool host uses the reserved `.invalid` TLD and the wallet is a
placeholder, so nothing here is a live indicator — only the structural
signature is real.

## Run it

```
python -m yararun scan demos/04-cryptominer/config.json
python -m yararun --format json scan demos/04-cryptominer/config.json
```

## Expected

- `Cryptominer_Config` fires (severity **high**) on `stratum+tcp://` plus the
  `donate-level` / `cryptonight` / `pool.minexmr` markers.
- `Suspicious_URL` may also fire on the embedded pool URL.
- Exit code `1`.

## How to act

Treat the host as compromised: capture volatile state, identify the parent
process and its persistence (check `Persistence_Registry_Runkey` /
cron / systemd units), block the pool host at egress, and rotate any
credentials reachable from that server.
