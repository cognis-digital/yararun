#!/bin/sh
# Smoke test for the shell port — std coreutils only. Exits non-zero on failure.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
yr="$here/yararun.sh"
tmp="${TMPDIR:-$here}/yararun_porttest_$$"
mkdir -p "$tmp"
trap 'rm -rf "$tmp"' EXIT
fail=0
ok()   { echo "ok   - $1"; }
bad()  { echo "FAIL - $1"; fail=1; }

# 1. clean file -> exit 0, max_severity info
printf 'just ordinary text\n' > "$tmp/clean.txt"
if "$yr" scan "$tmp/clean.txt" | grep -q '"max_severity":"info"'; then
  ok "clean file is info"; else bad "clean file severity"; fi
"$yr" scan "$tmp/clean.txt" >/dev/null && ok "clean exits 0" || bad "clean exit code"

# 2. ransom note -> critical, exit 1
printf 'your files have been encrypted, send bitcoin to our BTC wallet to decrypt\n' > "$tmp/ransom.txt"
out=$("$yr" scan "$tmp/ransom.txt" || true)
echo "$out" | grep -q '"rule":"Ransom_Note"' && ok "ransom fires" || bad "ransom rule"
echo "$out" | grep -q '"max_severity":"critical"' && ok "ransom critical" || bad "ransom severity"
if "$yr" scan "$tmp/ransom.txt" >/dev/null; then bad "ransom should exit 1"; else ok "ransom exits 1"; fi

# 3. powershell dropper
printf 'powershell -enc IEX DownloadString FromBase64String\n' > "$tmp/ps.txt"
"$yr" scan "$tmp/ps.txt" | grep -q '"rule":"Embedded_PowerShell"' \
  && ok "powershell fires" || bad "powershell rule"

# 4. EICAR — write only the rule's needle prefix (not the full live signature,
#    so on-access AV does not quarantine the fixture on Windows test runners).
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR test marker\n' > "$tmp/eicar.txt"
"$yr" scan "$tmp/eicar.txt" | grep -q '"rule":"EICAR_Test_File"' \
  && ok "eicar fires" || bad "eicar rule"

# 5. info has sha256 + filetype
printf 'MZ\220\0rest\n' > "$tmp/pe.bin"
"$yr" info "$tmp/pe.bin" | grep -q '"filetype":"pe"' && ok "pe filetype" || bad "pe filetype"
"$yr" info "$tmp/clean.txt" | grep -q '"sha256":"' && ok "info sha256" || bad "info sha256"

[ "$fail" -eq 0 ] && echo "ALL SHELL TESTS PASSED" || { echo "SHELL TESTS FAILED"; exit 1; }
