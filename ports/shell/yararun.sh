#!/bin/sh
# yararun — POSIX shell port of the triage-scan core.
#
#   yararun.sh info <file>   -> size / filetype / sha256 (via coreutils)
#   yararun.sh scan <file>   -> info + bundled triage string rules that fired
#
# Pure POSIX sh + standard coreutils (wc, head, od, sha256sum/shasum, grep).
# Passive/offline by design: only reads the bytes you hand it. Defensive use.
# JSON-ish line output; scan exits 1 when any rule fires (CI gate parity).
set -eu

usage() { echo "usage: yararun.sh <info|scan> <file>" >&2; exit 2; }

[ "$#" -ge 2 ] || usage
cmd="$1"; file="$2"
[ -r "$file" ] || { echo "error: cannot read $file" >&2; exit 2; }

# --- file intelligence ----------------------------------------------------- #
yr_size() { wc -c < "$file" | tr -d ' '; }

yr_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$file" | cut -d' ' -f1
  elif command -v shasum    >/dev/null 2>&1; then shasum -a 256 "$file" | cut -d' ' -f1
  else echo "unavailable"; fi
}

# Coarse magic sniff from the first bytes (hex), mirroring the reference tool.
yr_filetype() {
  magic=$(od -An -tx1 -N4 "$file" 2>/dev/null | tr -d ' \n')
  case "$magic" in
    4d5a*)     echo "pe" ;;
    7f454c46*) echo "elf" ;;
    feedface*|feedfacf*|cafebabe*|cffaedfe*) echo "macho" ;;
    504b0304*) echo "zip/office/jar" ;;
    25504446*) echo "pdf" ;;
    89504e47*) echo "png" ;;
    *)
      # printable-ratio heuristic over the first 4096 bytes
      np=$(head -c 4096 "$file" | tr -dc '\11\12\13\14\15\40-\176' | wc -c | tr -d ' ')
      tot=$(head -c 4096 "$file" | wc -c | tr -d ' ')
      if [ "$tot" -gt 0 ] && [ $((np * 100 / tot)) -gt 92 ]; then echo "text"; else echo "data"; fi
      ;;
  esac
}

# --- triage string rules (literal-substring subset) ------------------------ #
# A rule is a tab-separated record:  name<TAB>severity<TAB>min<TAB>needles...
# (each needle separated by a literal newline). We avoid pipe-to-function so
# the fired-rule list survives in the parent shell (no subshell scoping bug).
FIRED=""
fire() { FIRED="${FIRED}${FIRED:+ }$1:$2"; }

# check NAME SEVERITY MIN NEEDLE...   — fire NAME if >= MIN needles are present.
check() {
  name="$1"; sev="$2"; min="$3"; shift 3
  c=0
  for n in "$@"; do
    if LC_ALL=C grep -qF -- "$n" "$file" 2>/dev/null; then c=$((c + 1)); fi
  done
  [ "$c" -ge "$min" ] && fire "$name" "$sev" || true
}

run_rules() {
  check Embedded_PowerShell high 3 \
    'powershell' '-enc' '-EncodedCommand' 'FromBase64String' \
    'DownloadString' 'IEX' 'Invoke-Expression' 'hidden' 'bypass'
  check Ransom_Note critical 3 \
    'your files have been encrypted' 'decrypt' 'bitcoin' \
    'BTC wallet' 'pay the ransom' 'private key'
  check Cryptominer_Config high 2 \
    'stratum+tcp://' 'xmrig' 'minerd' 'pool.minexmr' 'donate-level' 'cryptonight'
  check Shell_Reverse_Connect critical 2 \
    'nc -e' 'ncat -e' 'bash -i >&' '/dev/tcp/' 'socket.socket' 'subprocess.call'
  check UPX_Packed medium 2 'UPX0' 'UPX1' 'UPX!'
  check EICAR_Test_File low 1 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR'
}

max_sev() {
  for s in critical high medium low; do
    case " $FIRED " in *":$s "*) echo "$s"; return;; esac
  done
  echo info
}

emit_info() {
  printf '{"tool":"yararun","target":"%s","size":%s,"filetype":"%s","sha256":"%s"}\n' \
    "$file" "$(yr_size)" "$(yr_filetype)" "$(yr_sha256)"
}

case "$cmd" in
  info) emit_info ;;
  scan)
    run_rules
    n=0; [ -n "$FIRED" ] && n=$(echo "$FIRED" | wc -w | tr -d ' ')
    matches=""
    for m in $FIRED; do
      r=${m%%:*}; sv=${m#*:}
      matches="${matches}${matches:+,}{\"rule\":\"$r\",\"severity\":\"$sv\"}"
    done
    printf '{"tool":"yararun","target":"%s","size":%s,"filetype":"%s","match_count":%s,"max_severity":"%s","matches":[%s]}\n' \
      "$file" "$(yr_size)" "$(yr_filetype)" "$n" "$(max_sev)" "$matches"
    [ "$n" -gt 0 ] && exit 1 || exit 0
    ;;
  *) usage ;;
esac
