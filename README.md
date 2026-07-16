# yararun

**A dependency-free, pure-stdlib YARA-subset rule engine and malware/IOC triage toolkit.**

`yararun` compiles and runs a genuinely useful subset of YARA-style rules
(text / hex / regex strings, the `xor` modifier, counts, offsets, integer
functions, and `N of (...)` conditions) over any file, blob, directory, or
stdin — and layers on a file-intelligence module (Shannon entropy, magic-byte
file typing, MD5/SHA1/SHA256) and a real, non-trivial bundled triage rule pack.
It runs on nothing but the Python standard library, so it drops onto edge,
air-gapped, and incident-response hosts with no install friction.

> **Defensive / forensic use only.** Scan files and blobs you are authorized to
> inspect.

> `yararun` also ships as the **`huntkit yara`** module of
> [**huntkit**](https://github.com/cognis-digital/huntkit). This repository
> remains the home of the standalone engine and CLI; both entry points share the
> same code.

---

## Table of contents

- [Why yararun](#why-yararun)
- [Features](#features)
- [Install](#install)
- [Quick start](#quick-start)
- [Usage](#usage)
  - [`scan`](#scan)
  - [`info`](#info)
  - [`rules`](#rules)
  - [`compile`](#compile)
  - [`feeds`](#feeds)
- [Output formats](#output-formats)
- [Writing rules](#writing-rules)
- [Architecture](#architecture)
- [Python API](#python-api)
- [Configuration reference](#configuration-reference)
- [FAQ](#faq)
- [Further docs](#further-docs)
- [License](#license)

---

## Why yararun

Full YARA is a compiled C engine with a native dependency chain. That is a poor
fit for the exact places triage is most valuable: an incident responder's laptop
mid-flight, a locked-down build agent, or a disconnected enclave. `yararun`
targets that gap:

- **Zero dependencies.** Pure standard library. `pip install` or just copy the
  package. Works anywhere Python 3.10+ runs.
- **Familiar rule language.** If you can write a basic YARA rule, you can write
  a `yararun` rule — strings, hex with wildcards/jumps, regex, and boolean
  conditions all parse.
- **Batteries included.** A curated triage rule pack ships in the box, so
  `yararun scan <file>` is useful with no rules of your own.
- **CI-native.** SARIF 2.1.0 output and a severity exit-code gate make it a
  drop-in code-scanning / pipeline step.

## Features

- **YARA-subset engine** — `meta:` / `strings:` / `condition:` rules with:
  - text strings with `nocase`, `wide`, `ascii`, `fullword`, and `xor` modifiers
  - hex strings with wildcards and jumps: `{ 4D 5A ?? 50 [2-4] 90 }`
  - regex strings: `/https?:\/\/[a-z]+/ nocase`
  - counts (`#a > 3`), offsets/anchors (`$a at 0`, `$a in (0..1024)`, `@a[1]`),
    match length (`!a`), integer functions (`uint8/16/32(...)`, big-endian
    variants), arithmetic/comparison, and set conditions (`any of them`,
    `2 of ($s*)`, `all of (...)`)
  - special condition variables: `filesize`, `entropy`, `filetype`
- **File-intelligence module** — Shannon entropy, magic/file-type sniffing, and
  cryptographic hashes, surfaced both in results and as condition variables.
- **Bundled triage pack** — PE/ELF/Mach-O headers, UPX packing, high-entropy
  blobs, XOR-encoded MZ stubs, PowerShell / JS / VBScript droppers, base64 PE
  stubs, suspicious URLs / `.onion` C2, ransom notes, cryptominer configs,
  reverse shells, credential theft, persistence run-keys, and the EICAR test
  string.
- **Directory & recursive scanning** — point `scan` at a folder; walk
  recursively (or not), filter with include/exclude globs, and cap file size.
- **Five output formats** — `table`, `json`, `ndjson`, `csv`, and `sarif`.
- **Severity controls** — a `--fail-on` exit-code gate for pipelines and a
  `--min-severity` display filter for reports.
- **Edge/air-gap threat-intel feeds** — a keyless, offline-first feed catalog
  (`feeds`) with disk caching and sneakernet snapshot import/export.
- **Integrations** — an MCP server and a native `cognis-connect` emitter
  (STIX/TAXII, MISP, Sigma, SIEM, chat) via optional extras.

## Install

```bash
# from a clone
pip install -e .

# with the dev toolchain (pytest + ruff)
pip install -e ".[dev]"

# optional extras
pip install -e ".[mcp]"       # MCP stdio server
pip install -e ".[connect]"   # cognis-connect emit (STIX/MISP/Sigma/SIEM/chat)
```

Requires Python **3.10+**. The core engine and CLI need no third-party packages.

## Quick start

```bash
# scan a single file with the bundled triage pack
yararun scan suspicious.bin

# scan an entire directory tree, emit JSON
yararun --format json scan ./quarantine/

# file intelligence only (entropy / type / hashes), no rule matching
yararun info suspicious.bin

# validate a custom rule file
yararun compile my_rules.yar

# pipe bytes in over stdin
cat payload | yararun scan -
```

`scan` exits **non-zero** when it finds something actionable, so it slots
directly into a shell `&&` chain or a CI gate.

## Usage

The CLI is `yararun <global-flags> <subcommand> <args>`. The global
`--format {table,json,ndjson,csv,sarif}` flag (default `table`) selects output
rendering; `--version` prints the version.

### `scan`

Scan files and/or directories against the bundled pack or a custom rule file.

```bash
yararun scan [FILES/DIRS or -] [options]
```

| Option | Description |
| --- | --- |
| `-r, --rules FILE` | Use a custom rule file instead of the bundled pack. |
| `--fail-on {critical,high,medium,low}` | Exit non-zero only at/above this severity (default `low`). |
| `--min-severity {critical,high,medium,low,info}` | Suppress matches below this severity in the output. |
| `-R, --recursive` / `--no-recursive` | Recurse into sub-directories (default: on). |
| `--include GLOB` | Only scan files matching this glob (repeatable). |
| `--exclude GLOB` | Skip files matching this glob (repeatable; wins over `--include`). |
| `--max-bytes N` | Skip files larger than `N` bytes while walking (`0` = no limit). |
| `--follow-symlinks` | Follow symlinked directories while walking. |
| `--stats` | Print a walk summary (files/dirs/skips) to stderr. |

Examples:

```bash
# recursively scan a tree but only .ps1/.vba, skip anything over 5 MB
yararun scan ./mail-dump --include '*.ps1' --include '*.vba' --max-bytes 5000000

# scan the top level only, show just critical/high findings, print a walk summary
yararun scan ./incoming --no-recursive --min-severity high --stats

# gate a pipeline: fail only on high or critical
yararun scan --fail-on high ./release-artifacts/
```

### `info`

File intelligence without rule matching — size, file type, entropy, and hashes.

```bash
yararun info firmware.bin
yararun --format json info a.bin b.bin
```

### `rules`

List the loaded rules (bundled pack or a custom file) with severity, tags, and
condition.

```bash
yararun rules
yararun --format json rules -r my_rules.yar
```

### `compile`

Parse/validate a rule file and report the rule count — a fast syntax check for
CI or pre-commit.

```bash
yararun compile my_rules.yar
yararun --format json compile my_rules.yar
```

### `feeds`

An edge/air-gap threat-intel feed catalog. It is **passive and offline by
default**; only `feeds update`/`get` (without `--offline`) ever touch the
network.

```bash
yararun feeds list                       # catalog + cache freshness (offline)
yararun feeds list --domain vuln         # filter by domain
yararun feeds update cisa-kev epss       # fetch + cache (the only egress)
yararun feeds get cisa-kev --offline     # serve from cache only
yararun feeds snapshot-export feeds.tar.gz   # for sneakernet to an air gap
yararun feeds snapshot-import feeds.tar.gz
```

## Output formats

| Format | Best for |
| --- | --- |
| `table` | Human reading in a terminal (default). |
| `json` | Programmatic use; a single object for one target, an array for many. |
| `ndjson` | Streaming / log pipelines; one compact JSON object per file, one per line. |
| `csv` | Spreadsheets / data lakes; one row per matched string (RFC 4180 quoted). |
| `sarif` | GitHub code-scanning and SARIF viewers (SARIF 2.1.0). |

```bash
yararun --format ndjson scan ./tree/ > findings.ndjson
yararun --format csv    scan ./tree/ > findings.csv
yararun --format sarif  scan ./tree/ > results.sarif
```

## Writing rules

A rule file is one or more YARA-style rules:

```yara
rule Suspicious_Downloader : dropper network {
    meta:
        author      = "you"
        severity    = "high"
        description = "PowerShell one-liner that pulls and runs a remote payload"
    strings:
        $ps   = "powershell" nocase
        $dl   = "DownloadString" nocase
        $iex  = "IEX" fullword
        $url  = /https?:\/\/[a-z0-9.\-]{4,}/ nocase
    condition:
        $ps and $dl and ($iex or $url)
}
```

`severity` in `meta:` drives both the report and the SARIF/exit-code mapping
(`critical` > `high` > `medium` > `low` > `info`). See
[docs/USAGE.md](docs/USAGE.md) for the full condition grammar and worked
examples, and the `demos/` directory for runnable scenarios.

## Architecture

```
paths ─▶ scanfs.iter_targets ─▶ core.scan ─▶ ScanResult ─▶ renderers
 (file/dir/stdin)  (walk+glob)    │  (entropy/type/hash + rules)   │
                                  │                                ├─ table
                            parse_rules ─▶ StringDef matchers      ├─ json / ndjson / csv
                                          _Cond evaluator          └─ to_sarif (SARIF 2.1.0)
```

- `yararun/core.py` — the engine: rule parser, string compilers, condition
  evaluator, file-intelligence, `ScanResult`, and the exporters.
- `yararun/scanfs.py` — filesystem target expansion (recursion, globs, size cap).
- `yararun/cli.py` — argument parsing, subcommands, and renderers.
- `yararun/datafeeds.py` — the edge/air-gap feed catalog and cache.
- `yararun/mcp_server.py`, `yararun/connect.py` — optional integrations.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detail.

## Python API

```python
from yararun import scan, load_rules, parse_rules, to_sarif, to_ndjson, iter_targets

# scan a blob with the bundled pack
res = scan(open("sample.bin", "rb").read(), load_rules(), target="sample.bin")
print(res.max_severity, res.counts())
for m in res.matches:
    print(m.severity, m.rule, [s.ident for s in m.matched_strings])

# only keep high+ findings, then export
high = res.filtered("high")
print(to_ndjson([high]))

# walk a directory the way the CLI does
for path in iter_targets(["./tree"], recursive=True, include=["*.bin"]):
    ...
```

## Configuration reference

| Setting | Where | Effect |
| --- | --- | --- |
| `--format` | CLI global | Output rendering: `table`/`json`/`ndjson`/`csv`/`sarif`. |
| `--fail-on` | `scan` | Minimum severity that makes the process exit non-zero. |
| `--min-severity` | `scan` | Drops matches below this severity from the output. |
| `--recursive` / `--no-recursive` | `scan` | Directory descent. |
| `--include` / `--exclude` | `scan` | `fnmatch` globs over basename and relative path. |
| `--max-bytes` | `scan` | Per-file size ceiling while walking (`0` = unlimited). |
| `COGNIS_FEEDS_CACHE` | env | Feed cache directory (default `~/.cache/cognis-feeds`). |

**Exit codes:** `0` = no actionable findings; `1` = findings at/above the
`--fail-on` threshold; `2` = usage/IO error (e.g. a target path that does not
exist).

## FAQ

**Is this a drop-in replacement for full YARA?** No. It implements a practical
*subset* of the rule language plus triage extras. Rules using modules like `pe`,
`math`, or `hash`, or advanced features outside the list above, will not parse.

**Does it need network access?** The engine never does. Only `feeds update` /
`feeds get` (without `--offline`) make HTTPS requests, and only when you ask.

**Why did `scan` exit `1` on a "clean-looking" file?** Any match at/above
`--fail-on` (default `low`) trips the gate. Raise the bar with
`--fail-on high` or hide low-severity noise with `--min-severity`.

**Can I use my own rules?** Yes — `scan -r my_rules.yar ...`. Validate them first
with `compile`.

**How do I integrate with GitHub code-scanning?** Emit SARIF and upload it:
`yararun --format sarif scan ./src > results.sarif`.

## Further docs

- [docs/USAGE.md](docs/USAGE.md) — full command and rule-language reference.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — internals and data flow.
- [ROADMAP.md](ROADMAP.md) — direction and planned work.
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to add a rule, test, and demo.
- [SOURCES.md](SOURCES.md) — feed catalog provenance.

## License

See [LICENSE](LICENSE) (LicenseRef-COCL-1.0) and [DISCLAIMER.md](DISCLAIMER.md).
Defensive and authorized use only.
