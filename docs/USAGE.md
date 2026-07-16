# YARARUN — Usage & Rule Reference

This page is the detailed companion to the README: the full CLI surface, the
rule-language grammar the engine understands, and worked examples. Everything
here runs against the pure-stdlib engine — no third-party packages required.

- [Command-line interface](#command-line-interface)
  - [Global flags](#global-flags)
  - [scan](#scan)
  - [info](#info)
  - [rules](#rules)
  - [compile](#compile)
  - [feeds](#feeds)
- [Output formats](#output-formats)
- [Exit codes](#exit-codes)
- [Rule language](#rule-language)
- [Recipes](#recipes)

## Command-line interface

### Global flags

| Flag | Description |
| --- | --- |
| `--version` | Print `yararun <version>` and exit. |
| `--format {table,json,ndjson,csv,sarif}` | Output rendering (default `table`). Applies to `scan`; other subcommands honor `json` where meaningful and otherwise print their table form. |

### scan

```
yararun [--format FMT] scan TARGET [TARGET ...] [options]
```

`TARGET` may be a **file**, a **directory**, or `-` for stdin. Directories are
expanded into files by the walker before scanning.

| Option | Default | Description |
| --- | --- | --- |
| `-r, --rules FILE` | bundled pack | Custom rule file. |
| `--fail-on {critical,high,medium,low}` | `low` | Minimum severity that forces a non-zero exit. |
| `--min-severity {critical,high,medium,low,info}` | *(off)* | Drop matches below this severity from the output (and the exit gate). |
| `-R, --recursive` | on | Descend into sub-directories. |
| `--no-recursive` | — | Scan only the top level of a directory target. |
| `--include GLOB` | *(none)* | Keep only files matching this glob. Repeatable. Matched against both the basename and the path relative to the walked root. |
| `--exclude GLOB` | *(none)* | Skip files matching this glob. Repeatable. **Takes precedence over `--include`.** |
| `--max-bytes N` | `0` | Skip files strictly larger than `N` bytes while walking. `0` disables the cap. Explicit non-directory targets are still size-checked. |
| `--follow-symlinks` | off | Follow symlinked directories while walking. |
| `--stats` | off | Print `scanned N file(s); dirs=… skipped(size=…, excluded=…, unreadable=…)` to stderr. |

Notes:

- A single explicit file target produces a JSON **object**; multiple files (or a
  directory that expands to several) produce a JSON **array**. This preserves
  the historical single-file shape.
- A top-level target that does not exist is a usage error (exit `2`). A file that
  becomes unreadable *during* a walk is skipped with a `warning:` on stderr, so
  one bad file never aborts a directory scan.
- Duplicate paths are de-duplicated; walk order is stable (sorted per directory).

### info

```
yararun [--format {table,json}] info TARGET [TARGET ...]
```

File intelligence only — size, magic-byte file type, Shannon entropy, and
MD5/SHA1/SHA256 — with no rule matching. Useful as a fast triage first look.

### rules

```
yararun [--format {table,json}] rules [-r FILE]
```

List loaded rules with severity, tags, string count, and condition.

### compile

```
yararun [--format {table,json}] compile FILE
```

Parse and validate a rule file; report the rule count (and names in JSON). Exits
`2` on a parse error — a cheap syntax gate for pre-commit or CI.

### feeds

```
yararun feeds list [--domain D]
yararun feeds update ID [ID ...]
yararun feeds get ID [--offline]
yararun feeds snapshot-export PATH.tar.gz
yararun feeds snapshot-import PATH.tar.gz
```

An offline-first threat-intel feed catalog. `list` and any `--offline` read are
pure cache/catalog operations; only `update` and a non-offline `get` make
network requests. Snapshots let you move a warmed cache into an air-gapped
enclave by sneakernet. The cache directory is `COGNIS_FEEDS_CACHE`
(default `~/.cache/cognis-feeds`).

## Output formats

| Format | Shape |
| --- | --- |
| `table` | Human-readable report per target. |
| `json` | Object for one target, array for many. Full `ScanResult.to_dict()`. |
| `ndjson` | One compact, key-sorted JSON object per file, newline-delimited. |
| `csv` | Header + one row per matched string; clean files still emit one summary row. Columns: `target, filetype, size, entropy, sha256, rule, severity, tags, description, string_id, offset, length, preview`. |
| `sarif` | SARIF 2.1.0 log: one `reportingDescriptor` per matched rule, one `result` per match with a byte-offset region and a `security-severity` score. |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No findings at/above the `--fail-on` threshold. |
| `1` | One or more findings at/above the threshold. |
| `2` | Usage or I/O error (bad rules, missing top-level target, etc.). |

## Rule language

A rule has an optional `meta:` block, an optional `strings:` block, and a
`condition:`.

```yara
rule Name : tag1 tag2 {
    meta:
        author      = "..."
        severity    = "high"     // critical|high|medium|low|info
        description = "..."
    strings:
        $id = ...                // see below
    condition:
        <boolean expression>
}
```

### String kinds & modifiers

| Kind | Example | Modifiers |
| --- | --- | --- |
| Text | `$a = "evil.exe"` | `nocase`, `wide`, `ascii`, `fullword`, `xor`, `xor(0x01-0xff)` |
| Hex | `$h = { 4D 5A ?? 50 [2-4] 90 }` | wildcards `??`, jumps `[m-n]`, alternation `( .. \| .. )` |
| Regex | `$r = /https?:\/\/[a-z]+/ nocase` | `nocase`, `fullword` |

The `xor` modifier brute-forces single-byte keys over the literal (real YARA
behavior); `xor(lo-hi)` bounds the key range.

### Condition grammar

- **Booleans:** `and`, `or`, `not`, parentheses.
- **String presence:** `$a` (matched?), with anchors `$a at 0`, `$a in (0..1024)`.
- **Counts:** `#a`, e.g. `#a > 3`.
- **Match length:** `!a` (length of the first match of `$a`).
- **Offsets:** `@a` (first offset), `@a[i]` (i-th match, 1-based).
- **Integer functions:** `uint8/uint16/uint32` and `int8/int16/int32`, plus the
  big-endian `uint16be/uint32be`, e.g. `uint16(0) == 0x5A4D`.
- **Arithmetic/comparison:** `+ - *`, `> < >= <= == !=`.
- **Sets:** `any of them`, `all of them`, `2 of ($s*)`, `all of ($a, $b)`.
- **Special variables:** `filesize` (with `KB`/`MB`/`GB` literals), `entropy`
  (0–8 bits/byte), `filetype` (e.g. `filetype == "pe"`).

A condition that raises during evaluation simply fails to match — a malformed
rule never crashes a scan.

## Recipes

Scan a mail dump for macro/script droppers only, capped at 5 MB per file:

```bash
yararun scan ./mail --include '*.vba' --include '*.js' --include '*.ps1' \
    --max-bytes 5000000 --min-severity high --format csv > droppers.csv
```

Gate a build and upload SARIF to GitHub code-scanning:

```bash
yararun --format sarif scan --fail-on high ./dist > results.sarif
# then: github/codeql-action/upload-sarif with sarif_file: results.sarif
```

Stream findings from a large tree into a log pipeline:

```bash
yararun --format ndjson scan ./corpus | your-log-shipper
```

Triage a single blob from stdin:

```bash
curl -s https://example/internal/artifact | yararun --format json scan -
```
