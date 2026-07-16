# YARARUN — Architecture

> A dependency-free YARA-subset rule engine + triage toolkit.

## Data flow

```
paths ─▶ scanfs.iter_targets ─▶ core.scan ─▶ ScanResult ─▶ renderers ─▶ output
 file/dir/-      walk + glob        │  entropy/type/hash          ├─ table
                                    │  + rule matching            ├─ json / ndjson / csv
                              parse_rules ─▶ StringDef            └─ to_sarif (SARIF 2.1.0)
                                            _Cond evaluator
                                                 │
                                          MCP tool (agents) · cognis-connect emit
```

1. **collect** — `scanfs.iter_targets` normalizes the target list (files,
   directories, `-`/stdin) into a de-duplicated stream of file paths, applying
   recursion, include/exclude globs, and a per-file size cap.
2. **compile** — `core.parse_rules` turns rule source into `Rule` objects whose
   strings are compiled to `StringDef` matchers (text/hex/regex, with the `xor`
   brute-forcer for the `xor` modifier).
3. **scan** — `core.scan` computes file intelligence (entropy, magic-byte type,
   hashes) once, then evaluates every rule's condition against the string hits
   via the `_Cond` recursive-descent evaluator.
4. **score** — matches are tagged with severity and sorted
   `critical → info`; `ScanResult` aggregates counts and `max_severity`.
5. **render** — `ScanResult` is emitted as a table, JSON, NDJSON, CSV, or a
   SARIF 2.1.0 log.

## Modules

| Module | Responsibility |
| --- | --- |
| `yararun/core.py` | Rule parser, string compilers, condition evaluator, file-intelligence, `ScanResult`, severity helpers, and the `to_sarif` / `to_ndjson` / `to_csv` exporters. |
| `yararun/scanfs.py` | Filesystem target expansion: recursion, `fnmatch` globs, size ceiling, symlink policy, and `WalkStats` counters. |
| `yararun/cli.py` | Argument parsing, subcommands (`scan`/`info`/`rules`/`compile`/`feeds`), and renderers. |
| `yararun/datafeeds.py` | Edge/air-gap threat-intel feed catalog, disk cache, and snapshot import/export. |
| `yararun/mcp_server.py` | MCP stdio server exposing `scan` as an agent tool. |
| `yararun/connect.py` | Native `cognis-connect` emit (STIX/TAXII/MISP/Sigma/SIEM/chat). |

## Key types

- `Rule` — name, tags, `meta`, `{ident: StringDef}`, and a condition string.
- `StringDef` — one compiled `$id = ...` matcher; `find()` returns
  `(offset, length)` hits (with a dedicated XOR key-sweep path).
- `RuleMatch` / `StringMatch` — a fired rule and its located strings.
- `ScanResult` — per-target report (size, entropy, type, hashes, matches) with
  `counts()`, `max_severity`, `filtered(min_severity)`, and `to_dict()`.

## Design invariants

- **Standard library only** in the core/CLI path — nothing to install on an edge
  or air-gapped host.
- **Fail safe** — a malformed condition fails to match rather than raising.
- **Passive by default** — nothing touches the network except explicit
  `feeds update` / non-offline `feeds get`.
- **Additive evolution** — new formats, flags, and helpers are layered on;
  existing entry points and output shapes are preserved.

## Extending

Add a rule to `DEFAULT_RULES` (or ship a rule file), a test in `tests/`, and a
`demos/NN-*/SCENARIO.md`. New exporters live beside `to_sarif` in `core.py`; new
CLI surface is wired in `cli.py`. See [CONTRIBUTING.md](../CONTRIBUTING.md).
