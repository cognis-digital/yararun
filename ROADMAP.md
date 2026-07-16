# YARARUN — Roadmap

`yararun` is a dependency-free YARA-subset rule engine and triage toolkit. This
roadmap describes direction, not commitments — priorities are shaped by issues
and PRs. Nothing here removes an existing entry point or output shape; the
project evolves additively.

## Guiding principles

- **Stdlib-only core.** The engine and CLI must keep running on a bare Python
  install so they drop onto edge, air-gapped, and IR hosts with zero friction.
- **Familiar rule language.** Grow toward YARA compatibility where it is cheap
  and high-value; be explicit about the supported subset.
- **Passive & safe by default.** No surprise network egress; malformed rules
  fail closed.
- **CI-native.** First-class machine-readable output (JSON/NDJSON/CSV/SARIF) and
  meaningful exit codes.

## Now (shipped)

- YARA-subset engine: text/hex/regex strings, `xor` modifier, counts, offsets,
  match length, `uint*`/`int*` functions, arithmetic/comparison, and
  `N of (...)` set conditions.
- File-intelligence module (entropy, magic-byte typing, MD5/SHA1/SHA256) usable
  as `entropy`/`filetype` condition variables.
- Bundled triage rule pack (PE/ELF/Mach-O, packers, droppers, ransom notes,
  cryptominers, reverse shells, credential theft, persistence, EICAR).
- **Directory & recursive scanning** with include/exclude globs, size cap, and
  a walk-stats summary.
- **Five output formats** — table, JSON, NDJSON, CSV, SARIF 2.1.0.
- **Severity controls** — `--fail-on` exit gate and `--min-severity` display
  filter.
- Edge/air-gap threat-intel feed catalog with offline cache and sneakernet
  snapshots.
- Integrations: MCP server and native `cognis-connect` emit.
- CI: pytest matrix (3.10–3.13) + a ruff lint gate.

## Next (near-term)

- **Rule-language depth:** `filesize`/offset ranges in more positions, string
  set arithmetic (`for any of ...`), and clearer parser diagnostics with line
  numbers on `compile`.
- **Performance:** multi-pattern pre-filtering (single scan pass over the buffer)
  and optional parallel directory scanning.
- **Reporting:** a `--summary` roll-up across a whole directory scan and a
  JUnit-XML exporter for pipeline test reports.
- **Rule packs:** namespaced/loadable community packs and per-rule enable/disable.
- **Feeds:** wire cached feed IOCs into generated rules (URL/hash/domain
  blocklists) for enrichment-driven detection.

## Mid-term

- **Compatibility layer:** parse a broader slice of real-world YARA rules and
  clearly report unsupported constructs instead of silently ignoring them.
- **Plugin API:** register custom analyzers/detectors and output formatters.
- **Streaming scans:** chunked scanning of very large files with bounded memory.

## Later

- PyPI release of the standalone distribution.
- Signed rule packs and provenance metadata.
- Commercial support / Pro tier for managed rule feeds
  (licensing@cognis.digital).

## Non-goals

- Becoming a full re-implementation of the native YARA C engine.
- Any offensive tooling. `yararun` is for defensive, authorized inspection only.

Open an issue or PR to shape priorities — see [CONTRIBUTING.md](CONTRIBUTING.md).
