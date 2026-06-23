# Ports of yararun

The same file-intelligence + triage-scan core, ported across languages so you
can drop yararun into any stack or ship a single static binary. Every port
mirrors the reference Python CLI's two read-only commands and emits the same
JSON shape, and `scan` exits **non-zero when any rule fires** (CI-gate parity):

```
<port> info <file>   -> entropy / filetype / hashes
<port> scan <file>   -> info + bundled triage string rules that fired
```

The ports implement the **literal-string subset** of the bundled triage pack
(PowerShell/JS droppers, ransom notes, cryptominers, reverse shells, credential
theft, UPX, EICAR). The Python reference is the full engine (hex/regex/`xor`
strings, `#count`/`!len`/`@offset`, `at`/`in` anchors, `uintN()` integer
functions, `N of (...)` conditions, SARIF export). All ports are **passive and
offline** — they only read the bytes you hand them; they never execute, modify,
or transmit anything.

| Language | Path | Run | Test |
|---|---|---|---|
| Python (reference) | [`../yararun/`](../yararun) | `yararun scan FILE` | `pytest` |
| JavaScript / Node | [`javascript/`](javascript) | `node ports/javascript/index.js scan FILE` | `node --test` (Node ≥ 18) |
| Go | [`go/`](go) | `cd ports/go && go run . scan FILE` | `go test ./...` |
| Rust | [`rust/`](rust) | `cd ports/rust && cargo run -- scan FILE` | `cargo test` |
| POSIX shell | [`shell/`](shell) | `sh ports/shell/yararun.sh scan FILE` | `sh ports/shell/test.sh` |

Each port carries a smoke test (asserting entropy bounds, magic-byte file-type
detection, and the ransom/PowerShell/EICAR/clean detections). They are built
and tested on every push by the [`ports` CI workflow](../.github/workflows/ports.yml),
so they are real and verifiable — not vaporware — even where the local
toolchain isn't installed.

Contributions of additional ports (Ruby, C#, Bun, Deno, WASM) are welcome — see [../CONTRIBUTING.md](../CONTRIBUTING.md).
