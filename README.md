<a name="top"></a>
<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:6b46c1,100:2b6cb0&height=120&section=header&text=YARARUN&fontSize=48&fontColor=ffffff&fontAlignY=58" width="100%" alt="YARARUN"/>

# YARARUN

### Run simple YARA-style string/regex rules over a directory

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&duration=3500&pause=1000&color=6B46C1&center=true&vCenter=true&width=720&lines=Run+simple+YARAstyle+stringregex+rules+over+a+directory;Self-hostable+%C2%B7+MCP-native+%C2%B7+CI-ready+%C2%B7+polyglot" width="720"/>

[![PyPI](https://img.shields.io/pypi/v/cognis-yararun.svg?color=6b46c1)](https://pypi.org/project/cognis-yararun/) [![CI](https://github.com/cognis-digital/yararun/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/yararun/actions) [![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE) [![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

*Part of the Cognis Neural Suite.*

</div>

```bash
pip install cognis-yararun
yararun scan .            # → prioritized findings in seconds
```


<!-- cognis:example:start -->
## 🔎 Example output

Real, reproducible output from the tool — runs offline:

```console
$ yararun-emit --version
yararun 2.0.0
```

```console
$ yararun-emit --help
usage: yararun [-h] [--version] [--format {table,json,sarif}]
               {scan,info,rules,compile,feeds} ...

YARA-subset rule engine for malware/IOC triage on files you are authorized to
inspect (defensive use only).

positional arguments:
  {scan,info,rules,compile,feeds}
    scan                scan file(s) against rules
    info                file intelligence: entropy, type, hashes
    rules               list loaded rules
    compile             validate/compile a rule file
    feeds               edge/air-gap threat-intel feed catalog (keyless,
                        offline-capable)

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --format {table,json,sarif}
                        output format (sarif = SARIF 2.1.0 for code-scanning)
```

```console
$ yararun-emit rules
YARARUN rules (17 loaded)
================================================================
[INFO    ] PE_Executable :pe format
           Windows PE / DOS MZ executable header
           strings=2  condition: uint16(0) == 0x5A4D and $pe
[INFO    ] ELF_Executable :elf format
           ELF binary (Linux executable / shared object)
           strings=1  condition: $elf at 0
[INFO    ] MachO_Executable :macho format
           Mach-O binary (macOS executable)
           strings=4  condition: any of them
[MEDIUM  ] High_Entropy_Blob :packer evasion
           Very high Shannon entropy: likely packed/encrypted payload
           strings=0  condition: entropy >= 7.5 and filesize > 1KB
[MEDIUM  ] UPX_Packed :packer evasion
           UPX-packed executable (common malware packer)
           strings=3  condition: 2 of them
[HIGH    ] XOR_Encoded_MZ :evasion encoded
           Single-byte XOR-obfuscated MZ/PE executable stub
           strings=2  condition: $mz and $stub
[HIGH    ] Embedded_PowerShell :script dropper
           Embedded/obfuscated PowerShell loader patterns
           strings=9  condition: $a and 2 of ($b, $c, $d, $e, $f, $g, $h, $i)
[HIGH    ] JS_Eval_Dropper :script obfuscation
           JavaScript eval/unescape obfuscation dropper
           strings=5  condition: $eval and 2 of ($unescape, $fromcc, $atob, $doc)
[HIGH    ] VBScript_Macro :office macro dropper
           VBA/VBScript auto-exec macro with shell execution
           strings=6  condition: any of ($auto1, $auto2, $auto3) and $create and 1 of ($shell, $run)
[HIGH    ] Base64_PE_Stub :encoded payload
           Base64-encoded PE header (TVqQ / TVpQ) embedded in text
           strings=3  condition: any of them
[MEDIUM  ] Suspicious_URL :network ioc
           Hardcoded HTTP(S) URL or Tor .onion C2 endpoint
           strings=3  condition: $onion or $ip or #url > 2
[CRITICAL] Ransom_Note :ransomware
           Ransomware ransom-note language and payment demand
           strings=6  condition: $r1 and 2 of ($r2, $r3, $r4, $r5, $r6)
[HIGH    ] Cryptominer_Config :miner cryptojacking
           Crypto-mining pool / stratum configuration strings
           strings=6  condition: $s1 or 2 of ($s2, $s3, $s4, $s5, $s6)
[CRITICAL] Shell_Reverse_Connect :backdoor network
           Reverse shell / netcat / bind-shell command patterns
           strings=6  condition: ($nc1 or $nc2) or ($bash and $dev
```

> Blocks above are real `yararun` output — reproduce them from a clone.

<!-- cognis:example:end -->

## Usage — step by step

1. **Install** the CLI (console script `yararun`):
   ```bash
   pip install cognis-yararun
   ```
2. **List the bundled triage rule pack** (or your own with `-r`):
   ```bash
   yararun rules
   yararun rules -r myrules.yar
   ```
3. **Scan one or more files** against the rules (`-` reads stdin); add a custom rule file with `-r`:
   ```bash
   yararun scan suspicious.bin
   yararun scan ./samples/* -r myrules.yar
   ```
4. **Read the result** as JSON, and validate a rule file before shipping it:
   ```bash
   yararun scan suspicious.bin --format json
   yararun compile myrules.yar
   ```
5. **Automate in CI** — `scan` exits non-zero when actionable (non-info) matches are found:
   ```yaml
   - run: pip install cognis-yararun
   - run: yararun scan artifact.bin --format json
   ```

## Contents

- [Why yararun?](#why) · [Features](#features) · [Quick start](#quick-start) · [Example](#example) · [Demos](#demos) · [Architecture](#architecture) · [Ports](#ports) · [Edge / air-gap feeds](#feeds) · [Scope & safety](#scope) · [AI stack](#ai-stack) · [How it compares](#how-it-compares) · [Integrations](#integrations) · [Install anywhere](#install-anywhere) · [Related](#related) · [Contributing](#contributing)

<a name="why"></a>
## Why yararun?

lightweight hunting

`yararun` is single-purpose, scriptable, and self-hostable: point it at a target, get prioritized results in the format your workflow already speaks (table · JSON · SARIF), gate CI on it, and let agents drive it over MCP.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="features"></a>
## Features

- ✅ YARA-subset rule engine — text/hex/regex strings, `nocase`/`wide`/`fullword`/**`xor`** modifiers, `#count`, `!len`, `@offset[i]`, `at`/`in` anchors, `uint8/16/32(...)` integer functions, arithmetic, and `and`/`or`/`not` + `N of (...)` conditions
- ✅ File-intelligence module — Shannon **entropy**, magic-byte **file-type** sniff, and MD5/SHA1/SHA256 hashes (also usable as the `entropy` / `filetype` condition variables) via `yararun info`
- ✅ Real bundled triage pack — PE/ELF/Mach-O, UPX, high-entropy blobs, XOR-encoded MZ stubs, PowerShell/JS/VBScript droppers, base64 PE stubs, ransom notes, cryptominers, reverse shells, credential theft, persistence, EICAR
- ✅ **Table · JSON · SARIF 2.1.0** output + a `--fail-on <severity>` CI gate
- ✅ Ten worked, verified demos under [`demos/`](demos/) (see below)
- ✅ **Edge / air-gap IOC feeds** — a keyless, offline-first threat-intel catalog (OSV, CISA KEV, EPSS, abuse.ch Feodo/ThreatFox/URLhaus, MITRE ATT&CK STIX) via `yararun feeds`, cacheable to disk and sneakernet-able into a disconnected enclave
- ✅ Runs on Linux/macOS/Windows · Docker · devcontainer
- ✅ Ports in Python, JavaScript, Go, Rust, **and POSIX shell** ([`ports/`](ports/)) — each mirrors the `info`/`scan` surface, carries a smoke test, and is built/tested in CI

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="quick-start"></a>
## Quick start

```bash
pip install cognis-yararun
yararun --version
yararun scan suspicious.bin                  # scan a file against the triage pack
yararun info suspicious.bin                  # entropy / file-type / hashes only
yararun scan suspicious.bin --format json    # machine-readable
yararun scan suspicious.bin --format sarif   # SARIF 2.1.0 for code-scanning
yararun scan ./artifacts/* --fail-on high    # CI gate (non-zero at/above high)
```

> `yararun` reads files and reports matches — it never executes, modifies, or
> transmits anything. Use it only on artifacts you are authorized to inspect.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="example"></a>
## Example

Real output from a multi-indicator dropper sample
([`demos/02-deep`](demos/02-deep)) — a PowerShell loader hidden in a high-entropy,
UPX-marked, XOR-obfuscated blob with a hardcoded C2 URL:

```text
$ yararun scan demos/02-deep/suspicious_sample.bin
YARARUN scan: demos/02-deep/suspicious_sample.bin
================================================================
Size           : 2424 bytes
File type      : pe
Entropy        : 7.8627 bits/byte  (HIGH - packed/encrypted)
SHA256         : f9913baa5f33aabee4caaad98c0225a1f77f04e1a19eb4ca1762c7389a6040aa
Matches        : 6
By severity    : high=2, medium=3, info=1
Max severity   : HIGH

[HIGH    ] XOR_Encoded_MZ :evasion encoded
           Single-byte XOR-obfuscated MZ/PE executable stub
[HIGH    ] Embedded_PowerShell :script dropper
           Embedded/obfuscated PowerShell loader patterns
             $a @ 0x5b (+10)  'powershell -nop -w hidde'
             $b @ 0x75 (+4)   '-enc IEX (New-Object Net'
[MEDIUM  ] High_Entropy_Blob :packer evasion
[MEDIUM  ] UPX_Packed :packer evasion
[MEDIUM  ] Suspicious_URL :network ioc
[INFO    ] PE_Executable :pe format
```

The same scan as machine-readable JSON (truncated):

```jsonc
$ yararun scan demos/02-deep/suspicious_sample.bin --format json
{
  "target": "demos/02-deep/suspicious_sample.bin",
  "size": 2424,
  "entropy": 7.8627,
  "filetype": "pe",
  "hashes": { "sha256": "f9913baa…40aa", "md5": "…", "sha1": "…" },
  "match_count": 6,
  "max_severity": "high",
  "counts": { "critical": 0, "high": 2, "medium": 3, "low": 0, "info": 1 },
  "matches": [ { "rule": "XOR_Encoded_MZ", "severity": "high",
                 "tags": ["evasion", "encoded"], "strings": [ … ] }, … ]
}
```

`scan` exits **non-zero** whenever an actionable (non-`info`) match is found, so
it drops straight into a CI gate (`--fail-on <severity>` raises the bar).

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="demos"></a>
## Worked demos

Every folder under [`demos/`](demos/) is a self-contained, **verified**
scenario: a realistic input file in the tool's real input format plus a
`SCENARIO.md` that explains where the data came from, the exact command to run,
the expected finding, and how to act on it. All inputs are sanitized — reserved
example domains/IPs (`.invalid`, RFC 2606/5737), placeholder wallets, and AWS's
own published example key — so nothing here is a live indicator.

| Demo | Scenario | Fires |
|---|---|---|
| [`01-basic`](demos/01-basic) | First hunt over a quarantined folder | custom pack |
| [`02-clean`](demos/02-clean) | A clean file → zero findings, exit 0 | — |
| [`02-deep`](demos/02-deep) | Multi-indicator dropper (xor + entropy + uint) | 5 rules, **critical** |
| [`03-mixed`](demos/03-mixed) | Mixed clean/suspicious tree | varies |
| [`04-cryptominer`](demos/04-cryptominer) | XMRig coin-miner config on a server | `Cryptominer_Config` |
| [`05-ransom-note`](demos/05-ransom-note) | Ransom note on a file share | `Ransom_Note` (**critical**) |
| [`06-reverse-shell`](demos/06-reverse-shell) | Reverse shell in a cron job | `Shell_Reverse_Connect` (**critical**) |
| [`07-office-macro`](demos/07-office-macro) | Auto-exec VBA downloader | `VBScript_Macro` + PowerShell |
| [`08-eicar-ci-gate`](demos/08-eicar-ci-gate) | EICAR + `--fail-on` + SARIF in CI | `EICAR_Test_File` |
| [`09-credential-stealer`](demos/09-credential-stealer) | Infostealer `strings` dump | `Credential_Theft` |
| [`10-custom-sarif`](demos/10-custom-sarif) | Custom secret-scan ruleset → SARIF | AWS key / api-secret / debug flag |

A couple of demos generate their artifact locally (`build_sample.py`,
`build_eicar.py`) so on-access antivirus can't strip a committed copy.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="architecture"></a>
## Architecture

```mermaid
flowchart LR
  IN[binary / sample] --> P[yararun<br/>scan + match]
  P --> OUT[detections]
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="ports"></a>
## Polyglot ports

The file-intelligence + triage-scan core is ported across five languages so you
can drop `yararun` into any stack or ship a single static binary. Every port
mirrors the reference CLI's two read-only commands and emits the same JSON
shape; `scan` exits non-zero when a rule fires (CI-gate parity). Each carries a
smoke test, and all are built/tested on every push by the
[`ports` CI workflow](.github/workflows/ports.yml).

| Language | Path | Run | Test |
|---|---|---|---|
| Python (reference) | [`yararun/`](yararun) | `yararun scan FILE` | `pytest` |
| JavaScript / Node | [`ports/javascript/`](ports/javascript) | `node ports/javascript/index.js scan FILE` | `node --test` |
| Go | [`ports/go/`](ports/go) | `cd ports/go && go run . scan FILE` | `go test ./...` |
| Rust | [`ports/rust/`](ports/rust) | `cd ports/rust && cargo run -- scan FILE` | `cargo test` |
| POSIX shell | [`ports/shell/`](ports/shell) | `sh ports/shell/yararun.sh scan FILE` | `sh ports/shell/test.sh` |

The ports implement the literal-string subset of the bundled triage pack; the
Python reference is the full engine (hex/regex/`xor` strings, counts/offsets,
`uintN()` functions, `N of (...)` conditions, SARIF). See [`ports/README.md`](ports/README.md).

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="ai-stack"></a>
## Use it from any AI stack

`yararun` is interoperable with every popular way of using AI:

- **MCP server** — `yararun mcp` (Claude Desktop, Cursor, Cognis.Studio, [uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet))
- **OpenAI-compatible / JSON** — pipe `yararun scan . --format json` into any agent or LLM
- **LangChain · CrewAI · AutoGen · LlamaIndex** — wrap the CLI/JSON as a tool in one line
- **CI / scripts** — exit codes + SARIF for non-AI pipelines

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="how-it-compares"></a>
## How it compares

| | **Cognis yararun** | YARA |
|---|:---:|:---:|
| Self-hostable, no account | ✅ | varies |
| Single command, zero config | ✅ | ⚠️ |
| JSON + SARIF for CI | ✅ | varies |
| MCP-native (AI agents) | ✅ | ❌ |
| Polyglot ports (JS/Go/Rust) | ✅ | ❌ |
| Open license | ✅ COCL | varies |

*Built in the spirit of **YARA**, re-framed the Cognis way. Missing a credit? Open a PR.*

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="feeds"></a>
## Edge / air-gap IOC feeds

`yararun` is a passive scanner, but triage often needs to cross-reference what
you find against current threat intelligence. The bundled **keyless feed
catalog** ([`yararun/data_feeds_2026.json`](yararun/data_feeds_2026.json), 35
feeds) wires real, mostly-keyless sources — **OSV.dev**, **CISA KEV**, **FIRST
EPSS**, abuse.ch **Feodo Tracker / ThreatFox / URLhaus / SSLBL**, **MITRE
ATT&CK** STIX, **NIST 800-53 OSCAL**, **OFAC SDN** — fetched over HTTPS, cached
to disk, and **re-served offline** so the tool keeps working on disconnected /
edge / air-gapped gear.

```bash
yararun feeds list                       # browse the catalog (offline, no network)
yararun feeds list --domain threat-intel # filter by domain
yararun feeds update feodo-c2 threatfox  # the ONLY command that egresses (explicit)
yararun feeds get feodo-c2 --offline     # serve from cache only — never touches the net
```

**Air-gap workflow** — refresh on a connected host, sneakernet the cache, import
on the isolated enclave:

```bash
# connected host
yararun feeds update osv cisa-kev feodo-c2 threatfox
yararun feeds snapshot-export feeds.tar.gz
# → copy feeds.tar.gz across the gap →
# air-gapped enclave
yararun feeds snapshot-import feeds.tar.gz
yararun feeds get cisa-kev --offline
```

The cache location is `COGNIS_FEEDS_CACHE` (default `~/.cache/cognis-feeds`).
Everything except `feeds update`/`get` (without `--offline`) is a pure
local/catalog read — **no network egress unless you explicitly ask for it**, and
no API keys are required for the core feeds. Only real, attributable sources are
catalogued; nothing here is fabricated intel.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="scope"></a>
## Scope, authorization & safety

`yararun` is a **defensive, passive, offline** tool:

- It **reads** files/blobs and reports matches. It never executes, modifies,
  patches, quarantines, or transmits the artifacts you point it at.
- There is **no active scanning** and no network probing of third-party hosts.
  The only outbound traffic the tool can make is an *explicit* `yararun feeds
  update`/`get` to the catalogued, public threat-intel sources — and even that
  is fully optional and air-gap-bypassable.
- Use it only on artifacts you are **authorized to inspect**. The bundled rules
  and all demo inputs use sanitized, reserved example indicators (RFC 2606/5737
  domains/IPs, placeholder wallets, AWS's own published example key, the EICAR
  test string) — nothing shipped here is a live indicator.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="integrations"></a>
## Integrations

Pipes into your stack: **SARIF** for code-scanning, **JSON** for anything, an **MCP server** (`yararun mcp`) for AI agents, and a webhook forwarder for SIEM/Slack/Jira. See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="install-anywhere"></a>
## Install — every way, every platform

```bash
pip install "git+https://github.com/cognis-digital/yararun.git"    # pip (works today)
pipx install "git+https://github.com/cognis-digital/yararun.git"   # isolated CLI
uv tool install "git+https://github.com/cognis-digital/yararun.git" # uv
pip install cognis-yararun                                          # PyPI (when published)
docker run --rm ghcr.io/cognis-digital/yararun:latest --help        # Docker
brew install cognis-digital/tap/yararun                             # Homebrew tap
curl -fsSL https://raw.githubusercontent.com/cognis-digital/yararun/main/install.sh | sh
```

| Linux | macOS | Windows | Docker | Cloud |
|---|---|---|---|---|
| `scripts/setup-linux.sh` | `scripts/setup-macos.sh` | `scripts/setup-windows.ps1` | `docker run ghcr.io/cognis-digital/yararun` | [DEPLOY.md](docs/DEPLOY.md) (AWS/Azure/GCP/k8s) |

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="related"></a>
## Related Cognis tools

- [`portfan`](https://github.com/cognis-digital/portfan) — Summarize and diff nmap XML into prioritized, attackable findings
- [`subhunt`](https://github.com/cognis-digital/subhunt) — Aggregate & dedupe subdomain enumeration from multiple sources
- [`dirsight`](https://github.com/cognis-digital/dirsight) — Analyze web content-discovery output (ffuf/gobuster) into ranked endpoints
- [`jwtinspect`](https://github.com/cognis-digital/jwtinspect) — Decode JWTs and lint for alg=none, weak secrets, and missing claims
- [`corsaudit`](https://github.com/cognis-digital/corsaudit) — Detect permissive/misconfigured CORS from headers or a config
- [`headerscan`](https://github.com/cognis-digital/headerscan) — Grade HTTP security headers (CSP/HSTS/XFO) A-F from a response dump

**Explore the suite →** [🗂️ all 170+ tools](https://github.com/cognis-digital/cognis-neural-suite) · [⭐ awesome-cognis](https://github.com/cognis-digital/awesome-cognis) · [🔗 cognis-sources](https://github.com/cognis-digital/cognis-sources) · [🤖 uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet) · [🧠 engram](https://github.com/cognis-digital/engram)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="contributing"></a>
## Contributing

PRs, new rules, and demo scenarios are welcome under the collaboration-pull model — see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

> ### ⭐ If `yararun` saved you time, **star it** — it genuinely helps others find it.

## Interoperability

`{}` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

---

<div align="center"><sub><b><a href="https://cognis.digital">Cognis Digital</a></b> · one of 170+ tools in the <a href="https://github.com/cognis-digital/cognis-neural-suite">Cognis Neural Suite</a> · <i>Making Tomorrow Better Today</i></sub></div>
