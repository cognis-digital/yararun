"""YARARUN — a stdlib YARA-subset rule engine + malware triage rule pack.

Compile and run a working subset of YARA rules (text/hex/regex strings,
`xor` modifier, `#count`, `!len`, `@offset[i]`, `at`/`in` anchors,
`uint8/16/32(...)` integer functions, arithmetic/comparison, and
`and`/`or`/`not` + `N of (...)` conditions) against any file or blob.

Also exposes a file-intelligence module the way VirusTotal does: Shannon
entropy, magic/file-type sniffing, and MD5/SHA1/SHA256 hashes (also usable as
the `entropy` and `filetype` condition variables).

Ships a real bundled triage rule pack (PE/ELF/Mach-O, UPX, high-entropy blobs,
XOR-encoded MZ stubs, PowerShell/JS/VBScript droppers, base64 PE stubs, ransom
notes, cryptominers, reverse shells, credential theft, persistence, EICAR).

In the spirit of VirusTotal/YARA. Defensive / forensic use only.
"""
from .core import (
    TOOL_NAME,
    TOOL_VERSION,
    SEVERITY_ORDER,
    DEFAULT_RULES,
    Rule,
    StringDef,
    StringMatch,
    RuleMatch,
    ScanResult,
    parse_rules,
    load_rules,
    match_rule,
    scan,
    shannon_entropy,
    sniff_filetype,
    file_hashes,
    to_sarif,
)

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "SEVERITY_ORDER",
    "DEFAULT_RULES",
    "Rule",
    "StringDef",
    "StringMatch",
    "RuleMatch",
    "ScanResult",
    "parse_rules",
    "load_rules",
    "match_rule",
    "scan",
    "shannon_entropy",
    "sniff_filetype",
    "file_hashes",
    "to_sarif",
]
