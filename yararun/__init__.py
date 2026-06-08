"""YARARUN — a stdlib YARA-subset rule engine + malware triage rule pack.

Compile and run a working subset of YARA rules (text/hex/regex strings,
`#count`, `at`/`in` anchors, and `and`/`or`/`not` + `N of (...)` conditions)
against any file or blob. Ships a real bundled triage rule pack (PE/ELF/Mach-O,
UPX, PowerShell/JS/VBScript droppers, base64 PE stubs, ransom notes,
cryptominers, reverse shells, credential theft, EICAR).

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
]
