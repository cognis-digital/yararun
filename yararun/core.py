"""YARARUN core — Run simple YARA-style string/regex rules over a directory."""
from __future__ import annotations
import json, time
from dataclasses import dataclass, field, asdict
from pathlib import Path

TOOL_NAME = "YARARUN"
TOOL_VERSION = "0.1.0"

SEVERITIES = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Minimal, dependency-free finding model so this tool runs standalone.
@dataclass
class Finding:
    id: str
    severity: str
    title: str
    where: str = ""
    detail: str = ""
    remediation: str = ""

@dataclass
class ScanResult:
    tool: str = TOOL_NAME
    version: str = TOOL_VERSION
    target: str = ""
    findings: list = field(default_factory=list)
    elapsed_ms: int = 0
    @property
    def score(self) -> int:
        return sum(SEVERITIES.get(f.severity, 0) for f in self.findings)

# Tool-specific heuristics live here. Start with a small, honest rule set and
# grow it via PRs (see CONTRIBUTING.md). Each rule = (id, severity, needle, title, fix).
RULES = [
    ("YAR-001", "high", "TODO", "Unresolved TODO / placeholder left in input", "Resolve before shipping."),
    ("YAR-002", "medium", "FIXME", "FIXME marker found", "Address the flagged issue."),
    ("YAR-003", "low", "XXX", "XXX marker found", "Review the flagged section."),
]

def scan(target: str, **opts) -> ScanResult:
    t0 = time.time()
    res = ScanResult(target=str(target))
    p = Path(target)
    files = [p] if p.is_file() else (sorted(p.rglob("*")) if p.exists() else [])
    for fp in files:
        if not fp.is_file():
            continue
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for rid, sev, needle, title, fix in RULES:
            if needle in text:
                res.findings.append(Finding(rid, sev, title, where=str(fp), remediation=fix))
    res.elapsed_ms = int((time.time() - t0) * 1000)
    return res

def to_json(res: ScanResult) -> str:
    d = asdict(res); d["score"] = res.score
    return json.dumps(d, indent=2)
