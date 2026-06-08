"""Core scanning engine for YARARUN.

A compact, dependency-free implementation of a YARA-like rule format. Rules
declare named strings (text, regex, or hex) and a boolean condition over the
matched-string identifiers. The engine walks a directory tree, reads files as
bytes, evaluates each rule, and reports per-string matches with offsets.

Supported rule syntax (a practical subset of YARA):

    rule SuspiciousScript {
        meta:
            description = "example"
            severity = "high"
        strings:
            $a = "powershell" nocase
            $b = /eval\\s*\\(/
            $c = { 4d 5a 90 00 }        // hex bytes
        condition:
            $a and ($b or $c)
    }

Condition grammar supports: identifiers ($name), 'any of them',
'all of them', 'N of them', parentheses, and the operators and/or/not.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

MAX_FILE_BYTES = 64 * 1024 * 1024  # 64 MiB safety cap per file


@dataclass
class StringDef:
    """A single named pattern within a rule."""

    name: str
    kind: str  # 'text' | 'regex' | 'hex'
    raw: str
    nocase: bool = False
    _compiled: Optional[re.Pattern] = field(default=None, repr=False)

    def compile(self) -> re.Pattern:
        if self._compiled is not None:
            return self._compiled
        flags = re.DOTALL
        if self.kind == "text":
            pat = re.escape(self.raw.encode())
            if self.nocase:
                flags |= re.IGNORECASE
        elif self.kind == "regex":
            pat = self.raw.encode()
            if self.nocase:
                flags |= re.IGNORECASE
        elif self.kind == "hex":
            pat = _hex_to_regex(self.raw)
        else:  # pragma: no cover - guarded by parser
            raise ValueError(f"unknown string kind: {self.kind}")
        self._compiled = re.compile(pat, flags)
        return self._compiled


@dataclass
class Rule:
    name: str
    strings: List[StringDef]
    condition: str
    meta: Dict[str, str] = field(default_factory=dict)

    def string_names(self) -> List[str]:
        return [s.name for s in self.strings]


@dataclass
class Match:
    rule: str
    string: str
    offset: int
    matched: str  # decoded preview of matched bytes


@dataclass
class FileResult:
    path: str
    matches: List[Match] = field(default_factory=list)

    @property
    def rules_hit(self) -> List[str]:
        seen: List[str] = []
        for m in self.matches:
            if m.rule not in seen:
                seen.append(m.rule)
        return seen


@dataclass
class ScanReport:
    files_scanned: int = 0
    files_skipped: int = 0
    results: List[FileResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def total_matches(self) -> int:
        return sum(len(r.matches) for r in self.results)

    def to_dict(self) -> dict:
        return {
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "total_matches": self.total_matches,
            "errors": self.errors,
            "results": [
                {
                    "path": r.path,
                    "rules": r.rules_hit,
                    "matches": [
                        {
                            "rule": m.rule,
                            "string": m.string,
                            "offset": m.offset,
                            "matched": m.matched,
                        }
                        for m in r.matches
                    ],
                }
                for r in self.results
            ],
        }


# --------------------------------------------------------------------------- #
# Hex pattern translation
# --------------------------------------------------------------------------- #
def _hex_to_regex(raw: str) -> bytes:
    """Translate a YARA hex string body into a byte regex.

    Supports two-digit hex bytes and the '??' wildcard nibble pair. Whitespace
    is ignored. Example: '4d 5a ?? 00' -> b'\\x4d\\x5a.\\x00'.
    """
    tokens = raw.replace("\n", " ").split()
    out: List[bytes] = []
    for tok in tokens:
        if tok == "??":
            out.append(b".")
            continue
        if len(tok) != 2 or not all(c in "0123456789abcdefABCDEF" for c in tok):
            raise ValueError(f"invalid hex token: {tok!r}")
        out.append(re.escape(bytes([int(tok, 16)])))
    if not out:
        raise ValueError("empty hex string")
    return b"".join(out)


# --------------------------------------------------------------------------- #
# Rule parsing
# --------------------------------------------------------------------------- #
_RULE_RE = re.compile(r"rule\s+([A-Za-z_]\w*)\s*\{(.*?)\}", re.DOTALL)
_STRING_RE = re.compile(r"\$([A-Za-z_]\w*)\s*=\s*(.+)")


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"//[^\n]*", "", text)
    return text


def _parse_string_value(raw: str) -> Tuple[str, str, bool]:
    """Return (kind, value, nocase) from a strings: right-hand side."""
    raw = raw.strip()
    nocase = False
    if raw.startswith("{") and "}" in raw:
        body = raw[1:raw.index("}")]
        return "hex", body.strip(), False
    if raw.startswith("/"):
        end = raw.rfind("/")
        if end <= 0:
            raise ValueError(f"unterminated regex: {raw!r}")
        body = raw[1:end]
        trailing = raw[end + 1:]
        if "i" in trailing or "nocase" in trailing:
            nocase = True
        return "regex", body, nocase
    if raw.startswith('"'):
        end = raw.index('"', 1)
        body = raw[1:end]
        trailing = raw[end + 1:]
        if "nocase" in trailing:
            nocase = True
        body = body.encode().decode("unicode_escape")
        return "text", body, nocase
    raise ValueError(f"cannot parse string value: {raw!r}")


def _parse_block(name: str, body: str) -> Rule:
    meta: Dict[str, str] = {}
    strings: List[StringDef] = []
    condition = ""

    sections = re.split(r"\b(meta|strings|condition)\s*:", body)
    # sections[0] is leading junk; then pairs of (keyword, content)
    i = 1
    while i < len(sections) - 1:
        key = sections[i].strip()
        content = sections[i + 1]
        i += 2
        if key == "meta":
            for line in content.splitlines():
                m = re.match(r"\s*([A-Za-z_]\w*)\s*=\s*\"(.*)\"\s*$", line)
                if m:
                    meta[m.group(1)] = m.group(2)
        elif key == "strings":
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                sm = _STRING_RE.match(line)
                if not sm:
                    continue
                sname = sm.group(1)
                kind, value, nocase = _parse_string_value(sm.group(2))
                strings.append(StringDef(name=sname, kind=kind, raw=value, nocase=nocase))
        elif key == "condition":
            condition = " ".join(content.split()).strip()

    if not strings:
        raise ValueError(f"rule {name} has no strings")
    if not condition:
        condition = "any of them"
    return Rule(name=name, strings=strings, condition=condition, meta=meta)


def parse_rules(text: str) -> List[Rule]:
    text = _strip_comments(text)
    rules: List[Rule] = []
    for m in _RULE_RE.finditer(text):
        rules.append(_parse_block(m.group(1), m.group(2)))
    if not rules:
        raise ValueError("no rules found in input")
    return rules


def parse_rules_file(path: str) -> List[Rule]:
    with open(path, "r", encoding="utf-8") as fh:
        return parse_rules(fh.read())


# --------------------------------------------------------------------------- #
# Condition evaluation
# --------------------------------------------------------------------------- #
def _eval_condition(condition: str, hits: Dict[str, bool], all_names: List[str]) -> bool:
    """Evaluate a rule condition given which string ids matched.

    Translates the YARA-ish condition into a Python boolean expression over a
    restricted namespace (only the hit booleans, parentheses, and/or/not). The
    'N of them' / 'any of them' / 'all of them' forms are expanded first.
    """
    cond = condition
    count_hits = sum(1 for v in hits.values() if v)
    total = len(all_names)

    cond = re.sub(r"\ball\s+of\s+them\b", str(count_hits >= total and total > 0), cond)
    cond = re.sub(r"\bany\s+of\s+them\b", str(count_hits >= 1), cond)

    def _n_of_them(m: re.Match) -> str:
        n = int(m.group(1))
        return str(count_hits >= n)

    cond = re.sub(r"\b(\d+)\s+of\s+them\b", _n_of_them, cond)

    # Replace $identifiers with their boolean value.
    def _sub_id(m: re.Match) -> str:
        name = m.group(1)
        return str(bool(hits.get(name, False)))

    cond = re.sub(r"\$([A-Za-z_]\w*)", _sub_id, cond)

    # Normalize operators to Python.
    cond = re.sub(r"\band\b", " and ", cond)
    cond = re.sub(r"\bor\b", " or ", cond)
    cond = re.sub(r"\bnot\b", " not ", cond)

    # Validate: only allow a safe token set before eval.
    allowed = re.fullmatch(r"[\sTrueFalsealndort()]*", cond)
    if not allowed:
        raise ValueError(f"unsafe/invalid condition after expansion: {cond!r}")
    if not cond.strip():
        return False
    return bool(eval(cond, {"__builtins__": {}}, {}))  # noqa: S307 - sandboxed token set


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #
def _preview(data: bytes, limit: int = 60) -> str:
    snippet = data[:limit]
    return snippet.decode("utf-8", errors="replace")


def _scan_bytes(data: bytes, rules: List[Rule], path: str) -> FileResult:
    result = FileResult(path=path)
    for rule in rules:
        hits: Dict[str, bool] = {}
        rule_matches: List[Match] = []
        for sd in rule.strings:
            pat = sd.compile()
            found = False
            for mo in pat.finditer(data):
                found = True
                rule_matches.append(
                    Match(
                        rule=rule.name,
                        string=sd.name,
                        offset=mo.start(),
                        matched=_preview(mo.group(0)),
                    )
                )
            hits[sd.name] = found
        if _eval_condition(rule.condition, hits, rule.string_names()):
            result.matches.extend(rule_matches)
    return result


def _iter_files(root: str) -> Iterable[str]:
    if os.path.isfile(root):
        yield root
        return
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in sorted(filenames):
            yield os.path.join(dirpath, fn)


def scan_path(target: str, rules: List[Rule]) -> ScanReport:
    report = ScanReport()
    for fpath in _iter_files(target):
        try:
            size = os.path.getsize(fpath)
            if size > MAX_FILE_BYTES:
                report.files_skipped += 1
                continue
            with open(fpath, "rb") as fh:
                data = fh.read()
        except (OSError, IOError) as exc:
            report.errors.append(f"{fpath}: {exc}")
            continue
        report.files_scanned += 1
        fres = _scan_bytes(data, rules, fpath)
        if fres.matches:
            report.results.append(fres)
    return report
