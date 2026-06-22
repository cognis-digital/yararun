"""YARARUN core — a working subset of the YARA rule engine + a triage rule pack.

This is a pure-stdlib re-implementation of a *useful subset* of YARA
(https://github.com/VirusTotal/yara). It is deliberately not a full YARA
clone, but it implements the parts that make YARA practical for malware/IOC
triage on artifacts you already possess:

  * rule declaration with `meta:`, `strings:`, and `condition:` sections
  * text strings           $a = "evil.exe"          (modifiers: nocase, wide, ascii, fullword, xor)
  * hex strings            $h = { 4D 5A ?? 50 [2-4] 90 }   (wildcards + jumps)
  * regex strings          $r = /https?:\\/\\/[a-z]+/ nocase
  * string counts          #a, #a > 3
  * offsets / anchoring     $a at 0, $a in (0..1024), @a[1], @a
  * match length            !a (length of first match of $a)
  * integer functions       uint8(0), uint16(0), uint32(0), uint16be(0) ...
  * boolean conditions     and / or / not / parentheses
  * comparison/arithmetic  > < >= <= == != + - *
  * set conditions         any of them, all of ($a, $b), 2 of ($s*)
  * special vars           filesize, all, any, entropy
  * tags                   rule X : trojan apt { ... }

It also exposes a small "module" of file-intelligence used by malware triage
the way VirusTotal does: Shannon entropy, magic/file-type sniffing, and
cryptographic hashes (MD5/SHA1/SHA256). These are surfaced both in the scan
result and as condition variables (`entropy`, `filetype`).

It ships with a real, non-trivial bundled rule pack (DEFAULT_RULES) covering
common triage signatures: PE/ELF/Mach-O headers, packers (UPX), embedded
scripts (PowerShell/JS/VBScript), eval/exec droppers, base64 PE stubs,
suspicious URLs/onion addresses, ransom notes, crypto-mining pool configs,
high-entropy packed blobs, XOR-obfuscated MZ stubs, and more.

Defensive use only: scan files/blobs you are authorized to inspect.
"""
from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

TOOL_NAME = "yararun"
TOOL_VERSION = "2.0.0"

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


# --------------------------------------------------------------------------- #
# File intelligence module (entropy / magic / hashes)                         #
# --------------------------------------------------------------------------- #
def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte (0..8). 7.5+ usually means packed/encrypted."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 4)


_MAGIC: list[tuple[bytes, str]] = [
    (b"MZ", "pe"),
    (b"\x7fELF", "elf"),
    (b"\xfe\xed\xfa\xce", "macho"),
    (b"\xfe\xed\xfa\xcf", "macho"),
    (b"\xca\xfe\xba\xbe", "macho-fat/java-class"),
    (b"\xcf\xfa\xed\xfe", "macho"),
    (b"PK\x03\x04", "zip/office/jar"),
    (b"PK\x05\x06", "zip-empty"),
    (b"Rar!\x1a\x07", "rar"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"%PDF", "pdf"),
    (b"\xd0\xcf\x11\xe0", "ole/legacy-office"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"GIF8", "gif"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"#!/bin/sh", "shell-script"),
    (b"#!/bin/bash", "shell-script"),
    (b"#!/usr/bin/env", "script"),
    (b"<?php", "php"),
    (b"<!DOCTYPE html", "html"),
    (b"<html", "html"),
    (b"{\\rtf", "rtf"),
]


def sniff_filetype(data: bytes) -> str:
    """Best-effort magic-byte file-type sniff; returns 'text', 'data', or a label."""
    for sig, label in _MAGIC:
        if data.startswith(sig):
            return label
    # heuristic: printable ratio
    if data:
        sample = data[:4096]
        printable = sum(1 for b in sample if 9 <= b <= 13 or 32 <= b < 127)
        if printable / len(sample) > 0.92:
            return "text"
    return "data"


def file_hashes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


# --------------------------------------------------------------------------- #
# Compiled string atoms                                                       #
# --------------------------------------------------------------------------- #
@dataclass
class StringDef:
    """One `$id = ...` declaration, compiled to a matcher."""
    ident: str
    raw: str
    kind: str                     # "text" | "hex" | "regex"
    regex: re.Pattern[bytes] | None = None
    fullword: bool = False
    private: bool = False
    xor: bool = False
    xor_lo: int = 0
    xor_hi: int = 255
    literal: bytes = b""          # for xor scanning

    def find(self, data: bytes) -> list[tuple[int, int]]:
        """Return (offset, match_length) for every non-overlapping match."""
        if self.xor:
            return self._find_xor(data)
        out: list[tuple[int, int]] = []
        assert self.regex is not None
        for m in self.regex.finditer(data):
            if self.fullword and not _is_fullword(data, m.start(), m.end()):
                continue
            out.append((m.start(), m.end() - m.start()))
        return out

    def _find_xor(self, data: bytes) -> list[tuple[int, int]]:
        """Brute-force single-byte XOR scan over the literal (real YARA `xor`)."""
        out: list[tuple[int, int]] = []
        lit = self.literal
        ln = len(lit)
        if not ln:
            return out
        for key in range(self.xor_lo, self.xor_hi + 1):
            needle = bytes(b ^ key for b in lit)
            start = 0
            while True:
                idx = data.find(needle, start)
                if idx < 0:
                    break
                out.append((idx, ln))
                start = idx + 1
        out.sort()
        return out


def _is_fullword(data: bytes, start: int, end: int) -> bool:
    word = re.compile(rb"[A-Za-z0-9_]")
    if start > 0 and word.match(data[start - 1:start]):
        return False
    if end < len(data) and word.match(data[end:end + 1]):
        return False
    return True


# --------------------------------------------------------------------------- #
# String compilation                                                          #
# --------------------------------------------------------------------------- #
def _compile_text(value: str, mods: set[str]) -> tuple[re.Pattern[bytes], str]:
    raw = value.encode("utf-8")
    flags = re.IGNORECASE if "nocase" in mods else 0
    if "wide" in mods and "ascii" not in mods:
        pat = b"".join(re.escape(bytes([b])) + b"\\x00" for b in raw)
    elif "wide" in mods and "ascii" in mods:
        wide = b"".join(re.escape(bytes([b])) + b"\\x00" for b in raw)
        pat = b"(?:" + re.escape(raw) + b"|" + wide + b")"
    else:
        pat = re.escape(raw)
    return re.compile(pat, flags), "text"


_HEX_TOKEN = re.compile(r"\?\?|[0-9A-Fa-f]{2}|\[\s*\d*\s*-?\s*\d*\s*\]|\(|\)|\|")


def _compile_hex(body: str) -> tuple[re.Pattern[bytes], str]:
    """Compile a hex string  { 4D 5A ?? [2-4] 90 }  into a byte regex."""
    inner = body.strip().lstrip("{").rstrip("}").strip()
    parts: list[bytes] = []
    for tok in _HEX_TOKEN.findall(inner):
        tok = tok.strip()
        if tok == "??":
            parts.append(b"[\\x00-\\xff]")
        elif tok in ("(", ")", "|"):
            parts.append(tok.encode())
        elif tok.startswith("["):
            nums = tok.strip("[]").split("-")
            lo = nums[0].strip()
            hi = nums[1].strip() if len(nums) > 1 else nums[0].strip()
            lo = lo if lo else "0"
            hi = hi if hi else ""
            parts.append(b"[\\x00-\\xff]{%s,%s}" % (lo.encode(), hi.encode()))
        else:
            parts.append(b"\\x" + tok.lower().encode())
    return re.compile(b"".join(parts), re.DOTALL), "hex"


def _compile_regex(value: str, mods: set[str]) -> tuple[re.Pattern[bytes], str]:
    flags = re.DOTALL
    if "nocase" in mods:
        flags |= re.IGNORECASE
    return re.compile(value.encode("utf-8"), flags), "regex"


# --------------------------------------------------------------------------- #
# Rule model                                                                  #
# --------------------------------------------------------------------------- #
@dataclass
class Rule:
    name: str
    tags: list[str]
    meta: dict[str, Any]
    strings: dict[str, StringDef]
    condition: str

    def severity(self) -> str:
        sev = str(self.meta.get("severity", "")).lower()
        return sev if sev in SEVERITY_ORDER else "medium"


@dataclass
class StringMatch:
    ident: str
    offset: int
    length: int
    preview: str


@dataclass
class RuleMatch:
    rule: str
    tags: list[str]
    meta: dict[str, Any]
    severity: str
    matched_strings: list[StringMatch]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "tags": self.tags,
            "severity": self.severity,
            "meta": self.meta,
            "strings": [
                {"id": s.ident, "offset": s.offset,
                 "length": s.length, "preview": s.preview}
                for s in self.matched_strings
            ],
        }


# --------------------------------------------------------------------------- #
# Parser                                                                       #
# --------------------------------------------------------------------------- #
_RULE_RE = re.compile(
    r"rule\s+(?P<name>[A-Za-z_]\w*)\s*"
    r"(?::\s*(?P<tags>[\w\s]+?))?\s*"
    r"\{(?P<body>.*?)\}\s*(?=rule\s|\Z)",
    re.DOTALL,
)
_SECTION_RE = re.compile(r"\b(meta|strings|condition)\s*:", re.IGNORECASE)
_STRING_LINE_RE = re.compile(r"^\s*(\$[\w]*)\s*=\s*(.+?)\s*$")


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    out = []
    for line in text.splitlines():
        # strip // comments not inside a string/regex literal (best-effort).
        # A double-slash is always a comment (regex literals never contain //
        # un-escaped); a single slash opens/closes a regex literal.
        in_str = False
        quote = ""
        cleaned = []
        i = 0
        while i < len(line):
            c = line[i]
            if in_str:
                cleaned.append(c)
                if c == quote and line[i - 1] != "\\":
                    in_str = False
            elif c == "/" and i + 1 < len(line) and line[i + 1] == "/":
                break
            elif c in ('"', "/"):
                in_str = True
                quote = c
                cleaned.append(c)
            else:
                cleaned.append(c)
            i += 1
        out.append("".join(cleaned))
    return "\n".join(out)


def _parse_meta(block: str) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    for line in block.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip()
        if val.startswith('"') and val.endswith('"'):
            meta[key] = val[1:-1]
        elif val.lower() in ("true", "false"):
            meta[key] = val.lower() == "true"
        else:
            try:
                meta[key] = int(val)
            except ValueError:
                meta[key] = val
    return meta


def _parse_xor_range(mods_str: str) -> tuple[int, int] | None:
    """Parse `xor` or `xor(0x01-0xff)` modifier -> (lo, hi) or None."""
    m = re.search(r"\bxor\b(?:\s*\(\s*([0-9a-fx]+)\s*-\s*([0-9a-fx]+)\s*\))?",
                  mods_str, re.IGNORECASE)
    if not m:
        return None
    if m.group(1) is None:
        return 1, 255
    return int(m.group(1), 0), int(m.group(2), 0)


def _parse_string_def(ident: str, rhs: str) -> StringDef:
    rhs = rhs.strip()
    if rhs.startswith("{"):
        regex, kind = _compile_hex(rhs)
        return StringDef(ident, rhs, kind, regex=regex)
    if rhs.startswith("/"):
        end = rhs.rfind("/")
        body = rhs[1:end]
        mods = set(rhs[end + 1:].split())
        regex, kind = _compile_regex(body, mods)
        return StringDef(ident, body, kind, regex=regex, fullword="fullword" in mods)
    # text string
    m = re.match(r'"((?:[^"\\]|\\.)*)"\s*(.*)$', rhs)
    if not m:
        raise ValueError(f"cannot parse string def for {ident}: {rhs!r}")
    value = m.group(1).encode().decode("unicode_escape")
    mods_str = m.group(2)
    mods = set(mods_str.split())
    xor_range = _parse_xor_range(mods_str)
    if xor_range is not None:
        lit = value.encode("latin-1", "replace")
        return StringDef(ident, value, "text", regex=None, xor=True,
                         xor_lo=xor_range[0], xor_hi=xor_range[1], literal=lit,
                         fullword="fullword" in mods)
    regex, kind = _compile_text(value, mods)
    return StringDef(ident, value, kind, regex=regex, fullword="fullword" in mods)


def parse_rules(text: str) -> list[Rule]:
    """Parse YARA-subset source into a list of Rule objects."""
    text = _strip_comments(text)
    rules: list[Rule] = []
    for rm in _RULE_RE.finditer(text):
        name = rm.group("name")
        tags = (rm.group("tags") or "").split()
        body = rm.group("body")

        # split body into sections by keyword
        sections: dict[str, str] = {}
        marks = list(_SECTION_RE.finditer(body))
        for i, mk in enumerate(marks):
            label = mk.group(1).lower()
            start = mk.end()
            end = marks[i + 1].start() if i + 1 < len(marks) else len(body)
            sections[label] = body[start:end]

        meta = _parse_meta(sections.get("meta", ""))
        strings: dict[str, StringDef] = {}
        anon = 0
        for line in sections.get("strings", "").splitlines():
            sm = _STRING_LINE_RE.match(line)
            if not sm:
                continue
            sid = sm.group(1)
            if sid == "$":
                sid = f"$_anon{anon}"
                anon += 1
            strings[sid] = _parse_string_def(sid, sm.group(2))

        condition = " ".join(sections.get("condition", "true").split())
        rules.append(Rule(name, tags, meta, strings, condition or "true"))
    return rules


# --------------------------------------------------------------------------- #
# Condition evaluator                                                         #
# --------------------------------------------------------------------------- #
class _Cond:
    """Evaluate a YARA-subset boolean condition against match state."""

    def __init__(self, rule: Rule, hits: dict[str, list[tuple[int, int]]],
                 data: bytes, ctx: dict[str, Any]):
        self.rule = rule
        self.hits = hits          # ident -> list[(offset, length)]
        self.data = data
        self.filesize = len(data)
        self.ctx = ctx            # entropy, filetype, etc.

    # ---- public ------------------------------------------------------- #
    def eval(self, expr: str) -> bool:
        self.toks = self._tokenize(expr)
        self.pos = 0
        val = self._or()
        return bool(val)

    # ---- tokenizer ---------------------------------------------------- #
    _TOK_RE = re.compile(
        r"\(|\)|,|\[|\]|\.\.|>=|<=|==|!=|>|<|\+|\-|\*|"
        r"\b(?:and|or|not|of|them|all|any|at|in|filesize|entropy|filetype|"
        r"true|false|"
        r"uint8|uint16|uint32|uint16be|uint32be|int8|int16|int32)\b|"
        r"[#$@!]?[\w*]+|0x[0-9A-Fa-f]+|\d+(?:KB|MB|GB)?|"
        r'"[^"]*"',
        re.IGNORECASE,
    )

    def _tokenize(self, expr: str) -> list[str]:
        return self._TOK_RE.findall(expr)

    def _peek(self, k: int = 0) -> str | None:
        i = self.pos + k
        return self.toks[i] if i < len(self.toks) else None

    def _next(self) -> str:
        t = self.toks[self.pos]
        self.pos += 1
        return t

    # ---- grammar (precedence: or<and<not<cmp<add<primary) ------------- #
    def _or(self):
        v = self._and()
        while (t := self._peek()) and t.lower() == "or":
            self._next()
            v = bool(v) or bool(self._and())
        return v

    def _and(self):
        v = self._not()
        while (t := self._peek()) and t.lower() == "and":
            self._next()
            v = bool(v) and bool(self._not())
        return v

    def _not(self):
        if (t := self._peek()) and t.lower() == "not":
            self._next()
            return not bool(self._not())
        return self._cmp()

    def _cmp(self):
        left = self._add()
        t = self._peek()
        if t in (">", "<", ">=", "<=", "==", "!="):
            op = self._next()
            return self._apply_cmp(left, op, self._add())
        return left

    def _add(self):
        v = self._term()
        while (t := self._peek()) in ("+", "-"):
            op = self._next()
            r = self._term()
            v = _num(v) + _num(r) if op == "+" else _num(v) - _num(r)
        return v

    def _term(self):
        v = self._primary()
        while self._peek() == "*":
            # only treat '*' as multiply between numeric primaries
            if not isinstance(v, (int, float)):
                break
            self._next()
            v = _num(v) * _num(self._primary())
        return v

    @staticmethod
    def _apply_cmp(a, op, b):
        a, b = _num(a), _num(b)
        return {
            ">": a > b, "<": a < b, ">=": a >= b, "<=": a <= b,
            "==": a == b, "!=": a != b,
        }[op]

    # ---- integer-at-offset functions ---------------------------------- #
    def _read_int(self, fn: str):
        if self._peek() == "(":
            self._next()
        off = int(_num(self._add()))
        if self._peek() == ")":
            self._next()
        sizes = {"uint8": 1, "int8": 1, "uint16": 2, "uint16be": 2,
                 "int16": 2, "uint32": 4, "uint32be": 4, "int32": 4}
        size = sizes[fn]
        chunk = self.data[off:off + size]
        if len(chunk) < size:
            return 0
        be = fn.endswith("be")
        signed = fn.startswith("int")
        return int.from_bytes(chunk, "big" if be else "little", signed=signed)

    def _primary(self):
        t = self._next()
        low = t.lower()

        if t == "(":
            v = self._or()
            if self._peek() == ")":
                self._next()
            return v

        if low == "true":
            return True
        if low == "false":
            return False
        if low == "filesize":
            return self.filesize
        if low == "entropy":
            return self.ctx.get("entropy", 0.0)
        if low == "filetype":
            return self.ctx.get("filetype", "data")

        if low in ("uint8", "uint16", "uint32", "uint16be", "uint32be",
                   "int8", "int16", "int32"):
            return self._read_int(low)

        # quoted literal (e.g. filetype == "pe")
        if t.startswith('"') and t.endswith('"'):
            return t[1:-1]

        # set expressions:  <quant> of (...) | them
        if (low in ("all", "any") or t.isdigit()) and \
                self._peek() and self._peek().lower() == "of":
            self._next()
            members = self._of_set()
            count = self._count_set(members)
            need = self._quant(low, len(members))
            return count >= need

        # numeric literals incl. 0x.. and KB/MB/GB
        if t.lower().startswith("0x"):
            return int(t, 16)
        m = re.fullmatch(r"(\d+)(KB|MB|GB)?", t, re.IGNORECASE)
        if m:
            n = int(m.group(1))
            unit = (m.group(2) or "").upper()
            return n * {"": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3}[unit]

        if low in ("all", "any"):
            return True

        # #a count
        if t.startswith("#"):
            return len(self.hits.get("$" + t[1:], []))

        # !a length of first match
        if t.startswith("!"):
            offs = self.hits.get("$" + t[1:], [])
            return offs[0][1] if offs else 0

        # @a / @a[i] offset of i-th match (1-based, YARA-style)
        if t.startswith("@"):
            offs = self.hits.get("$" + t[1:], [])
            if self._peek() == "[":
                self._next()
                idx = int(_num(self._add()))
                if self._peek() == "]":
                    self._next()
                return offs[idx - 1][0] if 1 <= idx <= len(offs) else -1
            return offs[0][0] if offs else -1

        # $a match reference (boolean), with at/in anchors
        if t.startswith("$"):
            idents = self._expand(t)
            hit = any(self.hits.get(i) for i in idents)
            nxt = self._peek()
            if nxt and nxt.lower() == "at":
                self._next()
                off = int(_num(self._primary()))
                return any(off == o for i in idents
                           for (o, _l) in self.hits.get(i, []))
            if nxt and nxt.lower() == "in":
                self._next()
                lo, hi = self._range()
                return any(lo <= o <= hi for i in idents
                           for (o, _l) in self.hits.get(i, []))
            return hit

        return False

    # ---- helpers ------------------------------------------------------ #
    def _range(self) -> tuple[int, int]:
        if self._peek() == "(":
            self._next()
        lo = int(_num(self._add()))
        if self._peek() == "..":
            self._next()
        hi = int(_num(self._add()))
        if self._peek() == ")":
            self._next()
        return lo, hi

    def _of_set(self) -> list[str]:
        nxt = self._peek()
        if nxt and nxt.lower() == "them":
            self._next()
            return list(self.rule.strings.keys())
        if nxt == "(":
            self._next()
            members: list[str] = []
            while self._peek() and self._peek() != ")":
                tok = self._next()
                if tok == ",":
                    continue
                members.extend(self._expand(tok))
            if self._peek() == ")":
                self._next()
            return members
        return list(self.rule.strings.keys())

    def _expand(self, tok: str) -> list[str]:
        if tok.endswith("*"):
            prefix = tok[:-1]
            return [k for k in self.rule.strings if k.startswith(prefix)]
        return [tok]

    def _count_set(self, members: list[str]) -> int:
        return sum(1 for m in members if self.hits.get(m))

    @staticmethod
    def _quant(word: str, total: int) -> int:
        if word == "all":
            return total
        if word == "any":
            return 1
        return int(word)


def _num(v) -> Any:
    if isinstance(v, (int, float)):
        return v
    if isinstance(v, bool):
        return 1 if v else 0
    if isinstance(v, str):
        return v
    return 1 if v else 0


# --------------------------------------------------------------------------- #
# Scanner                                                                      #
# --------------------------------------------------------------------------- #
def _preview(data: bytes, off: int, n: int = 24) -> str:
    chunk = data[off:off + n]
    return "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)


def match_rule(rule: Rule, data: bytes, ctx: dict[str, Any] | None = None
               ) -> RuleMatch | None:
    if ctx is None:
        ctx = _scan_context(data)
    hits: dict[str, list[tuple[int, int]]] = {}
    matched: list[StringMatch] = []
    for ident, sd in rule.strings.items():
        offs = sd.find(data)
        if offs:
            hits[ident] = offs
            o0, l0 = offs[0]
            matched.append(StringMatch(ident, o0, l0, _preview(data, o0)))
    try:
        ok = _Cond(rule, hits, data, ctx).eval(rule.condition)
    except Exception:
        ok = False
    if not ok:
        return None
    return RuleMatch(
        rule=rule.name,
        tags=rule.tags,
        meta=rule.meta,
        severity=rule.severity(),
        matched_strings=matched,
    )


def _scan_context(data: bytes) -> dict[str, Any]:
    return {"entropy": shannon_entropy(data), "filetype": sniff_filetype(data)}


@dataclass
class ScanResult:
    target: str
    size: int
    entropy: float = 0.0
    filetype: str = "data"
    hashes: dict[str, str] = field(default_factory=dict)
    matches: list[RuleMatch] = field(default_factory=list)

    @property
    def max_severity(self) -> str:
        for sev in SEVERITY_ORDER:
            if any(m.severity == sev for m in self.matches):
                return sev
        return "info"

    def counts(self) -> dict[str, int]:
        c = {s: 0 for s in SEVERITY_ORDER}
        for m in self.matches:
            c[m.severity] = c.get(m.severity, 0) + 1
        return c

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "size": self.size,
            "entropy": self.entropy,
            "filetype": self.filetype,
            "hashes": self.hashes,
            "match_count": len(self.matches),
            "max_severity": self.max_severity,
            "counts": self.counts(),
            "matches": [m.to_dict() for m in self.matches],
        }


def scan(data: bytes, rules: Iterable[Rule], target: str = "<data>",
         hashes: bool = True) -> ScanResult:
    ctx = _scan_context(data)
    res = ScanResult(
        target=target,
        size=len(data),
        entropy=ctx["entropy"],
        filetype=ctx["filetype"],
        hashes=file_hashes(data) if hashes else {},
    )
    for rule in rules:
        m = match_rule(rule, data, ctx)
        if m:
            res.matches.append(m)
    res.matches.sort(key=lambda m: SEVERITY_ORDER.index(m.severity))
    return res


def load_rules(text: str | None = None) -> list[Rule]:
    """Load rules from text, or the bundled DEFAULT_RULES if None."""
    return parse_rules(text if text is not None else DEFAULT_RULES)


# --------------------------------------------------------------------------- #
# SARIF 2.1.0 export (code-scanning / GitHub Advanced Security compatible)     #
# --------------------------------------------------------------------------- #
# SARIF severity is a small enum; map YARARUN severities onto it.
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}
# numeric security-severity (0-10) consumed by GitHub code-scanning.
_SARIF_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.0",
    "low": "3.0",
    "info": "1.0",
}


def to_sarif(results: Iterable["ScanResult"],
             tool_version: str = TOOL_VERSION) -> dict[str, Any]:
    """Render scan results as a SARIF 2.1.0 log (one run, one tool driver).

    Each distinct rule that matched becomes a SARIF `reportingDescriptor`
    (rule); every match becomes a `result` pointing at the scanned file with a
    byte-offset region. The output validates against the SARIF 2.1.0 schema and
    is consumable by GitHub code-scanning, Azure DevOps, and SARIF viewers.
    """
    results = list(results)
    rule_index: dict[str, int] = {}
    rule_descriptors: list[dict[str, Any]] = []
    sarif_results: list[dict[str, Any]] = []

    for res in results:
        for m in res.matches:
            if m.rule not in rule_index:
                rule_index[m.rule] = len(rule_descriptors)
                rule_descriptors.append({
                    "id": m.rule,
                    "name": m.rule,
                    "shortDescription": {
                        "text": str(m.meta.get("description", m.rule)),
                    },
                    "defaultConfiguration": {
                        "level": _SARIF_LEVEL.get(m.severity, "warning"),
                    },
                    "properties": {
                        "tags": list(m.tags),
                        "severity": m.severity,
                        "security-severity":
                            _SARIF_SECURITY_SEVERITY.get(m.severity, "5.0"),
                    },
                })
            region = None
            if m.matched_strings:
                first = m.matched_strings[0]
                region = {"byteOffset": first.offset,
                          "byteLength": max(first.length, 1)}
            phys: dict[str, Any] = {"artifactLocation": {"uri": res.target}}
            if region:
                phys["region"] = region
            sarif_results.append({
                "ruleId": m.rule,
                "ruleIndex": rule_index[m.rule],
                "level": _SARIF_LEVEL.get(m.severity, "warning"),
                "message": {
                    "text": f"{m.rule}: "
                            f"{m.meta.get('description', 'rule matched')} "
                            f"(severity={m.severity})",
                },
                "locations": [{"physicalLocation": phys}],
                "properties": {"severity": m.severity, "tags": list(m.tags)},
            })

    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                   "master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": tool_version,
                    "informationUri":
                        "https://github.com/cognis-digital/yararun",
                    "rules": rule_descriptors,
                }
            },
            "results": sarif_results,
        }],
    }


# --------------------------------------------------------------------------- #
# Bundled triage rule pack                                                     #
# --------------------------------------------------------------------------- #
DEFAULT_RULES = r"""
rule PE_Executable : pe format {
    meta:
        author = "yararun"
        severity = "info"
        description = "Windows PE / DOS MZ executable header"
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
    condition:
        uint16(0) == 0x5A4D and $pe
}

rule ELF_Executable : elf format {
    meta:
        severity = "info"
        description = "ELF binary (Linux executable / shared object)"
    strings:
        $elf = { 7F 45 4C 46 }
    condition:
        $elf at 0
}

rule MachO_Executable : macho format {
    meta:
        severity = "info"
        description = "Mach-O binary (macOS executable)"
    strings:
        $m32 = { FE ED FA CE }
        $m64 = { FE ED FA CF }
        $fat = { CA FE BA BE }
        $le  = { CF FA ED FE }
    condition:
        any of them
}

rule High_Entropy_Blob : packer evasion {
    meta:
        severity = "medium"
        description = "Very high Shannon entropy: likely packed/encrypted payload"
    condition:
        entropy >= 7.5 and filesize > 1KB
}

rule UPX_Packed : packer evasion {
    meta:
        severity = "medium"
        description = "UPX-packed executable (common malware packer)"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $sig  = "UPX!"
    condition:
        2 of them
}

rule XOR_Encoded_MZ : evasion encoded {
    meta:
        severity = "high"
        description = "Single-byte XOR-obfuscated MZ/PE executable stub"
    strings:
        $mz = "MZ" xor(0x01-0xff)
        $stub = "This program cannot be run in DOS mode" xor(0x01-0xff)
    condition:
        $mz and $stub
}

rule Embedded_PowerShell : script dropper {
    meta:
        severity = "high"
        description = "Embedded/obfuscated PowerShell loader patterns"
    strings:
        $a = "powershell" nocase
        $b = "-enc" nocase
        $c = "-EncodedCommand" nocase
        $d = "FromBase64String" nocase
        $e = "DownloadString" nocase
        $f = "IEX" fullword
        $g = "Invoke-Expression" nocase
        $h = "hidden" nocase
        $i = "bypass" nocase
    condition:
        $a and 2 of ($b, $c, $d, $e, $f, $g, $h, $i)
}

rule JS_Eval_Dropper : script obfuscation {
    meta:
        severity = "high"
        description = "JavaScript eval/unescape obfuscation dropper"
    strings:
        $eval     = "eval(" nocase
        $unescape = "unescape(" nocase
        $fromcc   = "fromCharCode" nocase
        $atob     = "atob(" nocase
        $doc      = "document.write" nocase
    condition:
        $eval and 2 of ($unescape, $fromcc, $atob, $doc)
}

rule VBScript_Macro : office macro dropper {
    meta:
        severity = "high"
        description = "VBA/VBScript auto-exec macro with shell execution"
    strings:
        $auto1 = "Auto_Open" nocase
        $auto2 = "Document_Open" nocase
        $auto3 = "AutoOpen" nocase
        $shell = "WScript.Shell" nocase
        $run   = ".Run" nocase
        $create = "CreateObject" nocase
    condition:
        any of ($auto1, $auto2, $auto3) and $create and 1 of ($shell, $run)
}

rule Base64_PE_Stub : encoded payload {
    meta:
        severity = "high"
        description = "Base64-encoded PE header (TVqQ / TVpQ) embedded in text"
    strings:
        $b64mz1 = "TVqQAAMAAAAEAAAA"
        $b64mz2 = "TVpQAAIAAAAEAA"
        $b64mz3 = "TVqA"
    condition:
        any of them
}

rule Suspicious_URL : network ioc {
    meta:
        severity = "medium"
        description = "Hardcoded HTTP(S) URL or Tor .onion C2 endpoint"
    strings:
        $url   = /https?:\/\/[a-z0-9.\-]{4,}/ nocase
        $onion = /[a-z2-7]{16,56}\.onion/ nocase
        $ip    = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
    condition:
        $onion or $ip or #url > 2
}

rule Ransom_Note : ransomware {
    meta:
        severity = "critical"
        description = "Ransomware ransom-note language and payment demand"
    strings:
        $r1 = "your files have been encrypted" nocase
        $r2 = "decrypt" nocase
        $r3 = "bitcoin" nocase
        $r4 = "BTC wallet" nocase
        $r5 = "pay the ransom" nocase
        $r6 = "private key" nocase
    condition:
        $r1 and 2 of ($r2, $r3, $r4, $r5, $r6)
}

rule Cryptominer_Config : miner cryptojacking {
    meta:
        severity = "high"
        description = "Crypto-mining pool / stratum configuration strings"
    strings:
        $s1 = "stratum+tcp://" nocase
        $s2 = "xmrig" nocase
        $s3 = "minerd" nocase
        $s4 = "pool.minexmr" nocase
        $s5 = "donate-level" nocase
        $s6 = "cryptonight" nocase
    condition:
        $s1 or 2 of ($s2, $s3, $s4, $s5, $s6)
}

rule Shell_Reverse_Connect : backdoor network {
    meta:
        severity = "critical"
        description = "Reverse shell / netcat / bind-shell command patterns"
    strings:
        $nc1 = "nc -e" nocase
        $nc2 = "ncat -e" nocase
        $bash = "bash -i >&"
        $devtcp = "/dev/tcp/"
        $py = "socket.socket"
        $sub = "subprocess.call"
    condition:
        ($nc1 or $nc2) or ($bash and $devtcp) or ($py and $sub and $devtcp)
}

rule Credential_Theft : infostealer {
    meta:
        severity = "high"
        description = "Browser/OS credential-store access patterns (stealer)"
    strings:
        $a = "Login Data"
        $b = "key3.db"
        $c = "logins.json"
        $d = "wallet.dat"
        $e = "shadow"
        $f = "SAM\\SAM"
    condition:
        2 of them
}

rule Persistence_Registry_Runkey : persistence {
    meta:
        severity = "high"
        description = "Run-key / scheduled-task / service persistence artifacts"
    strings:
        $run1 = "CurrentVersion\\Run" nocase
        $run2 = "CurrentVersion\\RunOnce" nocase
        $task = "schtasks /create" nocase
        $svc  = "sc create" nocase
        $startup = "Start Menu\\Programs\\Startup" nocase
    condition:
        any of them
}

rule EICAR_Test_File : test {
    meta:
        severity = "low"
        description = "EICAR anti-malware test string (harmless test artifact)"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"
    condition:
        $eicar
}
"""
