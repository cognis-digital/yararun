"""YARARUN core — a working subset of the YARA rule engine + a triage rule pack.

This is a pure-stdlib re-implementation of a *useful subset* of YARA
(https://github.com/VirusTotal/yara). It is deliberately not a full YARA
clone, but it implements the parts that make YARA practical for malware/IOC
triage on artifacts you already possess:

  * rule declaration with `meta:`, `strings:`, and `condition:` sections
  * text strings           $a = "evil.exe"          (modifiers: nocase, wide, ascii, fullword)
  * hex strings            $h = { 4D 5A ?? 50 [2-4] 90 }   (wildcards + jumps)
  * regex strings          $r = /https?:\\/\\/[a-z]+/ nocase
  * string counts          #a, #a > 3
  * offsets / anchoring     $a at 0, $a in (0..1024)
  * boolean conditions     and / or / not / parentheses
  * set conditions         any of them, all of ($a, $b), 2 of ($s*)
  * special vars           filesize, all, any
  * tags                   rule X : trojan apt { ... }

It ships with a real, non-trivial bundled rule pack (DEFAULT_RULES) covering
common triage signatures: PE/ELF/Mach-O headers, packers (UPX), embedded
scripts (PowerShell/JS/VBScript), eval/exec droppers, base64 PE stubs,
suspicious URLs/onion addresses, ransom notes, and crypto-mining pool configs.

Defensive use only: scan files/blobs you are authorized to inspect.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

TOOL_NAME = "yararun"
TOOL_VERSION = "1.0.0"

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


# --------------------------------------------------------------------------- #
# Compiled string atoms                                                       #
# --------------------------------------------------------------------------- #
@dataclass
class StringDef:
    """One `$id = ...` declaration, compiled to a regex matcher."""
    ident: str
    raw: str
    kind: str                     # "text" | "hex" | "regex"
    regex: re.Pattern[bytes]
    fullword: bool = False
    private: bool = False

    def find(self, data: bytes) -> list[int]:
        """Return byte offsets of every (non-overlapping start) match."""
        out: list[int] = []
        for m in self.regex.finditer(data):
            if self.fullword and not _is_fullword(data, m.start(), m.end()):
                continue
            out.append(m.start())
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
                {"id": s.ident, "offset": s.offset, "preview": s.preview}
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
_SECTION_RE = re.compile(r"(meta|strings|condition)\s*:", re.IGNORECASE)
_STRING_LINE_RE = re.compile(r"^\s*(\$[\w]*)\s*=\s*(.+?)\s*$")


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    out = []
    for line in text.splitlines():
        # strip // comments not inside a string/regex literal (best-effort)
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
            elif c in ('"', "/"):
                in_str = True
                quote = c
                cleaned.append(c)
            elif c == "/" and i + 1 < len(line) and line[i + 1] == "/":
                break
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


def _parse_string_def(ident: str, rhs: str) -> StringDef:
    rhs = rhs.strip()
    if rhs.startswith("{"):
        regex, kind = _compile_hex(rhs)
        return StringDef(ident, rhs, kind, regex)
    if rhs.startswith("/"):
        end = rhs.rfind("/")
        body = rhs[1:end]
        mods = set(rhs[end + 1:].split())
        regex, kind = _compile_regex(body, mods)
        return StringDef(ident, body, kind, regex, fullword="fullword" in mods)
    # text string
    m = re.match(r'"((?:[^"\\]|\\.)*)"\s*(.*)$', rhs)
    if not m:
        raise ValueError(f"cannot parse string def for {ident}: {rhs!r}")
    value = m.group(1).encode().decode("unicode_escape")
    mods = set(m.group(2).split())
    regex, kind = _compile_text(value, mods)
    return StringDef(ident, value, kind, regex, fullword="fullword" in mods)


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

    def __init__(self, rule: Rule, hits: dict[str, list[int]], filesize: int):
        self.rule = rule
        self.hits = hits          # ident -> list[offset]
        self.filesize = filesize

    # ---- public ------------------------------------------------------- #
    def eval(self, expr: str) -> bool:
        toks = self._tokenize(expr)
        self.toks = toks
        self.pos = 0
        val = self._or()
        return bool(val)

    # ---- tokenizer ---------------------------------------------------- #
    _TOK_RE = re.compile(
        r"\(|\)|,|\.\.|>=|<=|==|!=|>|<|"
        r"\b(?:and|or|not|of|them|all|any|at|in|filesize|true|false)\b|"
        r"[#$@!]?[\w*]+|\d+(?:KB|MB|GB)?",
        re.IGNORECASE,
    )

    def _tokenize(self, expr: str) -> list[str]:
        return self._TOK_RE.findall(expr)

    def _peek(self) -> str | None:
        return self.toks[self.pos] if self.pos < len(self.toks) else None

    def _next(self) -> str:
        t = self.toks[self.pos]
        self.pos += 1
        return t

    # ---- grammar (precedence: or < and < not < primary) --------------- #
    def _or(self):
        v = self._and()
        while (t := self._peek()) and t.lower() == "or":
            self._next()
            r = self._and()
            v = bool(v) or bool(r)
        return v

    def _and(self):
        v = self._not()
        while (t := self._peek()) and t.lower() == "and":
            self._next()
            r = self._not()
            v = bool(v) and bool(r)
        return v

    def _not(self):
        if (t := self._peek()) and t.lower() == "not":
            self._next()
            return not bool(self._not())
        return self._cmp()

    def _cmp(self):
        left = self._primary()
        t = self._peek()
        if t in (">", "<", ">=", "<=", "==", "!="):
            op = self._next()
            right = self._primary()
            return self._apply_cmp(left, op, right)
        return left

    @staticmethod
    def _apply_cmp(a, op, b):
        a = a if isinstance(a, (int, float)) else (1 if a else 0)
        b = b if isinstance(b, (int, float)) else (1 if b else 0)
        return {
            ">": a > b, "<": a < b, ">=": a >= b, "<=": a <= b,
            "==": a == b, "!=": a != b,
        }[op]

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

        # set expressions:  <quant> of (...)  /  <quant> of them
        # (checked before numeric-literal so "2 of them" isn't read as int 2)
        if (low in ("all", "any") or t.isdigit()) and \
                self._peek() and self._peek().lower() == "of":
            self._next()  # consume 'of'
            members = self._of_set()
            count = self._count_set(members)
            need = self._quant(low, len(members))
            return count >= need

        # numeric literals incl. KB/MB/GB
        m = re.fullmatch(r"(\d+)(KB|MB|GB)?", t, re.IGNORECASE)
        if m:
            n = int(m.group(1))
            unit = (m.group(2) or "").upper()
            return n * {"": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3}[unit]

        if low in ("all", "any"):
            # bare 'all'/'any' rarely used alone; treat as truthy
            return True

        # count reference  #a / #a > 3 handled by caller via _cmp
        if t.startswith("#"):
            return len(self.hits.get("$" + t[1:], []))

        # match reference   $a   (boolean: did it hit?)
        if t.startswith("$"):
            idents = self._expand(t)
            hit = any(self.hits.get(i) for i in idents)
            # optional anchors:  $a at N   /  $a in (lo..hi)
            nxt = self._peek()
            if nxt and nxt.lower() == "at":
                self._next()
                off = self._primary()
                return any(off in self.hits.get(i, []) for i in idents)
            if nxt and nxt.lower() == "in":
                self._next()
                lo, hi = self._range()
                return any(
                    any(lo <= o <= hi for o in self.hits.get(i, []))
                    for i in idents
                )
            return hit

        if t.startswith("@"):
            offs = self.hits.get("$" + t[1:], [])
            return offs[0] if offs else -1

        # unknown identifier -> treat as false
        return False

    # ---- helpers ------------------------------------------------------ #
    def _range(self) -> tuple[int, int]:
        if self._peek() == "(":
            self._next()
        lo = int(self._primary())
        if self._peek() == "..":
            self._next()
        hi = int(self._primary())
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


# --------------------------------------------------------------------------- #
# Scanner                                                                      #
# --------------------------------------------------------------------------- #
def _preview(data: bytes, off: int, n: int = 24) -> str:
    chunk = data[off:off + n]
    return "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)


def match_rule(rule: Rule, data: bytes) -> RuleMatch | None:
    hits: dict[str, list[int]] = {}
    matched: list[StringMatch] = []
    for ident, sd in rule.strings.items():
        offs = sd.find(data)
        if offs:
            hits[ident] = offs
            matched.append(StringMatch(ident, offs[0], _preview(data, offs[0])))
    try:
        ok = _Cond(rule, hits, len(data)).eval(rule.condition)
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


@dataclass
class ScanResult:
    target: str
    size: int
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
            "match_count": len(self.matches),
            "max_severity": self.max_severity,
            "counts": self.counts(),
            "matches": [m.to_dict() for m in self.matches],
        }


def scan(data: bytes, rules: Iterable[Rule], target: str = "<data>") -> ScanResult:
    res = ScanResult(target=target, size=len(data))
    for rule in rules:
        m = match_rule(rule, data)
        if m:
            res.matches.append(m)
    res.matches.sort(key=lambda m: SEVERITY_ORDER.index(m.severity))
    return res


def load_rules(text: str | None = None) -> list[Rule]:
    """Load rules from text, or the bundled DEFAULT_RULES if None."""
    return parse_rules(text if text is not None else DEFAULT_RULES)


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
        $mz at 0 and $pe
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
    condition:
        $a and 2 of ($b, $c, $d, $e, $f, $g)
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
