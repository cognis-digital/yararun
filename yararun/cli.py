"""Command-line interface for YARARUN."""
from __future__ import annotations

import argparse
import json
import sys

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    SEVERITY_ORDER,
    ScanResult,
    file_hashes,
    load_rules,
    parse_rules,
    scan,
    shannon_entropy,
    sniff_filetype,
    to_sarif,
)


def _read_bytes(path: str) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read()
    with open(path, "rb") as fh:
        return fh.read()


def _read_text(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _get_rules(args) -> list:
    if getattr(args, "rules", None):
        return parse_rules(_read_text(args.rules))
    return load_rules()


# --------------------------------------------------------------------------- #
# Renderers                                                                    #
# --------------------------------------------------------------------------- #
def _render_scan_table(res: ScanResult) -> str:
    lines: list[str] = []
    lines.append(f"YARARUN scan: {res.target}")
    lines.append("=" * 64)
    lines.append(f"Size           : {res.size} bytes")
    lines.append(f"File type      : {res.filetype}")
    lines.append(f"Entropy        : {res.entropy:.4f} bits/byte"
                 + ("  (HIGH - packed/encrypted)" if res.entropy >= 7.5 else ""))
    if res.hashes:
        lines.append(f"SHA256         : {res.hashes.get('sha256', '')}")
    lines.append(f"Matches        : {len(res.matches)}")
    counts = res.counts()
    sev = ", ".join(f"{k}={counts[k]}" for k in SEVERITY_ORDER if counts[k]) or "none"
    lines.append(f"By severity    : {sev}")
    lines.append(f"Max severity   : {res.max_severity.upper()}")
    lines.append("")
    if not res.matches:
        lines.append("No rules matched.")
        return "\n".join(lines)
    for m in res.matches:
        tagstr = (" :" + " ".join(m.tags)) if m.tags else ""
        lines.append(f"[{m.severity.upper():8}] {m.rule}{tagstr}")
        desc = m.meta.get("description")
        if desc:
            lines.append(f"           {desc}")
        for s in m.matched_strings[:6]:
            lines.append(f"             {s.ident} @ 0x{s.offset:x} "
                         f"(+{s.length})  {s.preview!r}")
        if len(m.matched_strings) > 6:
            lines.append(f"             ... +{len(m.matched_strings) - 6} more")
    return "\n".join(lines)


def _render_rules_table(rules: list) -> str:
    lines = [f"YARARUN rules ({len(rules)} loaded)", "=" * 64]
    for r in rules:
        tagstr = (" :" + " ".join(r.tags)) if r.tags else ""
        lines.append(f"[{r.severity().upper():8}] {r.name}{tagstr}")
        desc = r.meta.get("description")
        if desc:
            lines.append(f"           {desc}")
        lines.append(f"           strings={len(r.strings)}  condition: {r.condition}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Subcommand handlers                                                          #
# --------------------------------------------------------------------------- #
def _cmd_scan(args) -> int:
    try:
        rules = _get_rules(args)
    except (OSError, ValueError) as exc:
        print(f"error: cannot load rules: {exc}", file=sys.stderr)
        return 2

    results: list[ScanResult] = []
    for target in args.targets:
        try:
            data = _read_bytes(target)
        except OSError as exc:
            print(f"error: cannot read {target}: {exc}", file=sys.stderr)
            return 2
        results.append(scan(data, rules, target=target))

    if args.format == "json":
        payload = [r.to_dict() for r in results]
        out = json.dumps(payload if len(payload) != 1 else payload[0], indent=2)
        print(out)
    elif args.format == "sarif":
        print(json.dumps(to_sarif(results), indent=2))
    else:
        print("\n\n".join(_render_scan_table(r) for r in results))

    # Exit-code gate. By default any non-info match is actionable; --fail-on
    # raises the bar to a minimum severity (critical>high>medium>low>info).
    threshold = getattr(args, "fail_on", None) or "low"
    max_allowed = SEVERITY_ORDER.index(threshold)  # lower index == more severe
    overall_findings = any(
        m.severity != "info" and SEVERITY_ORDER.index(m.severity) <= max_allowed
        for r in results for m in r.matches
    )
    return 1 if overall_findings else 0


def _cmd_info(args) -> int:
    """File-intelligence (entropy / type / hashes) without rule matching."""
    reports = []
    for target in args.targets:
        try:
            data = _read_bytes(target)
        except OSError as exc:
            print(f"error: cannot read {target}: {exc}", file=sys.stderr)
            return 2
        reports.append({
            "target": target,
            "size": len(data),
            "filetype": sniff_filetype(data),
            "entropy": shannon_entropy(data),
            "hashes": file_hashes(data),
        })
    if args.format == "json":
        print(json.dumps(reports if len(reports) != 1 else reports[0], indent=2))
    else:
        for r in reports:
            print(f"{r['target']}")
            print(f"  size    : {r['size']} bytes")
            print(f"  type    : {r['filetype']}")
            print(f"  entropy : {r['entropy']:.4f} bits/byte"
                  + ("  (HIGH)" if r["entropy"] >= 7.5 else ""))
            print(f"  md5     : {r['hashes']['md5']}")
            print(f"  sha1    : {r['hashes']['sha1']}")
            print(f"  sha256  : {r['hashes']['sha256']}")
    return 0


def _cmd_rules(args) -> int:
    try:
        rules = _get_rules(args)
    except (OSError, ValueError) as exc:
        print(f"error: cannot load rules: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        payload = [
            {
                "name": r.name,
                "tags": r.tags,
                "severity": r.severity(),
                "meta": r.meta,
                "strings": list(r.strings.keys()),
                "condition": r.condition,
            }
            for r in rules
        ]
        print(json.dumps(payload, indent=2))
    else:
        print(_render_rules_table(rules))
    return 0


def _cmd_compile(args) -> int:
    try:
        text = _read_text(args.rules)
        rules = parse_rules(text)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps({"ok": True, "rule_count": len(rules),
                          "rules": [r.name for r in rules]}, indent=2))
    else:
        print(f"OK: {len(rules)} rule(s) compiled: "
              + ", ".join(r.name for r in rules))
    return 0


def _cmd_feeds(args) -> int:
    """Edge/air-gap threat-intel feed catalog (keyless, offline-capable).

    yararun is a passive, offline scanner. This subcommand never touches the
    network *unless you explicitly ask it to* with `feeds update`/`get`; `list`
    and `--offline` are pure cache/catalog reads. The catalog ships with the
    package so the tool stays fully functional air-gapped.
    """
    try:
        from . import datafeeds
    except ImportError as exc:  # pragma: no cover
        print(f"error: datafeeds unavailable: {exc}", file=sys.stderr)
        return 2

    if args.feeds_cmd == "list":
        feeds = datafeeds.list_feeds(getattr(args, "domain", None))
        if args.format == "json":
            print(json.dumps(feeds, indent=2))
        else:
            print(f"YARARUN feed catalog ({len(feeds)} feeds, keyless/offline-capable)")
            print("=" * 64)
            for f in feeds:
                age = datafeeds.cached_age_hours(f["id"])
                fresh = "uncached" if age is None else f"{age:.1f}h old"
                print(f"  {f['id']:28} {f.get('domain', ''):13} "
                      f"[{fresh}]  {f['name']}")
        return 0

    if args.feeds_cmd == "update":
        # Network egress — only on explicit `feeds update`.
        rc = 0
        for fid in args.ids:
            try:
                pth = datafeeds.update(fid)
                print(f"  updated {fid} -> {pth} ({pth.stat().st_size} bytes)")
            except (KeyError, ConnectionError) as exc:
                print(f"  {fid}: {exc}", file=sys.stderr)
                rc = 1
        return rc

    if args.feeds_cmd == "get":
        try:
            data = datafeeds.get(args.id, offline=args.offline)
        except (KeyError, FileNotFoundError, ConnectionError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if isinstance(data, (dict, list)):
            print(json.dumps(data, indent=2)[:8000])
        else:
            print(data[:8000])
        return 0

    if args.feeds_cmd == "snapshot-export":
        n = datafeeds.snapshot_export(args.path)
        print(f"exported {n} feed(s) -> {args.path}")
        return 0

    if args.feeds_cmd == "snapshot-import":
        n = datafeeds.snapshot_import(args.path)
        print(f"imported {n} feed(s) from {args.path}")
        return 0

    print("error: missing feeds subcommand (list|update|get|snapshot-*)",
          file=sys.stderr)
    return 2


# --------------------------------------------------------------------------- #
# Parser                                                                       #
# --------------------------------------------------------------------------- #
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="YARA-subset rule engine for malware/IOC triage on files "
                    "you are authorized to inspect (defensive use only).",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument("--format", choices=("table", "json", "sarif"),
                   default="table",
                   help="output format (sarif = SARIF 2.1.0 for code-scanning)")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan file(s) against rules")
    s.add_argument("targets", nargs="+",
                   help="file path(s) to scan, or '-' for stdin")
    s.add_argument("-r", "--rules",
                   help="custom rule file (default: bundled triage pack)")
    s.add_argument("--fail-on", dest="fail_on",
                   choices=("critical", "high", "medium", "low"), default="low",
                   help="exit non-zero only at/above this severity "
                        "(default: low = any actionable finding)")
    s.set_defaults(func=_cmd_scan)

    i = sub.add_parser("info", help="file intelligence: entropy, type, hashes")
    i.add_argument("targets", nargs="+", help="file path(s) or '-' for stdin")
    i.set_defaults(func=_cmd_info)

    r = sub.add_parser("rules", help="list loaded rules")
    r.add_argument("-r", "--rules",
                   help="custom rule file (default: bundled triage pack)")
    r.set_defaults(func=_cmd_rules)

    c = sub.add_parser("compile", help="validate/compile a rule file")
    c.add_argument("rules", help="rule file to compile")
    c.set_defaults(func=_cmd_compile)

    # ----------------------------------------------------------------- #
    # feeds: edge/air-gap threat-intel catalog (keyless, offline-first) #
    # ----------------------------------------------------------------- #
    f = sub.add_parser(
        "feeds",
        help="edge/air-gap threat-intel feed catalog (keyless, offline-capable)",
    )
    fsub = f.add_subparsers(dest="feeds_cmd", required=True)
    fl = fsub.add_parser("list", help="list catalogued feeds (offline)")
    fl.add_argument("--domain",
                    help="filter by domain (vuln/threat-intel/compliance/osint)")
    fu = fsub.add_parser("update",
                         help="fetch + cache feed(s) — the ONLY network egress")
    fu.add_argument("ids", nargs="+", help="feed id(s) to refresh")
    fg = fsub.add_parser("get", help="print a cached/fetched feed")
    fg.add_argument("id", help="feed id")
    fg.add_argument("--offline", action="store_true",
                    help="serve from cache only; never touch the network")
    fe = fsub.add_parser("snapshot-export",
                         help="tar the feed cache for air-gap sneakernet")
    fe.add_argument("path", help="output .tar.gz")
    fi = fsub.add_parser("snapshot-import",
                         help="import a feed-cache snapshot (air-gap)")
    fi.add_argument("path", help="input .tar.gz")
    f.set_defaults(func=_cmd_feeds)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
