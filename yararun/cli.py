"""Command-line interface for YARARUN.

Defensive/authorized use only. Scans a directory tree with simple YARA-style
rules and reports matches. Exit code is non-zero when matches are found (so it
is usable as a tripwire in CI/triage pipelines) or on error.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import ScanReport, parse_rules, parse_rules_file, scan_path

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _print_table(report: ScanReport) -> None:
    if not report.results:
        print("No matches.")
    else:
        print(f"{'RULE':<24} {'STRING':<10} {'OFFSET':>10}  PATH")
        print("-" * 78)
        for fres in report.results:
            for m in fres.matches:
                print(f"{m.rule:<24} {m.string:<10} {m.offset:>10}  {fres.path}")
    print("-" * 78)
    print(
        f"scanned={report.files_scanned} skipped={report.files_skipped} "
        f"matches={report.total_matches} files_hit={len(report.results)} "
        f"errors={len(report.errors)}"
    )
    for err in report.errors:
        print(f"error: {err}", file=sys.stderr)


def _run_scan(args: argparse.Namespace) -> int:
    try:
        if args.rule_string:
            rules = parse_rules(args.rule_string)
        else:
            rules = parse_rules_file(args.rules)
    except (OSError, ValueError) as exc:
        print(f"rule error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    try:
        report = scan_path(args.target, rules)
    except OSError as exc:
        print(f"scan error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        _print_table(report)

    if report.errors:
        return EXIT_ERROR
    return EXIT_FINDINGS if report.total_matches else EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Run simple YARA-style string/regex rules over a directory "
        "(defensive/authorized analysis & triage only).",
    )
    parser.add_argument(
        "--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}"
    )
    parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="output format (default: table)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a file or directory with rules")
    scan.add_argument("target", help="file or directory to scan")
    grp = scan.add_mutually_exclusive_group(required=True)
    grp.add_argument("-r", "--rules", help="path to a .yar rules file")
    grp.add_argument(
        "-e", "--rule-string", help="inline rule text (same syntax as a file)"
    )
    scan.set_defaults(func=_run_scan)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
