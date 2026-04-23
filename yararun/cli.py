"""YARARUN command-line interface."""
from __future__ import annotations
import argparse, sys
from yararun.core import scan, to_json, TOOL_NAME, TOOL_VERSION

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="yararun", description="YARARUN — Cognis Neural Suite")
    ap.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = ap.add_subparsers(dest="cmd")
    s = sub.add_parser("scan", help="scan a file or directory")
    s.add_argument("target")
    s.add_argument("--format", choices=["table", "json"], default="table")
    s.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], default=None)
    sub.add_parser("mcp", help="run as an MCP server")
    args = ap.parse_args(argv)

    if args.cmd == "mcp":
        from yararun.mcp_server import serve
        return serve()
    if args.cmd == "scan":
        res = scan(args.target)
        if args.format == "json":
            print(to_json(res))
        else:
            if not res.findings:
                print(f"[{TOOL_NAME}] no findings in {args.target}")
            for f in res.findings:
                print(f"  [{f.severity.upper():8}] {f.id}  {f.title}  ({f.where})")
            print(f"\n{len(res.findings)} findings · risk score {res.score} · {res.elapsed_ms}ms")
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        if args.fail_on and any(order.get(f.severity, 0) >= order[args.fail_on] for f in res.findings):
            return 2
        return 0
    ap.print_help()
    return 0

if __name__ == "__main__":
    sys.exit(main())
