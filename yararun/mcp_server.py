"""YARARUN MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json

from yararun.core import load_rules, parse_rules, scan


def _scan_path_to_json(target: str, rules_text: str | None = None) -> str:
    """Read a file, scan it with the bundled (or supplied) rules, return JSON."""
    with open(target, "rb") as fh:
        data = fh.read()
    rules = parse_rules(rules_text) if rules_text else load_rules()
    return json.dumps(scan(data, rules, target=target).to_dict(), indent=2)


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-yararun[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-yararun[mcp]'")
        return 1
    app = FastMCP("yararun")

    @app.tool()
    def yararun_scan(target: str, rules: str | None = None) -> str:
        """Scan a file with YARA-style rules. `target` is a file path; optional
        `rules` is custom rule-pack source text. Returns JSON findings
        (entropy, file type, hashes, and matched rules with offsets)."""
        return _scan_path_to_json(target, rules)

    app.run()
    return 0
