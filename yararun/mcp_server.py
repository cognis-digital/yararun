"""YARARUN MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
import json
import os
from yararun.core import load_rules, scan


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
    def yararun_scan(target: str) -> str:
        """Scan a file path with the bundled YARA triage rules. Returns JSON findings."""
        if not os.path.isfile(target):
            return json.dumps({"error": f"file not found: {target}"})
        try:
            data = open(target, "rb").read()
        except OSError as exc:
            return json.dumps({"error": str(exc)})
        rules = load_rules()
        result = scan(data, rules, target=target)
        return json.dumps(result.to_dict())

    app.run()
    return 0
