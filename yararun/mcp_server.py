"""YARARUN MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from yararun.core import scan, to_json

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
        """Run simple YARA-style string/regex rules over a directory. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
