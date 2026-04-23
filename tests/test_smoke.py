"""Smoke tests for YARARUN."""
from yararun.core import scan, TOOL_NAME, TOOL_VERSION

def test_identity():
    assert TOOL_NAME and TOOL_VERSION

def test_scan_runs(tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("a TODO here\nFIXME later\n")
    res = scan(str(tmp_path))
    assert res.score >= 0
    assert any("TODO" in fi.title or "FIXME" in fi.title for fi in res.findings)

def test_cli_importable():
    from yararun.cli import main
    assert callable(main)
