"""Tests for the deep-expansion additions:

  * severity helpers (``severity_rank`` / ``severity_at_least``)
  * ``ScanResult.filtered`` min-severity narrowing
  * NDJSON + CSV exporters (``to_ndjson`` / ``to_csv``)
  * filesystem target expansion (``yararun.scanfs.iter_targets``)
  * the new ``scan`` CLI surface: directory/recursive walking, include/exclude
    globs, ``--max-bytes``, ``--min-severity``, ``--stats``, and the ``ndjson`` /
    ``csv`` output formats.

Everything runs fully offline with the standard library plus pytest.
"""
import csv
import io
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from yararun import (  # noqa: E402
    SEVERITY_ORDER,
    WalkStats,
    iter_targets,
    load_rules,
    scan,
    severity_at_least,
    severity_rank,
    to_csv,
    to_ndjson,
)
from yararun.core import CSV_COLUMNS  # noqa: E402
from yararun.cli import main  # noqa: E402


# --------------------------------------------------------------------------- #
# Severity helpers                                                            #
# --------------------------------------------------------------------------- #
def test_severity_rank_orders_critical_highest():
    ranks = [severity_rank(s) for s in SEVERITY_ORDER]
    assert ranks == sorted(ranks)                 # already in descending severity
    assert severity_rank("critical") == 0
    assert severity_rank("info") == len(SEVERITY_ORDER) - 1
    assert severity_rank("critical") < severity_rank("high") < severity_rank("low")


def test_severity_rank_unknown_defaults_to_medium():
    assert severity_rank("bogus") == severity_rank("medium")
    assert severity_rank("") == severity_rank("medium")
    assert severity_rank("HIGH") == severity_rank("high")   # case-insensitive


def test_severity_at_least_boundaries():
    assert severity_at_least("high", "medium") is True
    assert severity_at_least("critical", "critical") is True
    assert severity_at_least("low", "high") is False
    assert severity_at_least("medium", "medium") is True
    assert severity_at_least("info", "low") is False


# --------------------------------------------------------------------------- #
# ScanResult.filtered                                                        #
# --------------------------------------------------------------------------- #
def _rich_blob():
    # fires critical (ransom), high (powershell), and info (PE header)
    return (b"MZ\x90\x00" + b"PE\x00\x00"
            b"All your files have been encrypted! decrypt bitcoin BTC wallet. "
            b"powershell -enc IEX DownloadString FromBase64String")


def test_filtered_drops_below_threshold_without_mutating():
    res = scan(_rich_blob(), load_rules(), target="t.bin")
    sevs = {m.severity for m in res.matches}
    assert "critical" in sevs and "info" in sevs   # precondition: mixed severities
    before = len(res.matches)

    high_only = res.filtered("high")
    assert all(severity_at_least(m.severity, "high") for m in high_only.matches)
    assert not any(m.severity in ("low", "info") for m in high_only.matches)
    # original untouched (pure, non-mutating)
    assert len(res.matches) == before
    # file intelligence preserved verbatim
    assert high_only.entropy == res.entropy
    assert high_only.filetype == res.filetype
    assert high_only.hashes == res.hashes
    assert high_only.size == res.size


def test_filtered_critical_only_keeps_just_ransom():
    res = scan(_rich_blob(), load_rules())
    crit = res.filtered("critical")
    assert crit.matches
    assert {m.severity for m in crit.matches} == {"critical"}


# --------------------------------------------------------------------------- #
# NDJSON exporter                                                            #
# --------------------------------------------------------------------------- #
def test_to_ndjson_one_object_per_result():
    r1 = scan(b"All your files have been encrypted decrypt bitcoin BTC wallet",
              load_rules(), target="a.txt")
    r2 = scan(b"perfectly clean", load_rules(), target="b.txt")
    out = to_ndjson([r1, r2])
    lines = out.splitlines()
    assert len(lines) == 2
    objs = [json.loads(ln) for ln in lines]
    assert objs[0]["target"] == "a.txt" and objs[1]["target"] == "b.txt"
    assert objs[0]["max_severity"] == "critical"
    # compact (no spaces after separators) and deterministic key order
    assert ", " not in lines[0] and '": ' not in lines[0]


def test_to_ndjson_empty_is_empty_string():
    assert to_ndjson([]) == ""


# --------------------------------------------------------------------------- #
# CSV exporter                                                               #
# --------------------------------------------------------------------------- #
def test_to_csv_header_and_row_per_string():
    res = scan(b"xxxxUPX0UPX1UPX! and more", load_rules(), target="p.bin")
    text = to_csv([res])
    rows = list(csv.DictReader(io.StringIO(text)))
    assert rows, "expected at least one CSV row"
    assert list(rows[0].keys()) == CSV_COLUMNS
    upx = [r for r in rows if r["rule"] == "UPX_Packed"]
    assert upx
    for r in upx:
        assert r["target"] == "p.bin"
        assert r["severity"] == "medium"
        assert r["string_id"].startswith("$")
        assert int(r["offset"]) >= 0
        assert int(r["length"]) >= 1


def test_to_csv_clean_file_still_emits_summary_row():
    res = scan(b"nothing here at all", load_rules(), target="clean.txt")
    rows = list(csv.DictReader(io.StringIO(to_csv([res]))))
    assert len(rows) == 1
    assert rows[0]["target"] == "clean.txt"
    assert rows[0]["rule"] == ""            # no match -> blank rule column
    assert rows[0]["sha256"]                # but intel columns populated


def test_to_csv_quotes_commas_in_preview(tmp_path):
    # A preview containing a comma must be RFC-4180 quoted and round-trip.
    res = scan(b"donate-level: 1, stratum+tcp://x xmrig minerd cryptonight",
               load_rules(), target="c.json")
    rows = list(csv.DictReader(io.StringIO(to_csv([res]))))
    assert any("," in r["preview"] for r in rows)   # some preview had a comma


# --------------------------------------------------------------------------- #
# iter_targets — filesystem expansion                                        #
# --------------------------------------------------------------------------- #
@pytest.fixture
def tree(tmp_path):
    (tmp_path / "a.txt").write_text("alpha")
    (tmp_path / "b.log").write_text("bravo")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "c.txt").write_text("charlie")
    (sub / "big.bin").write_bytes(b"X" * 5000)
    deep = sub / "deep"
    deep.mkdir()
    (deep / "d.txt").write_text("delta")
    return tmp_path


def test_iter_targets_recursive_finds_all(tree):
    got = list(iter_targets([str(tree)], recursive=True))
    names = sorted(os.path.basename(p) for p in got)
    assert names == ["a.txt", "b.log", "big.bin", "c.txt", "d.txt"]


def test_iter_targets_non_recursive_top_level_only(tree):
    got = list(iter_targets([str(tree)], recursive=False))
    names = sorted(os.path.basename(p) for p in got)
    assert names == ["a.txt", "b.log"]


def test_iter_targets_include_glob(tree):
    got = list(iter_targets([str(tree)], include=["*.txt"]))
    assert all(p.endswith(".txt") for p in got)
    assert sorted(os.path.basename(p) for p in got) == ["a.txt", "c.txt", "d.txt"]


def test_iter_targets_exclude_wins_over_include(tree):
    got = list(iter_targets([str(tree)], include=["*.txt"], exclude=["c.*"]))
    names = sorted(os.path.basename(p) for p in got)
    assert names == ["a.txt", "d.txt"]           # c.txt excluded despite include


def test_iter_targets_max_bytes_skips_large(tree):
    st = WalkStats()
    got = list(iter_targets([str(tree)], max_bytes=1000, stats=st))
    assert "big.bin" not in [os.path.basename(p) for p in got]
    assert st.skipped_size == 1


def test_iter_targets_stats_counts(tree):
    st = WalkStats()
    list(iter_targets([str(tree)], stats=st))
    assert st.files_yielded == 5
    assert st.dirs_visited == 3                   # root, sub, deep


def test_iter_targets_dedup_and_stdin_passthrough(tree):
    f = str(tree / "a.txt")
    got = list(iter_targets([f, f, "-"]))
    assert got.count(f) == 1                      # de-duplicated
    assert "-" in got                             # stdin sentinel preserved


def test_iter_targets_missing_path_recorded(tmp_path):
    st = WalkStats()
    got = list(iter_targets([str(tmp_path / "nope.bin")], stats=st))
    assert got == []
    assert st.skipped_unreadable == 1


def test_iter_targets_single_file(tree):
    f = str(tree / "b.log")
    assert list(iter_targets([f])) == [f]


# --------------------------------------------------------------------------- #
# CLI: directory scanning + new flags/formats                                #
# --------------------------------------------------------------------------- #
@pytest.fixture
def dirty_dir(tmp_path):
    (tmp_path / "ransom.txt").write_text(
        "All your files have been encrypted! decrypt bitcoin BTC wallet")
    (tmp_path / "clean.txt").write_text("just some ordinary notes")
    sub = tmp_path / "nested"
    sub.mkdir()
    (sub / "ps.txt").write_text(
        "powershell -enc IEX DownloadString FromBase64String")
    return tmp_path


def test_cli_scan_directory_json_is_list(dirty_dir, capsys):
    rc = main(["--format", "json", "scan", str(dirty_dir)])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1                                # findings present
    assert isinstance(payload, list)
    assert len(payload) == 3                      # recursive: 3 files scanned
    targets = {os.path.basename(p["target"]) for p in payload}
    assert {"ransom.txt", "clean.txt", "ps.txt"} == targets


def test_cli_scan_no_recursive(dirty_dir, capsys):
    rc = main(["--format", "json", "scan", "--no-recursive", str(dirty_dir)])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    names = {os.path.basename(p["target"]) for p in payload}
    assert names == {"ransom.txt", "clean.txt"}   # nested/ps.txt excluded


def test_cli_scan_include_glob(dirty_dir, capsys):
    rc = main(["--format", "json", "scan", "--include", "ransom.*",
               str(dirty_dir)])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    # single match -> dict, not list
    assert isinstance(payload, dict)
    assert os.path.basename(payload["target"]) == "ransom.txt"


def test_cli_scan_ndjson_format(dirty_dir, capsys):
    rc = main(["--format", "ndjson", "scan", str(dirty_dir)])
    out = capsys.readouterr().out.strip()
    assert rc == 1
    lines = out.splitlines()
    assert len(lines) == 3
    for ln in lines:
        json.loads(ln)                            # each line is valid JSON


def test_cli_scan_csv_format(dirty_dir, capsys):
    rc = main(["--format", "csv", "scan", str(dirty_dir)])
    out = capsys.readouterr().out
    assert rc == 1
    rows = list(csv.DictReader(io.StringIO(out)))
    assert list(rows[0].keys()) == CSV_COLUMNS
    assert any(r["rule"] == "Ransom_Note" for r in rows)
    assert any(r["rule"] == "Embedded_PowerShell" for r in rows)


def test_cli_scan_min_severity_filters(dirty_dir, capsys):
    rc = main(["--format", "json", "scan", "--min-severity", "critical",
               str(dirty_dir)])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    for entry in payload:
        for m in entry["matches"]:
            assert m["severity"] == "critical"


def test_cli_scan_max_bytes_skips_large(tmp_path, capsys):
    (tmp_path / "small.txt").write_text(
        "All your files have been encrypted decrypt bitcoin BTC wallet")
    (tmp_path / "huge.txt").write_text("bitcoin " * 5000)
    rc = main(["--format", "json", "scan", "--max-bytes", "500", str(tmp_path)])
    payload = json.loads(capsys.readouterr().out)
    names = {os.path.basename(p["target"]) for p in (
        payload if isinstance(payload, list) else [payload])}
    assert "huge.txt" not in names
    assert "small.txt" in names
    assert rc in (0, 1)


def test_cli_scan_stats_to_stderr(dirty_dir, capsys):
    main(["--format", "json", "scan", "--stats", str(dirty_dir)])
    err = capsys.readouterr().err
    assert "scanned 3 file(s)" in err


def test_cli_scan_missing_dir_target_errors(capsys):
    rc = main(["scan", "/definitely/not/here/xyz"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "cannot read" in err


def test_cli_scan_single_file_still_dict(dirty_dir, capsys):
    """Back-compat: a single explicit file yields a JSON object, not a list."""
    rc = main(["--format", "json", "scan", str(dirty_dir / "ransom.txt")])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert isinstance(payload, dict)
    assert payload["max_severity"] == "critical"
