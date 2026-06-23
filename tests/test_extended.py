"""Extended tests: engine edge cases, file-intel, feeds catalog, air-gap, CLI.

All assertions run fully offline with the standard library (plus pytest). The
feed tests exercise the catalog, cache freshness, and air-gap snapshot logic
without ever touching the network (a monkeypatched `fetch` stands in for HTTP,
and `--offline`/`offline=True` paths never call out at all)."""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from yararun import (  # noqa: E402
    DEFAULT_RULES,
    SEVERITY_ORDER,
    Rule,
    ScanResult,
    file_hashes,
    load_rules,
    match_rule,
    parse_rules,
    scan,
    shannon_entropy,
    sniff_filetype,
    to_sarif,
)
from yararun import core  # noqa: E402
from yararun import datafeeds  # noqa: E402
from yararun.cli import main  # noqa: E402


# --------------------------------------------------------------------------- #
# Entropy / file-intelligence corners                                         #
# --------------------------------------------------------------------------- #
def test_entropy_single_byte_is_zero():
    assert shannon_entropy(b"\x00") == 0.0
    assert shannon_entropy(b"Z") == 0.0


def test_entropy_two_equal_symbols_is_one_bit():
    assert abs(shannon_entropy(b"AB" * 50) - 1.0) < 1e-6


def test_entropy_monotonic_with_diversity():
    low = shannon_entropy(b"AAAAAAAA")
    mid = shannon_entropy(b"ABCD" * 4)
    high = shannon_entropy(bytes(range(256)))
    assert low < mid < high
    assert 0.0 <= low and high <= 8.0


def test_entropy_rounds_to_four_places():
    e = shannon_entropy(b"abcdefg")
    assert round(e, 4) == e


@pytest.mark.parametrize("data,expected", [
    (b"MZ\x90\x00", "pe"),
    (b"\x7fELF\x02\x01", "elf"),
    (b"\xfe\xed\xfa\xce....", "macho"),
    (b"\xfe\xed\xfa\xcf....", "macho"),
    (b"\xca\xfe\xba\xbe....", "macho-fat/java-class"),
    (b"PK\x03\x04zip", "zip/office/jar"),
    (b"%PDF-1.4", "pdf"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"GIF89a", "gif"),
    (b"\xff\xd8\xff\xe0", "jpeg"),
    (b"<?php echo 1;", "php"),
    (b"\x1f\x8b\x08", "gzip"),
    (b"BZh91", "bzip2"),
])
def test_filetype_table(data, expected):
    assert sniff_filetype(data) == expected


def test_filetype_text_vs_data():
    assert sniff_filetype(b"the quick brown fox\n" * 10) == "text"
    assert sniff_filetype(bytes(range(256))) == "data"
    assert sniff_filetype(b"") == "data"


def test_hashes_empty_and_known():
    h = file_hashes(b"")
    assert h["md5"] == "d41d8cd98f00b204e9800998ecf8427e"
    assert h["sha1"] == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    assert h["sha256"] == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    abc = file_hashes(b"abc")
    assert abc["sha1"] == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert len(abc["md5"]) == 32 and len(abc["sha256"]) == 64


# --------------------------------------------------------------------------- #
# Parser / rule-model behaviours                                              #
# --------------------------------------------------------------------------- #
def test_default_pack_rule_count_and_severities():
    rules = load_rules()
    assert len(rules) >= 17
    sevs = {r.severity() for r in rules}
    assert sevs <= set(SEVERITY_ORDER)
    assert "critical" in sevs and "info" in sevs
    # Ransom_Note must be critical; PE_Executable info.
    by_name = {r.name: r for r in rules}
    assert by_name["Ransom_Note"].severity() == "critical"
    assert by_name["PE_Executable"].severity() == "info"


def test_tags_parsed():
    r = parse_rules("rule X : trojan apt evasion { condition: true }")[0]
    assert r.tags == ["trojan", "apt", "evasion"]


def test_meta_typing():
    src = '''rule M {
        meta:
            author = "alice"
            severity = "high"
            confidence = 80
            stable = true
        condition:
            true
    }'''
    r = parse_rules(src)[0]
    assert r.meta["author"] == "alice"
    assert r.meta["confidence"] == 80
    assert r.meta["stable"] is True
    assert r.severity() == "high"


def test_comments_stripped():
    src = '''
    // a line comment
    rule C {
        /* block
           comment */
        strings:
            $a = "needle"   // trailing comment
        condition:
            $a
    }'''
    r = parse_rules(src)[0]
    assert "needle" in [sd.raw for sd in r.strings.values()][0]
    assert scan(b"has a needle here", [r]).matches


def test_unknown_severity_defaults_medium():
    r = parse_rules('rule Z { meta: severity = "bogus" condition: true }')[0]
    assert r.severity() == "medium"


def test_anonymous_string_ids():
    src = '''rule A {
        strings:
            $ = "foo"
            $ = "bar"
        condition:
            all of them
    }'''
    r = parse_rules(src)[0]
    assert len(r.strings) == 2
    assert scan(b"foo and bar", [r]).matches
    assert not scan(b"only foo", [r]).matches


def test_multiple_rules_in_one_source():
    src = (
        'rule One { strings: $a = "aaa" condition: $a }\n'
        'rule Two { strings: $b = "bbb" condition: $b }\n'
        'rule Three { condition: filesize > 0 }'
    )
    rules = parse_rules(src)
    assert [r.name for r in rules] == ["One", "Two", "Three"]


# --------------------------------------------------------------------------- #
# String-kind matching edge cases                                            #
# --------------------------------------------------------------------------- #
def test_wide_string_modifier():
    r = parse_rules('rule W { strings: $a = "MZ" wide condition: $a }')[0]
    wide = b"M\x00Z\x00"
    assert scan(wide, [r]).matches
    assert not scan(b"MZ", [r]).matches  # ascii form not matched by `wide`-only


def test_nocase_modifier():
    r = parse_rules('rule N { strings: $a = "EvIl" nocase condition: $a }')[0]
    assert scan(b"this is EVIL", [r]).matches
    assert scan(b"this is evil", [r]).matches
    assert not scan(b"benign", [r]).matches


def test_hex_exact_and_wildcard():
    r = parse_rules('rule H { strings: $h = { DE AD ?? EF } condition: $h }')[0]
    assert scan(b"\xde\xad\x00\xef", [r]).matches
    assert scan(b"\xde\xad\xff\xef", [r]).matches
    assert not scan(b"\xde\xad\xef", [r]).matches


def test_hex_jump_range():
    r = parse_rules('rule J { strings: $h = { 01 02 [2-3] 09 } condition: $h }')[0]
    assert scan(b"\x01\x02\xaa\xbb\x09", [r]).matches      # gap 2
    assert scan(b"\x01\x02\xaa\xbb\xcc\x09", [r]).matches  # gap 3
    assert not scan(b"\x01\x02\xaa\x09", [r]).matches        # gap 1 < 2


def test_regex_string_basic():
    r = parse_rules(r'rule R { strings: $r = /c2-[0-9]{3}/ condition: $r }')[0]
    assert scan(b"beacon c2-007 active", [r]).matches
    assert not scan(b"beacon c2-x active", [r]).matches


def test_xor_modifier_default_range():
    r = parse_rules('rule X { strings: $s = "evilcfg" xor condition: $s }')[0]
    enc = bytes(b ^ 0x5A for b in b"evilcfg")
    assert scan(b"...." + enc + b"....", [r]).matches


def test_count_operator():
    r = parse_rules('rule C { strings: $a = "ping" condition: #a == 3 }')[0]
    assert scan(b"ping ping ping", [r]).matches
    assert not scan(b"ping ping", [r]).matches


def test_in_range_anchor():
    r = parse_rules('rule I { strings: $a = "key" condition: $a in (0..8) }')[0]
    assert scan(b"the key here", [r]).matches            # offset 4
    assert not scan(b"x" * 20 + b"key", [r]).matches       # offset 20 outside


def test_uint_be_and_le():
    r = parse_rules('rule U { condition: uint16be(0) == 0x4D5A }')[0]
    assert scan(b"MZxx", [r]).matches      # big-endian 0x4D5A
    assert not scan(b"ZMxx", [r]).matches


def test_filesize_units():
    r = parse_rules('rule F { condition: filesize >= 1KB and filesize < 1MB }')[0]
    assert scan(b"A" * 2048, [r]).matches
    assert not scan(b"A" * 10, [r]).matches


def test_all_any_of_them():
    src = '''rule Q {
        strings:
            $a = "x1"
            $b = "x2"
            $c = "x3"
        condition:
            all of them
    }'''
    r = parse_rules(src)[0]
    assert scan(b"x1 x2 x3", [r]).matches
    assert not scan(b"x1 x2", [r]).matches


def test_not_and_or_precedence():
    src = '''rule P {
        strings:
            $a = "alpha"
            $b = "beta"
        condition:
            $a and not $b
    }'''
    r = parse_rules(src)[0]
    assert scan(b"alpha only", [r]).matches
    assert not scan(b"alpha beta", [r]).matches


# --------------------------------------------------------------------------- #
# ScanResult API                                                             #
# --------------------------------------------------------------------------- #
def test_scanresult_counts_and_maxseverity():
    blob = (b"All your files have been encrypted! decrypt bitcoin BTC wallet "
            b"powershell -enc IEX DownloadString FromBase64String")
    res = scan(blob, load_rules(), target="t.bin")
    assert isinstance(res, ScanResult)
    assert res.max_severity == "critical"
    c = res.counts()
    assert set(c.keys()) == set(SEVERITY_ORDER)
    assert sum(c.values()) == len(res.matches)
    d = res.to_dict()
    assert d["target"] == "t.bin"
    assert d["match_count"] == len(res.matches)
    assert "sha256" in d["hashes"]


def test_scan_no_hashes_flag():
    res = scan(b"clean", load_rules(), hashes=False)
    assert res.hashes == {}
    assert res.max_severity == "info"


def test_matches_sorted_by_severity():
    blob = (b"All your files have been encrypted! decrypt bitcoin BTC wallet "
            b"powershell -enc IEX DownloadString FromBase64String MZ")
    res = scan(blob, load_rules())
    idxs = [SEVERITY_ORDER.index(m.severity) for m in res.matches]
    assert idxs == sorted(idxs)  # critical(0) first ... info last


def test_match_rule_returns_none_on_miss():
    r = parse_rules('rule M { strings: $a = "absent" condition: $a }')[0]
    assert match_rule(r, b"nothing here") is None


def test_bad_condition_is_safe():
    # A nonsensical condition must not raise — it just fails to match.
    r = Rule("Bad", [], {}, {}, "this is ((( not valid")
    assert match_rule(r, b"data") is None


# --------------------------------------------------------------------------- #
# SARIF export details                                                       #
# --------------------------------------------------------------------------- #
def test_sarif_empty_run_is_valid():
    res = scan(b"perfectly clean text", load_rules(), target="ok.txt")
    log = to_sarif([res])
    assert log["version"] == "2.1.0"
    run = log["runs"][0]
    assert run["tool"]["driver"]["rules"] == []
    assert run["results"] == []


def test_sarif_security_severity_mapping():
    blob = b"powershell -enc IEX DownloadString FromBase64String"
    log = to_sarif([scan(blob, load_rules())])
    descs = {d["id"]: d for d in log["runs"][0]["tool"]["driver"]["rules"]}
    ps = descs["Embedded_PowerShell"]
    assert ps["properties"]["security-severity"] == "8.0"  # high
    assert ps["defaultConfiguration"]["level"] == "error"


def test_sarif_region_byteoffset():
    blob = b"xxxxUPX0UPX1UPX!"
    log = to_sarif([scan(blob, load_rules(), target="p.bin")])
    upx = [r for r in log["runs"][0]["results"] if r["ruleId"] == "UPX_Packed"]
    assert upx
    region = upx[0]["locations"][0]["physicalLocation"]["region"]
    assert region["byteOffset"] >= 0 and region["byteLength"] >= 1


# --------------------------------------------------------------------------- #
# CLI behaviours not covered elsewhere                                       #
# --------------------------------------------------------------------------- #
def test_cli_rules_table(capsys):
    rc = main(["rules"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "YARARUN rules" in out
    assert "Ransom_Note" in out


def test_cli_info_table(tmp_path, capsys):
    f = tmp_path / "f.bin"
    f.write_bytes(b"MZ\x90\x00hello")
    rc = main(["info", str(f)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "type    : pe" in out
    assert "sha256" in out


def test_cli_scan_table_clean(tmp_path, capsys):
    f = tmp_path / "c.txt"
    f.write_text("nothing to see")
    rc = main(["scan", str(f)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "No rules matched." in out
    assert "Max severity   : INFO" in out


def test_cli_scan_stdin(monkeypatch, capsys):
    import io
    data = b"powershell -enc IEX DownloadString FromBase64String"
    monkeypatch.setattr("sys.stdin", type("S", (), {"buffer": io.BytesIO(data)})())
    rc = main(["--format", "json", "scan", "-"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 1
    assert payload["target"] == "-"
    assert any(m["rule"] == "Embedded_PowerShell" for m in payload["matches"])


def test_cli_scan_missing_file_errors(capsys):
    rc = main(["scan", "/no/such/file/at/all.bin"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "cannot read" in err


def test_cli_compile_json(tmp_path, capsys):
    rf = tmp_path / "r.yar"
    rf.write_text('rule A { condition: true }\nrule B { condition: filesize > 0 }')
    rc = main(["--format", "json", "compile", str(rf)])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert data["ok"] is True and data["rule_count"] == 2


def test_cli_multi_target_json(tmp_path, capsys):
    a = tmp_path / "a.txt"; a.write_text("bitcoin your files have been encrypted decrypt BTC wallet")
    b = tmp_path / "b.txt"; b.write_text("totally fine")
    rc = main(["--format", "json", "scan", str(a), str(b)])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 1
    assert isinstance(payload, list) and len(payload) == 2


# --------------------------------------------------------------------------- #
# Edge / air-gap data feeds — fully offline                                  #
# --------------------------------------------------------------------------- #
@pytest.fixture
def feed_cache(tmp_path, monkeypatch):
    """Isolate the feed cache under tmp so no real cache is touched."""
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path / "fcache"))
    return tmp_path


def test_catalog_ships_and_parses():
    cat = datafeeds.load_catalog()
    feeds = cat["feeds"]
    assert len(feeds) >= 25
    ids = {f["id"] for f in feeds}
    # Real, keyless feeds a triage tool enriches against.
    assert {"osv", "cisa-kev", "epss", "feodo-c2", "threatfox", "urlhaus"} <= ids
    for f in feeds:
        assert f["url"].startswith(("http://", "https://"))
        assert "name" in f and "domain" in f


def test_list_feeds_filtered():
    vuln = datafeeds.list_feeds(domain="vuln")
    ti = datafeeds.list_feeds(domain="threat-intel")
    assert all(f["domain"] == "vuln" for f in vuln)
    assert all(f["domain"] == "threat-intel" for f in ti)
    assert len(vuln) >= 3 and len(ti) >= 3


def test_feeds_are_keyless_for_offline():
    # Every threat-intel/vuln feed we lean on should be fetchable without a key.
    for f in datafeeds.list_feeds(domain="threat-intel"):
        assert f.get("keyless", False) is True


def test_update_and_get_offline_roundtrip(feed_cache, monkeypatch):
    # Stand in for the network: `fetch` returns a fixed JSON blob.
    payload = b'{"vulns": [{"id": "OSV-FIXTURE-1"}]}'
    monkeypatch.setattr(datafeeds, "fetch", lambda *a, **k: payload)
    path = datafeeds.update("osv")
    assert path.exists()
    assert datafeeds.cached_age_hours("osv") is not None
    # offline get must NOT call fetch (would raise if it did)
    monkeypatch.setattr(datafeeds, "fetch",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("network!")))
    data = datafeeds.get("osv", offline=True)
    assert data["vulns"][0]["id"] == "OSV-FIXTURE-1"


def test_get_offline_without_cache_raises(feed_cache):
    with pytest.raises(FileNotFoundError):
        datafeeds.get("epss", offline=True)


def test_update_unknown_feed_raises(feed_cache):
    with pytest.raises(KeyError):
        datafeeds.update("does-not-exist")


def test_snapshot_export_import_airgap(feed_cache, tmp_path, monkeypatch):
    monkeypatch.setattr(datafeeds, "fetch", lambda *a, **k: b'{"ok": true}')
    datafeeds.update("cisa-kev")
    snap = tmp_path / "feeds.tar.gz"
    n = datafeeds.snapshot_export(str(snap))
    assert n >= 1 and snap.exists()
    # Wipe the cache, then import the snapshot into a *different* cache dir.
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path / "airgap"))
    assert datafeeds.cached_age_hours("cisa-kev") is None  # fresh empty cache
    imported = datafeeds.snapshot_import(str(snap))
    assert imported >= 1
    data = datafeeds.get("cisa-kev", offline=True)
    assert data == {"ok": True}


def test_cli_feeds_list_offline(capsys):
    rc = main(["feeds", "list", "--domain", "vuln"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "feed catalog" in out
    assert "osv" in out or "cisa-kev" in out


def test_cli_feeds_list_json(capsys):
    rc = main(["--format", "json", "feeds", "list"])
    out = capsys.readouterr().out
    assert rc == 0
    feeds = json.loads(out)
    assert isinstance(feeds, list) and len(feeds) >= 25


def test_cli_feeds_get_offline_missing(feed_cache, capsys):
    rc = main(["feeds", "get", "epss", "--offline"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "nothing cached" in err or "offline" in err
