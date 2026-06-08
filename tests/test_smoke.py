"""Smoke tests for YARARUN. Standard library only, no network."""
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from yararun import TOOL_NAME, TOOL_VERSION, parse_rules, scan_path  # noqa: E402
from yararun.cli import main  # noqa: E402
from yararun.core import _eval_condition, _hex_to_regex  # noqa: E402


TEXT_RULE = '''
rule HasSecret {
    meta:
        description = "finds the word secret"
    strings:
        $s = "secret" nocase
    condition:
        $s
}
'''

MULTI_RULE = '''
rule Combo {
    strings:
        $a = "alpha"
        $b = /be+ta/
        $h = { de ad be ef }
    condition:
        $a and ($b or $h)
}
'''


class ParseTests(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "yararun")
        self.assertTrue(TOOL_VERSION)

    def test_parse_text_rule(self):
        rules = parse_rules(TEXT_RULE)
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].name, "HasSecret")
        self.assertEqual(rules[0].meta["description"], "finds the word secret")
        self.assertTrue(rules[0].strings[0].nocase)

    def test_parse_requires_rule(self):
        with self.assertRaises(ValueError):
            parse_rules("not a rule")

    def test_hex_to_regex(self):
        self.assertEqual(_hex_to_regex("4d 5a"), b"\\\x4d\\\x5a")
        self.assertEqual(_hex_to_regex("4d ?? 5a").count(b"."), 1)
        with self.assertRaises(ValueError):
            _hex_to_regex("zz")


class ConditionTests(unittest.TestCase):
    def test_and_or(self):
        names = ["a", "b"]
        self.assertTrue(_eval_condition("$a and $b", {"a": True, "b": True}, names))
        self.assertFalse(_eval_condition("$a and $b", {"a": True, "b": False}, names))
        self.assertTrue(_eval_condition("$a or $b", {"a": False, "b": True}, names))

    def test_of_them(self):
        names = ["a", "b", "c"]
        self.assertTrue(_eval_condition("any of them", {"a": True, "b": False, "c": False}, names))
        self.assertFalse(_eval_condition("all of them", {"a": True, "b": False, "c": False}, names))
        self.assertTrue(_eval_condition("2 of them", {"a": True, "b": True, "c": False}, names))

    def test_not(self):
        names = ["a"]
        self.assertTrue(_eval_condition("not $a", {"a": False}, names))


class ScanTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp()
        with open(os.path.join(self.tmp, "hit.txt"), "w") as f:
            f.write("this has a SECRET inside\n")
        with open(os.path.join(self.tmp, "miss.txt"), "w") as f:
            f.write("nothing interesting here\n")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_scan_finds_match(self):
        rules = parse_rules(TEXT_RULE)
        report = scan_path(self.tmp, rules)
        self.assertEqual(report.files_scanned, 2)
        self.assertEqual(len(report.results), 1)
        self.assertEqual(report.total_matches, 1)
        self.assertEqual(report.results[0].matches[0].rule, "HasSecret")

    def test_combo_rule_hex_and_regex(self):
        rules = parse_rules(MULTI_RULE)
        path = os.path.join(self.tmp, "bin.dat")
        with open(path, "wb") as f:
            f.write(b"alpha beeeta \xde\xad\xbe\xef tail")
        report = scan_path(path, rules)
        self.assertEqual(report.total_matches, 3)

    def test_to_dict_serializable(self):
        rules = parse_rules(TEXT_RULE)
        report = scan_path(self.tmp, rules)
        json.dumps(report.to_dict())  # must not raise


class CliTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self.hit = os.path.join(self.tmp, "a.txt")
        with open(self.hit, "w") as f:
            f.write("a secret value\n")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_cli_findings_exit_code(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["--format", "json", "scan", self.tmp, "-e", TEXT_RULE])
        self.assertEqual(rc, 1)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["total_matches"], 1)

    def test_cli_no_findings_exit_zero(self):
        empty = os.path.join(self.tmp, "clean")
        os.mkdir(empty)
        with open(os.path.join(empty, "c.txt"), "w") as f:
            f.write("harmless\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["scan", empty, "-e", TEXT_RULE])
        self.assertEqual(rc, 0)

    def test_cli_bad_rule_exit_error(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["scan", self.tmp, "-e", "garbage"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
