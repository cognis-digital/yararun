"""Smoke tests for YARARUN. Standard library only, no network."""
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from yararun import TOOL_NAME, TOOL_VERSION, parse_rules, scan  # noqa: E402
from yararun.cli import main  # noqa: E402


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
        # $s is a text string with nocase — verify the regex is case-insensitive
        sd = rules[0].strings["$s"]
        self.assertTrue(sd.regex.flags & __import__("re").IGNORECASE)

    def test_parse_requires_rule(self):
        with self.assertRaises(ValueError):
            parse_rules("not a rule")

    def test_hex_rule_compiles(self):
        # Verify hex strings compile without error
        rules = parse_rules(MULTI_RULE)
        self.assertEqual(len(rules), 1)
        self.assertIn("$h", rules[0].strings)
        self.assertEqual(rules[0].strings["$h"].kind, "hex")


class ConditionTests(unittest.TestCase):
    """Test the condition evaluator via full rule round-trips."""

    def _mk_rule(self, condition: str, string_bodies: dict[str, str] = None) -> object:
        """Build a minimal Rule object by parsing a synthetic source."""
        parts = []
        if string_bodies:
            parts.append("strings:")
            for k, v in string_bodies.items():
                parts.append(f'    {k} = "{v}"')
        parts.append(f"condition:\n    {condition}")
        body = "\n".join(parts)
        src = f"rule T {{\n{body}\n}}"
        return parse_rules(src)[0]

    def test_and_or(self):
        from yararun.core import match_rule
        r_and = self._mk_rule("$a and $b",
                               {"$a": "alpha", "$b": "beta"})
        self.assertIsNotNone(match_rule(r_and, b"alpha beta"))
        self.assertIsNone(match_rule(r_and, b"alpha only"))

        r_or = self._mk_rule("$a or $b",
                              {"$a": "alpha", "$b": "beta"})
        self.assertIsNotNone(match_rule(r_or, b"only beta"))

    def test_of_them(self):
        from yararun.core import match_rule
        r = self._mk_rule("any of them",
                          {"$a": "alpha", "$b": "beta", "$c": "charlie"})
        self.assertIsNotNone(match_rule(r, b"alpha only"))
        self.assertIsNone(match_rule(r, b"nothing here"))

        r2 = self._mk_rule("2 of them",
                           {"$a": "alpha", "$b": "beta", "$c": "charlie"})
        self.assertIsNotNone(match_rule(r2, b"alpha beta"))
        self.assertIsNone(match_rule(r2, b"alpha only"))

    def test_not(self):
        from yararun.core import match_rule
        r = self._mk_rule("not $a", {"$a": "alpha"})
        self.assertIsNotNone(match_rule(r, b"no match here"))
        self.assertIsNone(match_rule(r, b"alpha present"))


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
        # scan individual files
        hit_data = open(os.path.join(self.tmp, "hit.txt"), "rb").read()
        miss_data = open(os.path.join(self.tmp, "miss.txt"), "rb").read()
        hit_res = scan(hit_data, rules, target="hit.txt")
        miss_res = scan(miss_data, rules, target="miss.txt")
        self.assertTrue(hit_res.matches)
        self.assertFalse(miss_res.matches)
        self.assertEqual(hit_res.matches[0].rule, "HasSecret")

    def test_combo_rule_hex_and_regex(self):
        rules = parse_rules(MULTI_RULE)
        data = b"alpha beeeta \xde\xad\xbe\xef tail"
        res = scan(data, rules)
        self.assertTrue(res.matches)

    def test_to_dict_serializable(self):
        rules = parse_rules(TEXT_RULE)
        data = open(os.path.join(self.tmp, "hit.txt"), "rb").read()
        res = scan(data, rules, target="hit.txt")
        json.dumps(res.to_dict())  # must not raise

    def test_scan_result_has_entropy_filetype_hashes(self):
        rules = parse_rules(TEXT_RULE)
        data = b"this has a SECRET inside"
        res = scan(data, rules, target="<test>")
        self.assertIsInstance(res.entropy, float)
        self.assertIsInstance(res.filetype, str)
        self.assertIn("sha256", res.hashes)
        self.assertEqual(len(res.hashes["sha256"]), 64)


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
            rc = main(["--format", "json", "scan", self.hit, "-e", TEXT_RULE])
        self.assertEqual(rc, 1)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["match_count"], 1)

    def test_cli_no_findings_exit_zero(self):
        empty = os.path.join(self.tmp, "clean")
        os.mkdir(empty)
        clean_file = os.path.join(empty, "c.txt")
        with open(clean_file, "w") as f:
            f.write("harmless\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["scan", clean_file, "-e", TEXT_RULE])
        self.assertEqual(rc, 0)

    def test_cli_bad_rule_exit_error(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["scan", self.hit, "-e", "garbage"])
        self.assertEqual(rc, 2)

    def test_cli_info_subcommand(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["--format", "json", "info", self.hit])
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertIn("filetype", data)
        self.assertIn("entropy", data)
        self.assertIn("sha256", data["hashes"])


if __name__ == "__main__":
    unittest.main()
