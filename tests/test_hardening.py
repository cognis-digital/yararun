"""Hardening tests: bad input, edge cases, and error-path coverage."""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from yararun.cli import main
from yararun.core import (
    _parse_xor_range,
    parse_rules,
    scan,
    shannon_entropy,
    sniff_filetype,
)


# --------------------------------------------------------------------------- #
# parse_rules error paths                                                      #
# --------------------------------------------------------------------------- #
class ParseRulesErrorTests(unittest.TestCase):
    def test_bad_regex_raises_value_error(self):
        """An invalid regex pattern inside a rule must raise ValueError, not
        re.error, so callers have a single exception type to handle."""
        src = "rule T { strings: $r = /[unclosed/ condition: $r }"
        with self.assertRaises(ValueError) as ctx:
            parse_rules(src)
        self.assertIn("invalid regex", str(ctx.exception).lower())
        self.assertIn("$r", str(ctx.exception))

    def test_non_string_input_raises_value_error(self):
        """Passing a non-string to parse_rules must raise ValueError."""
        for bad in (None, 42, b"rule T { condition: true }"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    parse_rules(bad)

    def test_empty_string_raises_value_error(self):
        """Empty input has no rules and should raise ValueError."""
        with self.assertRaises(ValueError):
            parse_rules("")

    def test_whitespace_only_raises_value_error(self):
        """Whitespace-only input has no rules and should raise ValueError."""
        with self.assertRaises(ValueError):
            parse_rules("   \n\t  ")


# --------------------------------------------------------------------------- #
# XOR range normalisation                                                      #
# --------------------------------------------------------------------------- #
class XorRangeTests(unittest.TestCase):
    def test_inverted_range_normalised(self):
        """xor(0xff-0x01) should be normalised to (1, 255), not (255, 1)."""
        lo, hi = _parse_xor_range("xor(0xff-0x01)")
        self.assertLessEqual(lo, hi)
        self.assertEqual((lo, hi), (1, 255))

    def test_out_of_byte_range_clamped(self):
        """Values outside [0, 255] should be clamped."""
        lo, hi = _parse_xor_range("xor(0x300-0x01)")
        self.assertGreaterEqual(lo, 0)
        self.assertLessEqual(hi, 255)
        self.assertLessEqual(lo, hi)

    def test_bare_xor_defaults_to_full_range(self):
        lo, hi = _parse_xor_range("xor")
        self.assertEqual((lo, hi), (0x00, 0xFF))


# --------------------------------------------------------------------------- #
# CLI error exits                                                              #
# --------------------------------------------------------------------------- #
class CliErrorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.sample = os.path.join(self.tmp, "sample.txt")
        with open(self.sample, "w") as f:
            f.write("hello world\n")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, argv):
        buf_out = io.StringIO()
        buf_err = io.StringIO()
        with redirect_stdout(buf_out), redirect_stderr(buf_err):
            rc = main(argv)
        return rc, buf_out.getvalue(), buf_err.getvalue()

    def test_scan_missing_target_exits_2(self):
        rc, _, err = self._run(["scan", "/no/such/file.bin"])
        self.assertEqual(rc, 2)
        self.assertIn("error", err.lower())

    def test_scan_bad_inline_regex_exits_2(self):
        """Bad regex in -e expression must print a clear message, not a traceback."""
        rc, _, err = self._run([
            "scan", self.sample,
            "-e", "rule T { strings: $r = /[bad/ condition: $r }",
        ])
        self.assertEqual(rc, 2)
        self.assertIn("error", err.lower())
        self.assertIn("regex", err.lower())

    def test_compile_bad_regex_exits_2(self):
        rule_file = os.path.join(self.tmp, "bad.yar")
        with open(rule_file, "w") as f:
            f.write("rule T { strings: $r = /[bad/ condition: $r }\n")
        rc, _, err = self._run(["compile", rule_file])
        self.assertEqual(rc, 2)
        self.assertIn("error", err.lower())

    def test_scan_missing_rules_file_exits_2(self):
        rc, _, err = self._run([
            "scan", self.sample, "-r", "/no/such/rules.yar",
        ])
        self.assertEqual(rc, 2)
        self.assertIn("error", err.lower())

    def test_info_missing_file_exits_2(self):
        rc, _, err = self._run(["info", "/no/such/file.bin"])
        self.assertEqual(rc, 2)
        self.assertIn("error", err.lower())


# --------------------------------------------------------------------------- #
# Edge cases: empty input, empty rules                                         #
# --------------------------------------------------------------------------- #
class EdgeCaseTests(unittest.TestCase):
    def test_scan_empty_bytes(self):
        """scan() on zero-length data must not raise."""
        rules = parse_rules("rule T { condition: true }")
        res = scan(b"", rules, target="<empty>")
        self.assertEqual(res.size, 0)
        self.assertEqual(res.entropy, 0.0)
        self.assertIsInstance(res.filetype, str)

    def test_scan_empty_rules_list(self):
        """scan() with an empty rules list must return a ScanResult with no matches."""
        res = scan(b"hello world", [], target="<test>")
        self.assertEqual(res.matches, [])
        self.assertIsInstance(res.hashes.get("sha256"), str)

    def test_shannon_entropy_empty(self):
        self.assertEqual(shannon_entropy(b""), 0.0)

    def test_sniff_filetype_empty(self):
        ft = sniff_filetype(b"")
        self.assertIsInstance(ft, str)

    def test_scan_to_dict_json_serialisable_no_matches(self):
        res = scan(b"plain text with nothing", [], target="x")
        json.dumps(res.to_dict())  # must not raise


if __name__ == "__main__":
    unittest.main()
