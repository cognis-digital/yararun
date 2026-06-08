"""YARARUN - lightweight YARA-style string/regex rule hunting over a directory.

Defensive/authorized-testing use only: analysis, triage, and detection.
This tool only READS files and reports matches; it performs no modification,
exfiltration, or attack capability.
"""
from .core import (
    Rule,
    StringDef,
    Match,
    FileResult,
    ScanReport,
    parse_rules,
    parse_rules_file,
    scan_path,
)

TOOL_NAME = "yararun"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Rule",
    "StringDef",
    "Match",
    "FileResult",
    "ScanReport",
    "parse_rules",
    "parse_rules_file",
    "scan_path",
    "TOOL_NAME",
    "TOOL_VERSION",
]
