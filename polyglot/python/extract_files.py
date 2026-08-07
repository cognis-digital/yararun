#!/usr/bin/env python3
"""
yararun - YARA-style string/regex rule runner for directory scanning.

Extracts and matches strings against regex patterns defined in simple rules.
Designed to be fast, memory-efficient, and robust against malformed input.
"""

import argparse
import fnmatch
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional


@dataclass(frozen=True)
class Rule:
    """Represents a single YARA-style rule."""
    name: str
    pattern: re.Pattern
    flags: int = 0
    
    def __init__(self, name: str, pattern_str: str, flags: int = 0):
        self.name = name
        try:
            self.pattern = re.compile(pattern_str, flags)
        except re.error as e:
            raise ValueError(f"Invalid regex in rule '{name}': {e}") from e


class RuleCompiler:
    """Compiles YARA-style rules from text."""
    
    # Default flags for case-insensitive matching (common in YARA)
    DEFAULT_FLAGS = re.IGNORECASE | re.MULTILINE
    
    @classmethod
    def compile_rules(cls, rule_text: str, default_flags: int = 0) -> list[Rule]:
        """
        Parse a multi-line string of rules.
        
        Expected format (YARA-style):
            RULE_NAME: regex_pattern
        
        Lines starting with # are comments.
        Empty lines are ignored.
        Whitespace around the colon is trimmed.
        """
        if not rule_text.strip():
            return []
        
        flags = default_flags | cls.DEFAULT_FLAGS
        rules = []
        
        for line in rule_text.splitlines():
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Find the first colon to split name from pattern
            colon_idx = line.find(':')
            if colon_idx == -1:
                # No colon found, treat entire line as pattern with default name
                rule_name = f"unnamed_{len(rules)}"
                pattern_str = line.strip()
            else:
                rule_name = line[:colon_idx].strip()
                pattern_str = line[colon_idx + 1:].strip()
            
            if not rule_name:
                continue
            
            rules.append(Rule(rule_name, pattern_str, flags))
        
        return rules


class FileScanner:
    """Scans directories for files matching patterns."""
    
    def __init__(self, base_path: Path):
        self.base = base_path.resolve()
    
    def include_patterns(self) -> list[str]:
        """Return glob patterns to INCLUDE (default: all)."""
        return ["*"]  # Include everything by default
    
    def exclude_patterns(self) -> list[str]:
        """Return glob patterns to EXCLUDE."""
        return [".git", ".svn", "__pycache__", "*.pyc", "node_modules"]
    
    def _matches_any(self, path: Path, patterns: list[str]) -> bool:
        """Check if path matches any of the given glob patterns."""
        for pattern in patterns:
            if fnmatch.fnmatch(path.name, pattern):
                return True
        return False
    
    def get_files(self) -> Iterable[Path]:
        """Yield all regular files, filtered by include/exclude patterns."""
        includes = self.include_patterns()
        excludes = self.exclude_patterns()
        
        for root, dirs, files in os.walk(self.base):
            # Filter directories to avoid descending into excluded ones
            dirs[:] = [d for d in dirs if not self._matches_any(Path(d), excludes)]
            
            for name in files:
                path = Path(root) / name
                
                # Apply include filter first (if no includes specified, skip this check)
                if includes and not any(fnmatch.fnmatch(name, inc) for inc in includes):
                    continue
                
                # Apply exclude filter
                if self._matches_any(path, excludes):
                    continue
                
                yield path


class Extractor:
    """Extracts matching content from files with context."""
    
    DEFAULT_LINE_WIDTH = 80
    
    def __init__(self, rule: Rule, line_context: int = 2, 
                 max_matches_per_file: int = 100):
        self.rule = rule
        self.line_context = line_context
        self.max_matches_per_file = max_matches_per_file
    
    def extract(self, content: str) -> list[tuple[int, int, str]]:
        """
        Extract all matches with context.
        
        Returns list of tuples: (start_line, end_line, matched_text)
        where lines are 1-indexed for user-friendly output.
        """
        if not content:
            return []
        
        results = []
        line_width = self.rule.pattern.line_width or self.DEFAULT_LINE_WIDTH
        
        # Find all matches with their positions
        for match in self.rule.pattern.finditer(content):
            start_pos, end_pos = match.span()
            
            # Convert byte positions to approximate line numbers
            content_before = content[:start_pos]
            start_line = content_before.count('\n') + 1
            
            # Extend context boundaries
            context_start = max(0, start_pos - (self.line_context * line_width))
            context_end = min(len(content), end_pos + (self.line_context * line_width))
            
            context_text = content[context_start:context_end]
            
            results.append((start_line, match.end(), context_text))
        
        return results


class YaraRunner:
    """Main orchestrator for running YARA-style rules."""
    
    def __init__(self, base_path: Path):
        self.base = base_path.resolve()
        self.rules: list[Rule] = []
        self.scanner = FileScanner(base_path)
    
    def add_rule(self, rule_text: str, default_flags: int = 0) -> None:
        """Add a rule from text."""
        compiled = RuleCompiler.compile_rules(rule_text, default_flags)
        self.rules.extend(compiled)
    
    def load_rules_from_file(self, path: Path) -> None:
        """Load rules from a file containing rule definitions."""
        if not path.is_file():
            raise FileNotFoundError(f"Rules file not found: {path}")
        
        with open(path, 'r', encoding='utf-8') as f:
            self.add_rule(f.read())
    
    def run(self) -> list[tuple[Rule, str]]:
        """
        Run all rules against all files.
        
        Returns list of (rule, extracted_content) tuples.
        Empty content means no matches found.
        """
        results = []
        scanner = self.scanner
        
        for file_path in scanner.get_files():
            try:
                # Read file with fallback encoding
                encodings = ['utf-8', 'latin-1', 'cp1252']
                content = None
                
                for enc in encodings:
                    try:
                        with open(file_path, 'r', encoding=enc) as f:
                            content = f.read()
                            break
                    except UnicodeDecodeError:
                        continue
                
                if content is None:
                    # Binary file or all encodings failed
                    continue
                
            except (IOError, OSError):
                continue
            
            for rule in self.rules:
                extractor = Extractor(rule)
                
                matches = extractor.extract(content)
                
                if matches:
                    results.append((rule, content))
                    
                    # Limit output size per file to prevent memory issues
                    total_matches = sum(len(m[2]) for m in matches)
                    if total_matches > 100 * 1024:  # ~100KB threshold
                        break
        
        return results


def format_output(results: list[tuple[Rule, str]], 
                 max_lines_per_rule: int = 50) -> str:
    """Format extraction results for display."""
    output_parts = []
    
    for rule, content in results:
        extractor = Extractor(rule, line_context=2)
        matches = extractor.extract(content)
        
        if not matches:
            continue
        
        header = f"\n{'='*60}\n"
        header += f"Rule: {rule.name}\n"
        header += f"Matches found: {len(matches)}\n"
        header += f"{'='*60}\n\n"
        
        output_parts.append(header)
        
        # Group matches by file (already grouped in results)
        for i, (start_line, end_pos, context) in enumerate(matches):
            if i >= max_lines_per_rule:
                break
            
            line_start = content[:end_pos].count('\n') + 1
            output_parts.append(f"  Match {i+1}: lines ~{line_start}+")
            
            # Truncate long contexts for readability
            display_context = context
            if len(display_context) > 500:
                display_context = display_context[:250] + "..." + display_context[-250:]
            
            output_parts.append(f"    {repr(display_context)}")
    
    return ''.join(output_parts).rstrip()


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Run YARA-style rules over a directory and extract matches."
    )
    parser.add_argument("path", nargs="?", default=".", 
                       help="Directory to scan (default: current)")
    parser.add_argument("-r", "--rules", dest="rule_file",
                       help="Path to file containing rule definitions")
    parser.add_argument("-e", "--extract", action="store_true",
                       help="Extract and display matching content")
    parser.add_argument("-q", "--quiet", action="store_true",
                       help="Suppress output, return exit code only")
    parser.add_argument("--include", action="append", default=["*"],
                       help="Glob patterns to include (default: *)")
    parser.add_argument("--exclude", action="append", 
                       help="Glob patterns to exclude from scan")
    
    args = parser.parse_args()
    
    base_path = Path(args.path)
    if not base_path.is_dir():
        print(f"Error: Not a directory: {base_path}", file=sys.stderr)
        sys.exit(1)
    
    runner = YaraRunner(base_path)
    
    # Load rules from file if specified
    if args.rule_file:
        try:
            runner.load_rules_from_file(Path(args.rule_file))
        except FileNotFoundError as e:
            print(f"Error loading rules: {e}", file=sys.stderr)
            sys.exit(1)
        except ValueError as e:
            print(f"Error parsing rules: {e}", file=sys.stderr)
            sys.exit(1)
    
    # If no rules loaded, add a default "find all text" rule
    if not runner.rules:
        runner.add_rule(r"(?s)(?:[a-zA-Z0-9_]+[:=].*|\".*?\"|'.*?')")
    
    results = runner.run()
    
    # Output results or exit code
    if args.quiet:
        sys.exit(1 if results else 0)
    
    output = format_output(results)
    print(output)


if __name__ == "__main__":
    main()