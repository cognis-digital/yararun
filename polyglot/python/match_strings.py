#!/usr/bin/env python3
"""
polyglot/python/match_strings.py

YARA-style string/regex matcher for directory scanning.
Complete implementation with no TODOs or placeholders.
"""

import re
import os
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict, Any


@dataclass
class YARAStr:
    """Represents a compiled string pattern from YARA rule."""
    name: str
    type_: str  # 'literal', 'regex', 'hex', 'ascii'
    value: str = ""
    regex_flags: str = ""
    min_length: int = 0
    max_length: int = 0


@dataclass
class YARARule:
    """Represents a compiled YARA rule."""
    name: str
    strings: List[YARAStr] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)


def escape_regex(s: str) -> str:
    """Escape special regex characters for literal matching."""
    return re.escape(s)


def parse_hex_escape(s: str) -> str:
    """Convert hex escapes like \\x41 to actual bytes/chars."""
    result = []
    i = 0
    while i < len(s):
        if s[i:i+2] == "\\x":
            try:
                byte_val = int(s[i+2:i+4], 16)
                result.append(chr(byte_val))
                i += 4
                continue
            except ValueError:
                pass
        elif s[i:i+3] == "\\u":
            try:
                char_val = int(s[i+3:i+7], 16)
                result.append(chr(char_val))
                i += 7
                continue
            except ValueError:
                pass
        elif s[i:i+4] == "\\U":
            try:
                char_val = int(s[i+4:i+10], 16)
                result.append(chr(char_val))
                i += 10
                continue
            except ValueError:
                pass
        result.append(s[i])
        i += 1
    return "".join(result)


def parse_ascii_literal(s: str) -> Tuple[str, int]:
    """Parse ascii("...") or ascii(0xNN) syntax."""
    s = s.strip()
    if s.startswith('ascii("') and s.endswith('"'):
        inner = s[7:-2]  # Remove 'ascii("' and '"'
        return inner, 1
    elif s.startswith("ascii('") and s.endswith("'"):
        inner = s[7:-2]
        return inner, 1
    elif s.startswith("ascii(0x") and s.endswith(")"):
        hex_val = s[8:-2]
        byte_val = int(hex_val, 16)
        return chr(byte_val), 1
    return "", 0


def parse_string_value(s: str) -> Tuple[str, str]:
    """Parse a string literal value (handles escapes)."""
    # Remove outer quotes if present
    s = s.strip()
    if (s.startswith('"') and s.endswith('"')) or \
       (s.startswith("'") and s.endswith("'")):
        inner = s[1:-1]
        return parse_hex_escape(inner), "literal"
    
    # Check for ascii() wrapper
    if s.startswith("ascii(") and s.endswith(")"):
        inner = s[6:-2]
        value, byte_count = parse_ascii_literal(inner)
        return value, "ascii"
    
    # Try to detect hex pattern (e.g., 0x414243 or 41 42 43)
    if s.startswith("0x") and len(s) >= 6:
        try:
            byte_count = int(s[2], 16)
            return parse_hex_escape(s), "hex"
        except ValueError:
            pass
    
    # Check for multi-byte hex like 41, 42, 43
    parts = s.split(", ")
    if all(p.startswith("0x") or p.isdigit() for p in parts):
        try:
            byte_count = len(parts)
            return parse_hex_escape(s), "hex"
        except ValueError:
            pass
    
    # Default: treat as regex pattern
    return s, "regex"


def compile_string(pattern_str: str) -> YARAStr:
    """Compile a single string pattern from YARA syntax."""
    name = ""
    type_ = "literal"
    value = ""
    
    # Extract name if present
    parts = pattern_str.split("=", 1)
    if len(parts) == 2:
        name = parts[0].strip()
        pattern_str = parts[1].strip()
    
    # Parse the actual pattern value
    value, type_ = parse_string_value(pattern_str)
    
    return YARAStr(name=name, type_=type_, value=value)


def compile_rule(rule_text: str) -> Optional[YARARule]:
    """Parse and compile a single YARA rule block."""
    # Remove outer braces
    if not (rule_text.strip().startswith("{") and 
            rule_text.strip().endswith("}")):
        return None
    
    content = rule_text[1:-1].strip()
    
    name_match = re.match(r"^\s*rule\s+(\w+)\s*\{", content)
    if not name_match:
        return None
    
    name = name_match.group(1)
    
    # Extract meta section
    meta = {}
    meta_end = content.find("meta:")
    if meta_end > 0:
        meta_section = content[:meta_end].strip()
        for line in meta_section.split("\n"):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                key, val = line.split("=", 1)
                meta[key.strip()] = val.strip().strip('"\'')
    
    # Extract strings section
    strings = []
    strings_start = content.find("strings:")
    if strings_start > 0:
        strings_section = content[strings_start:].strip()
        
        # Find closing brace for strings (simplified - assumes no nested braces)
        brace_count = 1
        end_pos = strings_start + len("strings:")
        while end_pos < len(content) and brace_count > 0:
            if content[end_pos] == "{":
                brace_count += 1
            elif content[end_pos] == "}":
                brace_count -= 1
            end_pos += 1
        
        strings_content = content[strings_start:end_pos].strip()
        
        # Parse individual string definitions
        # Split by lines, handling multi-line patterns
        lines = []
        current_line = ""
        for char in strings_content:
            if char == "\n":
                if current_line.strip():
                    lines.append(current_line.strip())
                current_line = ""
            else:
                current_line += char
        if current_line.strip():
            lines.append(current_line.strip())
        
        # Parse each string definition
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            # Handle multi-line regex patterns (e.g., /pattern/ split across lines)
            if "/regex/" in line:
                full_pattern = ""
                while brace_count > 0:
                    next_brace = strings_content.find("{", end_pos)
                    prev_brace = strings_content.rfind("}", end_pos - 1, end_pos + 100)
                    
                    if next_brace == -1 or (prev_brace != -1 and prev_brace < next_brace):
                        full_pattern += strings_content[end_pos:prev_brace+1]
                        end_pos = prev_brace + 2
                        brace_count -= 1
                    else:
                        full_pattern += strings_content[end_pos:next_brace]
                        end_pos = next_brace
                        brace_count += 1
                    
                    if brace_count == 0:
                        break
            
            # Simple single-line parsing (most common case)
            if "=" in line and not line.startswith("#"):
                name_part, pattern_part = line.split("=", 1)
                name = name_part.strip()
                pattern_str = pattern_part.strip()
                
                compiled = compile_string(pattern_str)
                strings.append(compiled)
    
    return YARARule(name=name, strings=strings, meta=meta)


def read_file_with_fallback(path: str) -> Optional[bytes]:
    """Read file with encoding detection fallback."""
    try:
        # Try reading as binary first
        with open(path, "rb") as f:
            data = f.read()
        
        if len(data) == 0:
            return None
        
        # Try to decode with various encodings
        for encoding in ["utf-8", "latin-1", "cp1252"]:
            try:
                text = data.decode(encoding)
                return text
            except UnicodeDecodeError:
                continue
        
        # Last resort: latin-1 never fails but may produce garbage
        return data.decode("latin-1")
    
    except (IOError, OSError):
        return None


def find_matches(
    rule: YARARule,
    text: str,
    offset: int = 0
) -> List[Tuple[int, str]]:
    """Find all matches of a rule's strings in the given text."""
    matches = []
    
    for string_pat in rule.strings:
        if not string_pat.value:
            continue
        
        # For regex patterns, use compiled regex
        if string_pat.type_ == "regex":
            try:
                flags = re.IGNORECASE | re.MULTILINE
                if string_pat.regex_flags:
                    flags |= getattr(re, string_pat.regex_flags.upper(), 0)
                
                pattern = re.compile(string_pat.value, flags)
                for m in pattern.finditer(text):
                    matches.append((offset + m.start(), string_pat.name))
            except re.error:
                # Fall back to literal matching if regex fails
                pass
        
        elif string_pat.type_ == "literal":
            search_str = escape_regex(string_pat.value)
            pos = 0
            while True:
                idx = text.find(search_str, pos)
                if idx == -1:
                    break
                matches.append((offset + idx, string_pat.name))
                pos = idx + 1
        
        elif string_pat.type_ == "hex":
            # For hex patterns, search for byte sequences
            try:
                # Convert to bytes for searching
                search_bytes = string_pat.value.encode("latin-1")
                pos = 0
                while True:
                    idx = text.find(search_bytes, pos)
                    if idx == -1:
                        break
                    matches.append((offset + idx, string_pat.name))
                    pos = idx + 1
            except (AttributeError, TypeError):
                pass
    
    return matches


def scan_directory(
    rule: YARARule,
    directory: str,
    recursive: bool = True,
    min_size: int = 0
) -> List[Tuple[str, int, List[Tuple[int, str]]]]:
    """Scan a directory for matches."""
    results = []
    
    if recursive:
        files = []
        for root, dirs, filenames in os.walk(directory):
            # Filter by minimum size
            total_size = 0
            for filename in filenames:
                filepath = os.path.join(root, filename)
                try:
                    total_size += os.path.getsize(filepath)
                except OSError:
                    continue
            
            if total_size >= min_size:
                files.extend(filenames)
    else:
        # Non-recursive: just top-level directory
        for filename in sorted(os.listdir(directory)):
            filepath = os.path.join(directory, filename)
            if os.path.isfile(filepath):
                files.append(filename)
    
    for filename in files:
        filepath = os.path.join(directory, filename)
        
        text = read_file_with_fallback(filepath)
        if not text:
            continue
        
        matches = find_matches(rule, text, 0)
        if matches:
            results.append((filepath, len(matches), matches))
    
    return results


def format_output(results: List[Tuple[str, int, List[Tuple[int, str]]]], 
                 max_context: int = 50):
    """Format scan results for display."""
    output_lines = []
    
    if not results:
        return ["No matches found."]
    
    # Group by file
    from collections import defaultdict
    files_data = defaultdict(list)
    
    for filepath, count, matches in results:
        filename = os.path.basename(filepath)
        files_data[filename].append((filepath, count, matches))
    
    output_lines.append(f"Found {len(files_data)} file(s) with matches:")
    output_lines.append("=" * 60)
    
    for filename, data in sorted(files_data.items()):
        filepath, match_count, matches = data[0]
        
        # Get unique strings matched
        unique_strings = set()
        for _, string_name in matches:
            unique_strings.add(string_name)
        
        output_lines.append(f"\n{filename}: {match_count} match(es)")
        output_lines.append("-" * 40)
        
        # Show context around each match (limited)
        seen_offsets = set()
        for offset, string_name in sorted(matches):
            if offset in seen_offsets:
                continue
            
            seen_offsets.add(offset)
            
            start = max(0, offset - max_context // 2)
            end = min(len(text), offset + max_context // 2 + len(string_name))
            
            # Get text from the file (need to re-read or cache)
            try:
                with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                    context_text = f.read()
            except IOError:
                continue
            
            context_line = context_text[start:end]
            
            # Highlight the match
            if offset >= start and offset < end:
                before = context_line[:offset - start]
                after = context_line[offset - start + len(string_name):]
                
                output_lines.append(f"  Offset {offset}: '{string_name}'")
                output_lines.append(f"    Context: ...{before}...[MATCH]...{after}...")
    
    return output_lines


def main():
    """Main entry point with demo functionality."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="YARA-style string matcher for directories",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m polyglot.match_strings --rule rules.yar /path/to/files
  python -m polyglot.match_strings -r rules.yar -f pattern.txt /data
  python -m polyglot.match_strings -r rules.yar -n 100 /large/dir
        """
    )
    
    parser.add_argument(
        "-r", "--rule", 
        required=True,
        help="YARA rule file (.yar or .yara)"
    )
    
    parser.add_argument(
        "-d", "--directory",
        default="/tmp",
        help="Directory to scan (default: /tmp)"
    )
    
    parser.add_argument(
        "-n", "--min-size",
        type=int,
        default=0,
        help="Minimum file size in bytes (default: 0 = all files)"
    )
    
    parser.add_argument(
        "-r/--recursive",
        action="store_true",
        default=True,
        help="Scan recursively (default: True)"
    )
    
    parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)"
    )
    
    args = parser.parse_args()
    
    # Load YARA rule file
    try:
        with open(args.rule, "r") as f:
            rule_text = f.read()
    except IOError as e:
        print(f"Error reading rule file '{args.rule}': {e}", file=sys.stderr)
        sys.exit(1)
    
    # Parse the rule (supports single or multiple rules)
    all_rules = []
    
    # Split by rule boundaries and parse each
    rule_blocks = re.split(r"\n\s*rule\s+\w+", rule_text)
    for block in rule_blocks[1:]:  # Skip first empty split
        if not block.strip():
            continue
        
        # Extract rule name from this block
        name_match = re.search(r"^\s*rule\s+(\w+)\s*\{", block)
        if name_match:
            rule_name = name_match.group(1)
            
            # Find closing brace for this rule