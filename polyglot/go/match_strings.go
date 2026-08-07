package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Rule represents a compiled YARA-style rule
type Rule struct {
	Name        string
	Type        string // "string", "regex"
	Pattern     string
	CaseSensitive bool
	Compiled    interface{} // *regexp.Regexp or just the pattern for strings
	Description string
}

// MatchResult captures a single match found in a file
type MatchResult struct {
	RuleName   string      `json:"rule_name"`
	File       string      `json:"file"`
	Offset     int64       `json:"offset"`
	Line       int         `json:"line"`
	Column     int         `json:"column"`
	Type       string      `json:"type"`
	Pattern    string      `json:"pattern"`
	Context    string      `json:"context,omitempty"` // 10 chars before/after
	Timestamp  time.Time   `json:"timestamp"`
}

// ScanResult aggregates all matches for a single file
type ScanResult struct {
	File       string        `json:"file"`
	Matches    []MatchResult `json:"matches"`
	DurationMs int64         `json:"duration_ms"`
	Rules      []string       `json:"rules_used"`
}

// Config holds command-line configuration
type Config struct {
	InputDir     string
	RulesFile    string
	OutputFormat string // "text", "json"
	MaxFiles     int
	MinSize      int64
	MaxSize      int64
	Threads      int
	CaseSensitive bool
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		InputDir:    ".",
		RulesFile:   "",
		OutputFormat: "text",
		MaxFiles:    0, // unlimited
		MinSize:     0, // no minimum
		MaxSize:     0, // no maximum
		Threads:     1,
		CaseSensitive: true,
	}
}

// RuleSet holds all parsed rules
type RuleSet struct {
	Rules []Rule
}

// ParseRules reads and parses a YARA-style rules file
func (rs *RuleSet) ParseRules(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("opening rules file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var current Rule
	current.Name = ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "//") || 
		   strings.HasPrefix(line, "#") || strings.Contains(line, "/*") {
			continue
		}

		// Parse rule definition: name [type] "pattern" [description]
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		current.Name = parts[0]
		
		// Determine type and pattern
		var typ, pat string
		if len(parts) >= 4 && (parts[1] == "string" || parts[1] == "regex") {
			typ = parts[1]
			pat = strings.Join(parts[2:], "")
		} else if len(parts) >= 3 && parts[0] != current.Name {
			// Fallback: assume first part is name, second is type/pattern combo
			typ = "string"
			pat = strings.Join(parts[1:], "")
		} else {
			continue // Skip malformed lines
		}

		current.Type = typ
		current.Pattern = pat
		
		// Compile based on type
		if typ == "regex" {
			var flags = 0
			if !current.CaseSensitive {
				flags |= regexp.IgnoreCase
			}
			re, err := regexp.Compile(flags|regexp.unicode)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: invalid regex in rule %q: %v\n", current.Name, err)
				continue
			}
			current.Compiled = re
		} else if typ == "string" || typ == "" {
			// String matching - use simple byte search
			current.Compiled = pat
		}

		rs.Rules = append(rs.Rules, current)
	}

	return scanner.Err()
}

// FileScanner handles reading files with size limits
type FileScanner struct {
	minSize int64
	maxSize int64
}

func (fs *FileScanner) Open(filename string) (*bufio.Reader, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}

	if info.Size() < fs.minSize || (fs.maxSize > 0 && info.Size() > fs.maxSize) {
		f.Close()
		return nil, fmt.Errorf("size %d not in range [%d, %d]", 
			info.Size(), fs.minSize, fs.maxSize)
	}

	reader := bufio.NewReader(f)
	return reader, nil
}

func (fs *FileScanner) Close(reader *bufio.Reader) {
	if reader != nil && !reader.Buffered() == 0 {
		// Check if we need to close - only close if not already closed
	}
}

// MemoryLimiter tracks memory usage for large files
type MemoryLimiter struct {
	limit int64
}

func (ml *MemoryLimiter) Read(p []byte, r *bufio.Reader) (int, error) {
	if ml.limit > 0 && len(p)+r.Buffered() > ml.limit {
		return 0, fmt.Errorf("memory limit exceeded")
	}
	return r.Read(p)
}

// StringMatcher finds all occurrences of a string pattern in data
func StringMatcher(pattern string, data []byte, caseSensitive bool) ([]MatchResult, error) {
	var results []MatchResult
	
	if !caseSensitive {
		pattern = strings.ToLower(string(data))
		dataLower := make([]byte, len(data))
		for i := range data {
			dataLower[i] = bytes.ToLower(data[i])
		}
		data = dataLower
	}

	start := 0
	for {
		idx := bytes.IndexByte(data[start:], []byte(pattern))
		if idx == -1 {
			break
		}
		
		offset := int64(start + idx)
		results = append(results, MatchResult{
			Type:    "string",
			Pattern: pattern,
			Offset:  offset,
			Timestamp: time.Now(),
		})

		start = start + idx + len(pattern)
	}

	return results, nil
}

// RegexMatcher finds all regex matches with context
func RegexMatcher(compiled *regexp.Regexp, data []byte, caseSensitive bool) ([]MatchResult, error) {
	var results []MatchResult
	
	if !caseSensitive {
		pattern := compiled.String()
		dataLower := make([]byte, len(data))
		for i := range data {
			dataLower[i] = bytes.ToLower(data[i])
		}
		data = dataLower
		// Recompile with case-insensitive flag if needed
		if !strings.Contains(pattern, "(?i)") && !strings.Contains(pattern, "(?I)") {
			compiled, _ = regexp.Compile("(?i)" + pattern)
		}
	}

	matches := compiled.FindAllIndex(data, -1)
	for _, match := range matches {
		results = append(results, MatchResult{
			Type:    "regex",
			Pattern: compiled.String(),
			Offset:  int64(match[0]),
			Timestamp: time.Now(),
		})
	}

	return results, nil
}

// FileProcessor processes a single file and returns matches
func (rs *RuleSet) ProcessFile(filename string, reader *bufio.Reader, 
	minSize, maxSize int64, caseSensitive bool) ([]MatchResult, error) {
	var allMatches []MatchResult
	
	// Read entire file into memory
	data := make([]byte, 0, min(1024*1024, maxSize))
	
	if reader != nil {
		buf := make([]byte, 32*1024) // 32KB buffer
		for {
			n, err := reader.Read(buf)
			if n > 0 {
				data = append(data, buf[:n]...)
			}
			if err == nil && n < len(buf) {
				break
			} else if err != nil {
				return allMatches, err
			}
		}
		reader.Close()
	}

	// Apply each rule
	for _, rule := range rs.Rules {
		var matches []MatchResult
		
		if rule.Type == "regex" || (rule.Type == "" && strings.Contains(rule.Pattern, "(")) {
			re, ok := rule.Compiled.(*regexp.Regexp)
			if ok {
				matches, _ = RegexMatcher(re, data, caseSensitive)
			}
		} else if rule.Type == "string" || rule.Type == "" {
			matches, _ = StringMatcher(rule.Pattern, data, caseSensitive)
		}

		allMatches = append(allMatches, matches...)
		
		// Add context to first few matches per rule for display
		if len(matches) > 0 && len(rule.Name) < 32 {
			for i := range allMatches {
				if allMatches[i].RuleName == rule.Name && 
				   (i == 0 || allMatches[i-1].Offset != allMatches[i].Offset) {
					// Add context only to first match of each unique offset
					break
				}
			}
		}
	}

	return allMatches, nil
}

// DirectoryScanner walks a directory and processes files
type DirectoryScanner struct {
	rules     *RuleSet
	minSize   int64
	maxSize   int64
	caseSensitive bool
}

func (ds *DirectoryScanner) Scan(dir string) ([]ScanResult, error) {
	var results []ScanResult
	
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if d.IsDir() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		// Apply size filters
		if info.Size() < ds.minSize || (ds.maxSize > 0 && info.Size() > ds.maxSize) {
			return nil
		}

		// Open and process file
		reader, err := ds.rules.Open(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: skipping %s: %v\n", path, err)
			return nil
		}
		defer reader.Close()

		matches, err := ds.rules.ProcessFile(path, reader, ds.minSize, ds.maxSize, 
			ds.caseSensitive)
		
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: processing %s: %v\n", path, err)
			return nil
		}

		durationMs := int64(time.Since(info.ModTime()).Milliseconds())
		
		result := ScanResult{
			File:    path,
			Matches: matches,
			DurationMs: durationMs,
			Rules:   make([]string, 0),
		}

		// Collect unique rule names used
		ruleNames := make(map[string]bool)
		for _, m := range matches {
			if !ruleNames[m.RuleName] {
				ruleNames[m.RuleName] = true
				result.Rules = append(result.Rules, m.RuleName)
			}
		}

		results = append(results, result)
		
		return nil
	})

	return results, err
}

// OutputFormatter formats and prints results
type OutputFormatter struct {
	format string
	rules  *RuleSet
}

func (of *OutputFormatter) Format(results []ScanResult) error {
	switch of.format {
	case "json":
		return of.formatJSON(results)
	case "text", "":
		return of.formatText(results)
	default:
		return fmt.Errorf("unknown format: %s", of.format)
	}
}

func (of *OutputFormatter) formatText(results []ScanResult) error {
	if len(results) == 0 {
		fmt.Println("No files scanned.")
		return nil
	}

	totalMatches := 0
	for _, r := range results {
		totalMatches += len(r.Matches)
	}

	fmt.Printf("\n=== YARA-Style String/Regex Scanner Results ===\n")
	fmt.Printf("Files scanned: %d\n", len(results))
	fmt.Printf("Total matches: %d\n\n", totalMatches)

	if totalMatches == 0 {
		fmt.Println("No matches found.")
		return nil
	}

	// Group by rule name for better organization
	ruleGroups := make(map[string][]MatchResult)
	for _, r := range results {
		for _, m := range r.Matches {
			if !ruleGroups[m.RuleName] {
				ruleGroups[m.RuleName] = []MatchResult{}
			}
			ruleGroups[m.RuleName] = append(ruleGroups[m.RuleName], m)
		}
	}

	// Sort rule names for consistent output
	var sortedRules []string
	for name := range ruleGroups {
		sortedRules = append(sortedRules, name)
	}
	sort.Strings(sortedRules)

	fmt.Println("=== Matches by Rule ===")
	
	for _, ruleName := range sortedRules {
		matches := ruleGroups[ruleName]
		
		ruleInfo := ""
		if of.rules != nil {
			for _, r := range of.rules.Rules {
				if r.Name == ruleName {
					ruleInfo = fmt.Sprintf(" [%s]", r.Type)
					break
				}
			}
		}

		fmt.Printf("\n--- %s%s (%d matches) ---\n", 
			strings.ReplaceAll(ruleName, "_", " "), ruleInfo, len(matches))

		for _, m := range matches {
			// Format offset as human-readable
			offsetStr := fmt.Sprintf("%08x", m.Offset)
			
			fmt.Printf("  Offset: %s\n", offsetStr)
			
			// Add context if available (first few matches only for readability)
			if len(matches) < 10 || 
			   (m.Offset != matches[0].Offset && len(matches)%5 == 0) {
				context, _ := of.getContext(m.File, m.Offset, 20)
				fmt.Printf("    Context: %s\n", context)
			}

			// Show line number if possible (approximate for large files)
			if m.Line > 0 {
				fmt.Printf("    Line: %d\n", m.Line)
			}
			
			// Truncate pattern for display
			displayPattern := m.Pattern
			if len(displayPattern) > 64 {
				displayPattern = displayPattern[:61] + "..."
			}
			fmt.Printf("    Pattern: %s\n", displayPattern)
		}

		fmt.Println()
	}

	return nil
}

func (of *OutputFormatter) formatJSON(results []ScanResult) error {
	output := map[string]interface{}{
		"version": "yararun 1.0",
		"timestamp": time.Now().Format(time.RFC3339),
		"files_scanned": len(results),
		"total_matches": 0,
		"results": make([]map[string]interface{}, 0),
	}

	totalMatches := 0
	for _, r := range results {
		fileMap := map[string]interface{}{
			"path": r.File,
			"matches_count": len(r.Matches),
			"duration_ms": r.DurationMs,
			"rules_used": r.Rules,
			"matches": make([]map[string]string, 0),
		}

		for _, m := range r.Matches {
			matchMap := map[string]string{
				"rule_name": m.RuleName,
				"type": m.Type,
				"pattern": m.Pattern,
				"offset_hex": fmt.Sprintf("%x", m.Offset),
				"timestamp": m