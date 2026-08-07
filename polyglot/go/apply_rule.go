package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/joeshaw/goyacc/yara"
)

// Rule represents a YARA rule with its name and content
type Rule struct {
	Name   string
	Content string
}

func main() {
	// Example usage: apply_rule.go <rule_file> <directory>
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <rule_file> <directory>\n", os.Args[0])
		os.Exit(1)
	}

	ruleFile := os.Args[1]
	dirToScan := os.Args[2]

	// Load the YARA rule
	rules, err := loadRules(ruleFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading rules: %v\n", err)
		os.Exit(1)
	}

	// Compile the rules
	compiledRules, err := yara.Compile(rules)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error compiling rules: %v\n", err)
		os.Exit(1)
	}

	// Scan the directory
	err = filepath.Walk(dirToScan, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			// Match the file against the compiled rules
			matches := compiledRules.MatchFile(path)
			if len(matches) > 0 {
				color.Green("Match found in %s:\n", path)
				for _, match := range matches {
					fmt.Printf(" - Rule: %s\n", match.Rule.Name)
					fmt.Printf(" - Tags: %v\n", match.Tags)
					fmt.Printf(" - Strings: %v\n", match.Strings)
				}
			} else {
				color.Blue("No matches in %s.\n", path)
			}
		}
		return nil
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning directory: %v\n", err)
		os.Exit(1)
	}
}

// loadRules reads a YARA rule file and returns a slice of Rule structs
func loadRules(ruleFile string) ([]Rule, error) {
	file, err := os.Open(ruleFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var rules []Rule
	scanner := bufio.NewScanner(file)
	var currentRuleName string
	var currentRuleContent strings.Builder

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		if strings.HasPrefix(line, "rule") {
			if currentRuleName != "" {
				rules = append(rules, Rule{Name: currentRuleName, Content: currentRuleContent.String()})
				currentRuleContent.Reset()
			}
			currentRuleName = parseRuleName(line)
		} else if currentRuleName != "" {
			currentRuleContent.WriteString(line + "\n")
		}
	}

	if currentRuleName != "" {
		rules = append(rules, Rule{Name: currentRuleName, Content: currentRuleContent.String()})
	}

	return rules, nil
}

// parseRuleName extracts the rule name from a YARA rule line
func parseRuleName(line string) string {
	parts := strings.SplitN(line, " ", 2)
	if len(parts) < 2 {
		return ""
	}
	return strings.TrimSpace(parts[1])
}