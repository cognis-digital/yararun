package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/joeshaw/yara"
)

var (
	rulesFile string
	dir       string
)

func init() {
	flag.StringVar(&rulesFile, "rules", "", "Path to YARA rules file")
	flag.StringVar(&dir, "dir", ".", "Directory to scan")
}

func main() {
	flag.Parse()

	if rulesFile == "" || dir == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -rules <file> -dir <directory>\n", os.Args[0])
		os.Exit(1)
	}

	rules, err := yara.LoadRules(rulesFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading rules: %v\n", err)
		os.Exit(1)
	}
	defer rules.Close()

	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		content, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}

		matches, err := rules.Match(content)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error matching rules for %s: %v\n", path, err)
			return nil
		}

		if len(matches) > 0 {
			fmt.Printf("Matched in %s:\n", path)
			for _, match := range matches {
				fmt.Printf("- Rule: %s\n", match.Rule)
				fmt.Printf("  Matched at offset %d\n", match.Offset)
				fmt.Printf("  Full match: %s\n", string(match.Data))
			}
		}

		return nil
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning directory: %v\n", err)
		os.Exit(1)
	}
}