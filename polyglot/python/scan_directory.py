import os
import re
from typing import List, Dict, Any

class YaraRule:
    def __init__(self, name: str, pattern: str, description: str = ""):
        self.name = name
        self.pattern = pattern
        self.description = description

    def match(self, content: str) -> bool:
        return re.search(self.pattern, content, re.DOTALL) is not None

def load_rules_from_file(file_path: str) -> List[YaraRule]:
    rules = []
    with open(file_path, 'r') as f:
        rule_data = ""
        for line in f:
            line = line.strip()
            if line.startswith("rule"):
                if rule_data:
                    rules.append(YaraRule(**eval(rule_data)))
                rule_data = line
            elif line.startswith("description") or line.startswith("strings") or line.startswith("condition"):
                rule_data += "\n" + line
        if rule_data:
            rules.append(YaraRule(**eval(rule_data)))
    return rules

def scan_directory(directory: str, rules: List[YaraRule]) -> Dict[str, List[Dict[str, Any]]]:
    results = {}
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
            except UnicodeDecodeError:
                continue
            matches = []
            for rule in rules:
                if rule.match(content):
                    matches.append({
                        "rule": rule.name,
                        "description": rule.description,
                        "file": file_path
                    })
            if matches:
                results[file_path] = matches
    return results

def main():
    rules_file = 'rules.yar'
    if not os.path.exists(rules_file):
        print(f"Rules file '{rules_file}' not found.")
        return

    rules = load_rules_from_file(rules_file)
    directory_to_scan = os.getcwd()
    scan_results = scan_directory(directory_to_scan, rules)

    if scan_results:
        print("Matches found:")
        for file_path, matches in scan_results.items():
            print(f"\nFile: {file_path}")
            for match in matches:
                print(f" - Rule: {match['rule']}, Description: {match['description']}")
    else:
        print("No matches found.")

if __name__ == "__main__":
    main()