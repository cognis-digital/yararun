use std::fs;
use std::path::{Path, PathBuf};
use yara::{Rule, YaraError, YaraResult};

#[derive(Debug)]
struct RuleDefinition {
    name: String,
    rule: Rule,
}

fn main() {
    // Example rule definition (YARA-style)
    let rule_str = r#"
rule TestRule {
    strings:
        $a = "Hello, world!"
    condition:
        $a
}
"#;

    let rule_def = RuleDefinition {
        name: "TestRule".to_string(),
        rule: Rule::from_source(rule_str).unwrap(),
    };

    // Example directory to scan
    let dir_path = PathBuf::from(".");

    // Apply the rule to all files in the directory
    apply_rule(&rule_def, &dir_path);
}

fn apply_rule(rule: &RuleDefinition, dir_path: &Path) {
    if !dir_path.exists() {
        eprintln!("Directory does not exist: {}", dir_path.display());
        return;
    }

    if !dir_path.is_dir() {
        eprintln!("Not a directory: {}", dir_path.display());
        return;
    }

    for entry in fs::read_dir(dir_path).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();

        if path.is_file() {
            match rule.rule.match_file(&path) {
                Ok(matches) => {
                    if !matches.is_empty() {
                        println!("Matched rule '{}':", rule.name);
                        for match_result in matches {
                            println!("  Matched string: {}", match_result.strings[0].get_text());
                        }
                    }
                }
                Err(e) => eprintln!("Error matching rule '{}': {}", rule.name, e),
            }
        }
    }
}