use std::fs;
use std::path::{Path, PathBuf};
use yara::{Compiler, Match, Rule};

fn main() {
    let rules = include_str!("rules.yar");
    let compiler = Compiler::new().unwrap();
    let module = compiler.compile(rules).unwrap();

    let root_dir = PathBuf::from("test_data");

    for entry in fs::read_dir(root_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            scan_file(&module, &path);
        } else if path.is_dir() {
            scan_directory(&module, &path);
        }
    }

    println!("Scan complete.");
}

fn scan_file(module: &Rule, path: &Path) {
    let content = std::fs::read_to_string(path).unwrap();
    let matches = module.match(&content).unwrap();

    if !matches.is_empty() {
        println!("Match found in file: {}", path.display());
        for match_result in &matches {
            println!("  Rule: {}", match_result.rule.name);
            println!("  Matched text: {}", match_result.strings.iter().map(|s| s.text.clone()).collect::<Vec<_>>().join(", "));
        }
    }
}

fn scan_directory(module: &Rule, path: &Path) {
    for entry in fs::read_dir(path).unwrap() {
        let entry_path = entry.unwrap().path();
        if entry_path.is_file() {
            scan_file(module, &entry_path);
        } else if entry_path.is_dir() {
            scan_directory(module, &entry_path);
        }
    }
}