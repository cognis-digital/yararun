use regex::{Regex, RegexBuilder};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Configuration for the string matcher.
#[derive(Debug, Clone)]
pub struct Config {
    /// Directory to scan (default: current directory)
    pub search_dir: Option<PathBuf>,
    /// File extensions to include (None = all files)
    pub extensions: Option<Vec<String>>,
    /// Minimum file size in bytes to process (0 = no limit)
    pub min_size: u64,
    /// Maximum file size in bytes to process (0 = no limit)
    pub max_size: u64,
    /// Whether to print progress
    pub verbose: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            search_dir: None,
            extensions: None,
            min_size: 0,
            max_size: 0,
            verbose: true,
        }
    }
}

/// A single string pattern to match.
#[derive(Debug, Clone)]
pub struct StringPattern {
    /// The regex pattern (compiled)
    pub compiled: Regex,
    /// Original pattern string for display
    pub original: String,
    /// Case sensitivity flag
    pub case_sensitive: bool,
}

impl StringPattern {
    fn new(pattern: &str, flags: Option<&str>) -> Result<Self, regex::Error> {
        let mut builder = RegexBuilder::new(pattern);
        
        if let Some(f) = flags {
            match f.as_str() {
                "i" | "ignore-case" => builder.case_insensitive(true),
                "g" | "global" => builder.multi_line(true),
                _ => {}
            }
        }
        
        Ok(Self {
            compiled: builder.build()?,
            original: pattern.to_string(),
            case_sensitive: !builder.is_case_insensitive(),
        })
    }

    /// Check if a string matches this pattern.
    pub fn match_text(&self, text: &str) -> bool {
        self.compiled.find(text).is_some()
    }

    /// Count how many times the pattern appears in text.
    pub fn count_matches(&self, text: &str) -> usize {
        let mut count = 0;
        for _ in self.compiled.find_iter(text) {
            count += 1;
        }
        count
    }

    /// Extract all matching substrings.
    pub fn extract_matches(&self, text: &str) -> Vec<&str> {
        self.compiled
            .find_iter(text)
            .map(|m| m.as_str())
            .collect()
    }
}

/// A collection of patterns to search for.
#[derive(Debug, Clone)]
pub struct PatternSet {
    /// The list of patterns
    pub patterns: Vec<StringPattern>,
    /// Whether any pattern is case-insensitive
    pub has_case_insensitive: bool,
}

impl PatternSet {
    fn new(patterns: Vec<String>) -> Result<Self, regex::Error> {
        let compiled = patterns
            .iter()
            .map(|p| StringPattern::new(p, None))
            .collect::<Result<Vec<_>, _>>()?;
        
        Ok(Self {
            patterns: compiled,
            has_case_insensitive: compiled.iter().any(|p| !p.case_sensitive),
        })
    }

    /// Check if any pattern matches the text.
    pub fn find_matches(&self, text: &str) -> Vec<StringPattern> {
        self.patterns
            .iter()
            .filter_map(|p| p.compiled.find(text).map(|m| (p.clone(), m.as_str())))
            .collect::<Vec<_>>()
    }

    /// Check if any pattern matches and return the first match.
    pub fn find_first_match(&self, text: &str) -> Option<(StringPattern, &str)> {
        self.patterns.iter().find_map(|p| p.compiled.find(text).map(|m| (p.clone(), m.as_str())))
    }

    /// Count total matches across all patterns.
    pub fn count_all_matches(&self, text: &str) -> usize {
        self.patterns.iter().map(|p| p.count_matches(text)).sum()
    }
}

/// Result of scanning a single file.
#[derive(Debug)]
pub struct FileResult {
    /// Path to the file
    pub path: PathBuf,
    /// Size in bytes
    pub size: u64,
    /// Number of matches found
    pub match_count: usize,
    /// List of matching patterns (name and count)
    pub matches: Vec<(StringPattern, usize)>,
}

impl FileResult {
    fn new(path: PathBuf, size: u64, matches: Vec<(StringPattern, usize)>) -> Self {
        let match_count = matches.iter().map(|(_, c)| *c).sum();
        Self { path, size, match_count, matches }
    }

    /// Check if this file has any matches.
    pub fn is_match(&self) -> bool {
    self.match_count > 0
}

/// Scanner for finding string patterns in files.
pub struct Scanner {
    config: Config,
    pattern_set: PatternSet,
}

impl Scanner {
    /// Create a new scanner with the given configuration and patterns.
    pub fn new(config: Config, patterns: Vec<String>) -> Result<Self, regex::Error> {
        Ok(Self {
            config,
            pattern_set: PatternSet::new(patterns)?,
        })
    }

    /// Scan a single file for matches.
    fn scan_file(&self, path: &Path) -> Option<FileResult> {
        let mut metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return None,
        };

        // Check size constraints
        if self.config.min_size > 0 && metadata.len() < self.config.min_size {
            return None;
        }
        if self.config.max_size > 0 && metadata.len() > self.config.max_size {
            return None;
        }

        // Check extension filter
        let ext = path.extension().and_then(|e| e.to_str());
        if let Some(ref allowed) = self.config.extensions {
            let file_ext = ext.unwrap_or("");
            if !allowed.contains(&file_ext.to_string()) && !allowed.contains("*") {
                return None;
            }
        }

        // Read and scan the file content
        let mut reader = BufReader::new(File::open(path).ok()?);
        let content = match reader.read_to_string() {
            Ok(c) => c,
            Err(_) => return None,
        };

        if content.is_empty() {
            return None;
        }

        // Find all matches
        let matches = self.pattern_set.find_matches(&content);
        
        Some(FileResult::new(path.to_path_buf(), metadata.len(), matches))
    }

    /// Scan a directory recursively.
    pub fn scan_directory(&self, root: &Path) -> Vec<FileResult> {
        let mut results = Vec::new();

        if !root.exists() || !root.is_dir() {
            return results;
        }

        // Collect all files first for progress tracking
        let mut entries = fs::read_dir(root).ok().unwrap_or_default();
        
        while let Some(entry) = entries.next() {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let path = entry.path();
            
            if path.is_file() {
                if let Some(result) = self.scan_file(&path) {
                    results.push(result);
                }
            } else if path.is_dir() && !path.file_name().map_or(false, |n| n == ".git") {
                // Recurse into subdirectories (skip common git folder)
                results.extend(self.scan_directory(&path));
            }
        }

        results.sort_by_key(|r| r.match_count);
        results.reverse(); // Most matches first

        results
    }

    /// Scan a single file directly.
    pub fn scan_file_direct(&self, path: &Path) -> Option<FileResult> {
        self.scan_file(path)
    }

    /// Get statistics about the scan.
    pub fn get_stats(&self, results: &[FileResult]) -> (usize, usize, f64) {
        let total_files = results.len();
        let matched_files = results.iter().filter(|r| r.is_match()).count();
        
        let total_matches: usize = results.iter().map(|r| r.match_count).sum();
        
        // Calculate average matches per file (excluding non-matches)
        let avg_per_file = if total_files > 0 {
            total_matches as f64 / total_files as f64
        } else {
            0.0
        };

        (total_files, matched_files, avg_per_file)
    }
}

/// CLI interface for the scanner.
pub struct Cli {
    config: Config,
    patterns: Vec<String>,
}

impl Default for Cli {
    fn default() -> Self {
        Self {
            config: Config::default(),
            patterns: vec![],
        }
    }
}

impl Cli {
    /// Parse command-line arguments.
    pub fn parse(args: &[String]) -> Result<Self, String> {
        let mut cli = Self::default();
        
        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-d" | "--dir" => {
                    if i + 1 >= args.len() {
                        return Err("Missing directory argument".to_string());
                    }
                    cli.config.search_dir = Some(PathBuf::from(&args[i + 1]));
                    i += 2;
                }
                "-e" | "--ext" => {
                    if i + 1 >= args.len() {
                        return Err("Missing extension argument".to_string());
                    }
                    cli.config.extensions = Some(vec![args[i + 1].clone()]);
                    i += 2;
                }
                "-m" | "--min-size" => {
                    if i + 1 >= args.len() {
                        return Err("Missing size argument".to_string());
                    }
                    cli.config.min_size = match args[i + 1].parse::<u64>() {
                        Ok(n) => n,
                        Err(_) => return Err(format!("Invalid min-size: {}", args[i + 1])),
                    };
                    i += 2;
                }
                "-M" | "--max-size" => {
                    if i + 1 >= args.len() {
                        return Err("Missing size argument".to_string());
                    }
                    cli.config.max_size = match args[i + 1].parse::<u64>() {
                        Ok(n) => n,
                        Err(_) => return Err(format!("Invalid max-size: {}", args[i + 1])),
                    };
                    i += 2;
                }
                "-v" | "--verbose" => {
                    cli.config.verbose = true;
                    i += 1;
                }
                "-q" | "--quiet" => {
                    cli.config.verbose = false;
                    i += 1;
                }
                _ if args[i].starts_with('-') => {
                    return Err(format!("Unknown option: {}", args[i]));
                }
                // First non-flag argument is the pattern(s)
                _ => {
                    let rest = &args[i..];
                    cli.patterns = rest.iter().map(|s| s.to_string()).collect();
                    i = args.len();
                }
            }
        }

        Ok(cli)
    }

    /// Run the scan and output results.
    pub fn run(&self, root: &Path) -> Result<(), String> {
        if self.patterns.is_empty() {
            return Err("No patterns provided".to_string());
        }

        let scanner = Scanner::new(self.config.clone(), self.patterns.clone())?;
        
        // If a specific directory was given, use it; otherwise use the root
        let search_dir = self.config.search_dir.as_ref().unwrap_or(&root);

        if !search_dir.exists() {
            return Err(format!("Directory not found: {}", search_dir.display()));
        }

        let start_time = Instant::now();
        
        let results = scanner.scan_directory(search_dir);
        
        let (total_files, matched_files, avg_per_file) = 
            scanner.get_stats(&results);

        println!("\n=== YARA-Style String Scanner Results ===\n");
        println!("Directory: {}", search_dir.display());
        println!("Files scanned: {}", total_files);
        println!("Files with matches: {}", matched_files);
        println!("Total matches found: {}", results.iter().map(|r| r.match_count).sum::<usize>());
        println!("Average matches per file: {:.2}\n", avg_per_file);

        if self.config.verbose && !results.is_empty() {
            println!("\n--- Match Details ---\n");
            
            for result in &results {
                if result.match_count > 0 {
                    println!(
                        "File: {} ({} bytes, {} matches)",
                        result.path.display(),
                        result.size,
                        result.match_count
                    );
                    
                    for (pattern, count) in &result.matches {
                        let flag = if pattern.case_sensitive { "" } else { "(case-insensitive)" };
                        println!("  - '{}' [{}] x{}", 
                            pattern.original.as_str(),
                            flag,
                            count
                        );
                    }
                }
            }
        }

        println!("\nTime elapsed: {:?}", start_time.elapsed());
        
        Ok(())
    }
}

/// Default configuration for interactive use.
pub fn default_config() -> Config {
    Config::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use tempfile::TempDir;

    #[test]
    fn test_pattern_matching() {
        let pattern = StringPattern::new("hello", None).unwrap();
        
        assert!(pattern.match_text("hello world"));
        assert!(!pattern.match_text("HELLO WORLD")); // case sensitive by default
        
        let ci_pattern = StringPattern::new("world", Some("i")).unwrap();
        assert!(ci_pattern.match_text("Hello World"));
    }

    #[test]
    fn test_pattern_count() {
        let pattern = StringPattern::new("a+", None).unwrap();
        
        assert_eq!(pattern.count_matches("aaaa"), 4);
        assert_eq!(pattern.count_matches("abacaba"), 3);
    }

    #[test]
    fn test_file_scanning() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        
        // Create a test file with matches
        File::create(&file_path).unwrap().write_all(b"hello hello HELLO world").unwrap();
        
        let config = Config {
            search_dir: Some(temp_dir.path().to_path_buf()),
            ..Default::default()
        };
        
        let scanner = Scanner::new(config, vec!["hello".to_string(), "world".to_string()]).unwrap();
        let results = scanner.scan_directory(&temp_dir);
        
        assert_eq!(results.len(), 1);
        assert!(results[0].is_match());
        assert_eq!(results[0].match_count, 4); // hello x2 + HELLO x1 + world x1
    }

    #[test]
    fn test_cli_parsing() {
        let args = vec![
            "yararun".to_string(),
            "-d".to_string(),
            "/tmp/test".to_string(),
            "-e".to_string(),
            "txt".to_string(),
            "-v".to_string(),
            "hello".to_string(),
        ];

        let cli = Cli::parse(&args).unwrap();
        
        assert!(cli.config.search_dir.is_some());
        assert_eq!(cli.config.extensions, Some(vec!["txt".to_string()]));
        assert!(cli.config.verbose);
        assert_eq!(cli.patterns.len(), 1);
    }

    #[test]
    fn test_empty_file_handling() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("empty.txt");
        
        File::create(&file_path).unwrap().write_all(b"").unwrap();
        
        let config = Config {
            search_dir: Some(temp_dir.path().to_path_buf()),
            ..Default::default()
        };
        
        let scanner = Scanner::new(config, vec!["test".to_string()]).unwrap();
        let results = scanner.scan_directory(&temp_dir);
        
        // Empty file should still be scanned but return no matches
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].match_count, 0);
    }

    #[test]
    fn test_size_filtering() {
        let temp_dir = TempDir::new().unwrap();
        
        // Create a small file (should be included)
        File::create