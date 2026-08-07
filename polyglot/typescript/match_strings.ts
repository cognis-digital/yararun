import * as fs from 'fs';
import * as path from 'path';

// ============================================================================
// TYPES & CONFIGURATION
// ============================================================================

interface YaraRule {
  name: string;
  description?: string;
  patterns: Pattern[];
}

interface Pattern {
  id: number;
  regex: RegExp;
  flags: string;
  caseSensitive?: boolean;
}

interface MatchResult {
  ruleName: string;
  filename: string;
  filepath: string;
  matches: Array<{
    patternId: number;
    lineIndex: number;
    lineNumber: number;
    matchText: string;
    offset: number;
  }>;
}

interface ScanOptions {
  rootDir: string;
  rules: YaraRule[];
  recursive?: boolean;
  maxDepth?: number;
  minFileSize?: number;
  maxFileSize?: number;
  includeHidden?: boolean;
  followSymlinks?: boolean;
}

interface ScanResult {
  totalFiles: number;
  totalMatches: number;
  matchesByRule: Map<string, number>;
  results: MatchResult[];
  errors: Array<{ file: string; message: string }>;
}

// ============================================================================
// DEFAULT CONFIGURATION
// ============================================================================

const DEFAULT_OPTIONS: ScanOptions = {
  rootDir: '.',
  rules: [],
  recursive: true,
  maxDepth: 10,
  minFileSize: 0,
  maxFileSize: Infinity,
  includeHidden: false,
  followSymlinks: false,
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function getExtension(filename: string): string {
  const lastDot = filename.lastIndexOf('.');
  return lastDot === -1 ? '' : filename.slice(lastDot + 1).toLowerCase();
}

function isHiddenFile(filename: string): boolean {
  if (filename.startsWith('.') && !['.', '..'].includes(filename)) {
    return true;
  }
  const parts = path.basename(filename).split('.');
  return parts[0].startsWith('.');
}

function getFileSize(filePath: string): number | undefined {
  try {
    return fs.statSync(filePath)?.size;
  } catch {
    return undefined;
  }
}

// ============================================================================
// FILE SCANNER
// ============================================================================

function* scanFiles(options: ScanOptions & { currentDepth: number }): Generator<
  string,
  void,
  void
> {
  const root = path.resolve(options.rootDir);
  
  if (!fs.existsSync(root)) {
    return;
  }

  let currentPath = options.recursive 
    ? (options.currentDepth < options.maxDepth) 
      ? path.join(root, '') 
      : root
    : root;

  const entries = fs.readdirSync(currentPath, {
    withFileTypes: true,
    recursive: false,
  });

  for (const entry of entries) {
    if (!options.includeHidden && isHiddenFile(entry.name)) continue;

    const fullPath = path.join(currentPath, entry.name);

    if (entry.isDirectory()) {
      if (options.recursive && options.currentDepth < options.maxDepth) {
        yield* scanFiles({ ...options, currentDepth: options.currentDepth + 1 });
      }
    } else if (entry.isFile()) {
      const stats = fs.statSync(fullPath);

      // Filter by size constraints
      if (stats.size > 0 && 
          (options.minFileSize === 0 || stats.size >= options.minFileSize) &&
          (options.maxFileSize === Infinity || stats.size <= options.maxFileSize)) {
        
        yield fullPath;
      }
    }
  }
}

// ============================================================================
// PATTERN COMPILER
// ============================================================================

function compilePattern(pattern: string, flags: string): Pattern {
  const id = Date.now() + Math.random().toString(16).slice(2);
  
  try {
    // YARA-style: \x00 for null byte, \xNN for hex escapes
    let compiledRegex = pattern;
    
    // Handle common YARA escape sequences
    compiledRegex = compiledRegex.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => {
      return String.fromCharCode(parseInt(hex, 16));
    });

    const caseSensitive = !flags.includes('i');
    
    // Convert to JS flags
    let jsFlags: string;
    if (caseSensitive) {
      jsFlags = flags.replace(/i/g, '');
    } else {
      jsFlags = 'i';
    }

    return { id, regex: new RegExp(compiledRegex, jsFlags), flags, caseSensitive };
  } catch (error) {
    throw new Error(`Invalid pattern "${pattern}": ${(error as Error).message}`);
  }
}

function compileRules(rules: YaraRule[]): Pattern[] {
  const allPatterns: Pattern[] = [];
  
  for (const rule of rules) {
    if (!rule.patterns || rule.patterns.length === 0) continue;

    for (let i = 0; i < rule.patterns.length; i++) {
      try {
        const patternStr = rule.patterns[i];
        // Default flags: case-insensitive, multiline
        let defaultFlags = 'ims';
        
        if (typeof patternStr === 'string') {
          allPatterns.push(compilePattern(patternStr, defaultFlags));
        } else if (patternStr instanceof RegExp) {
          const flags = patternStr.flags;
          // Convert to case-sensitive if no 'i' flag
          let jsFlags = flags.replace(/i/g, '');
          if (!jsFlags.includes('i')) jsFlags += 'i';
          
          allPatterns.push({
            id: Date.now() + Math.random().toString(16).slice(2),
            regex: patternStr,
            flags: defaultFlags,
            caseSensitive: !flags.includes('i'),
          });
        } else if (typeof patternStr === 'object') {
          // Object form with explicit options
          const opts = patternStr as { regex?: string | RegExp; flags?: string };
          
          let compiledRegex: string | RegExp;
          let jsFlags: string;
          
          if (opts.regex instanceof RegExp) {
            compiledRegex = opts.regex.source;
            jsFlags = opts.flags || 'ims';
          } else {
            compiledRegex = opts.regex as string;
            jsFlags = (opts.flags || '').replace(/i/g, '');
            if (!jsFlags.includes('i')) jsFlags += 'i';
          }

          allPatterns.push({
            id: Date.now() + Math.random().toString(16).slice(2),
            regex: new RegExp(compiledRegex, jsFlags),
            flags: opts.flags || defaultFlags,
            caseSensitive: !jsFlags.includes('i'),
          });
        }
      } catch (error) {
        console.error(`Error compiling pattern in rule "${rule.name}":`, error);
      }
    }
  }

  return allPatterns;
}

// ============================================================================
// MATCHING ENGINE
// ============================================================================

function matchFile(
  filepath: string,
  patterns: Pattern[],
  filename: string
): MatchResult | null {
  const matches: MatchResult['matches'] = [];
  
  try {
    let content: string;
    
    // Try to detect encoding and read as text
    try {
      content = fs.readFileSync(filepath, 'utf-8');
    } catch {
      // Fallback: try latin1 (common for binary-ish files)
      try {
        content = fs.readFileSync(filepath, 'latin1').toString();
      } catch {
        return null;
      }
    }

    const lines = content.split(/\r?\n/);
    
    for (const pattern of patterns) {
      let match: RegExpMatchArray | null;
      
      // Use global flag to find all matches
      const searchRegex = new RegExp(pattern.regex.source, 
        pattern.flags + 'g');

      while ((match = searchRegex.exec(content)) !== null) {
        const lineIndex = content.slice(0, match.index).split(/\r?\n/).length - 1;
        
        matches.push({
          patternId: pattern.id,
          lineIndex,
          lineNumber: lineIndex + 1,
          matchText: match[0],
          offset: match.index,
        });
      }

      if (matches.length > 0) {
        return {
          ruleName: '', // Will be filled by caller
          filename,
          filepath,
          matches,
        };
      }
    }
    
    return null;
  } catch (error) {
    console.error(`Error reading file ${filepath}:`, error);
    return null;
  }
}

function matchDirectory(options: ScanOptions): ScanResult {
  const startTime = Date.now();
  
  // Compile all patterns first
  const compiledPatterns = compileRules(options.rules);
  
  if (compiledPatterns.length === 0) {
    return {
      totalFiles: 0,
      totalMatches: 0,
      matchesByRule: new Map(),
      results: [],
      errors: [{ file: '', message: 'No valid patterns found' }],
    };
  }

  const result: ScanResult = {
    totalFiles: 0,
    totalMatches: 0,
    matchesByRule: new Map(),
    results: [],
    errors: [],
  };

  // Track which rules matched to avoid duplicates in output
  const ruleMatched = new Set<string>();

  for (const file of scanFiles({ ...options, currentDepth: 0 })) {
    result.totalFiles++;

    try {
      const filename = path.basename(file);
      let matchResult: MatchResult | null = null;

      // Check each rule against the file
      for (const rule of options.rules) {
        if (!ruleMatched.has(rule.name)) {
          const matches = matchFile(file, compiledPatterns, filename);
          
          if (matches && matches.matches.length > 0) {
            result.results.push({
              ...matches,
              ruleName: rule.name,
            });
            
            // Deduplicate by pattern ID and line number
            const seen = new Set<string>();
            const dedupedMatches: MatchResult['matches'] = [];
            
            for (const m of matches.matches) {
              const key = `${m.patternId}:${m.lineIndex}`;
              if (!seen.has(key)) {
                seen.add(key);
                dedupedMatches.push(m);
              }
            }

            result.results[result.results.length - 1].matches = dedupedMatches;
            
            // Update counts
            for (const m of matches.matches) {
              const ruleName = options.rules.find(r => 
                r.patterns.some(p => p.id === m.patternId))?.name || 'Unknown';
              
              result.totalMatches++;
              result.matchesByRule.set(ruleName, 
                (result.matchesByRule.get(ruleName) || 0) + 1);
            }

            ruleMatched.add(rule.name);
          }
        }
      }

    } catch (error) {
      result.errors.push({ file, message: String(error) });
    }
  }

  // Sort results by filename then line number for consistent output
  result.results.sort((a, b) => {
    const cmp = a.filename.localeCompare(b.filename);
    if (cmp !== 0) return cmp;
    return a.lineNumber - b.lineNumber;
  });

  return result;
}

// ============================================================================
// OUTPUT FORMATTERS
// ============================================================================

function formatResults(result: ScanResult): string {
  let output = '';

  // Summary header
  const totalRules = options.rules.length;
  const matchedRules = Array.from(result.matchesByRule.keys()).length;
  
  output += `=== YARA-STYLE SCAN RESULTS ===\n\n`;
  output += `Files scanned: ${result.totalFiles}\n`;
  output += `Total matches: ${result.totalMatches}\n`;
  output += `Rules matched: ${matchedRules}/${totalRules}\n\n`;

  if (result.errors.length > 0) {
    output += '--- ERRORS ---\n';
    for (const err of result.errors.slice(0, 10)) {
      output += `  [${err.file}] ${err.message}\n`;
    }
    if (result.errors.length > 10) {
      output += `  ... and ${result.errors.length - 10} more errors\n`;
    }
    output += '\n';
  }

  // Group results by file
  const grouped: Map<string, MatchResult[]> = new Map();

  for (const r of result.results) {
    if (!grouped.has(r.filename)) {
      grouped.set(r.filename, []);
    }
    grouped.get(r.filename)!.push(r);
  }

  // Output each file's matches
  const sortedFiles = Array.from(grouped.entries()).sort((a, b) => 
    a[0].localeCompare(b[0])
  );

  for (const [filename, fileMatches] of sortedFiles) {
    output += `--- ${filename} ---\n`;
    
    // Get rule names for these matches
    const ruleNames = new Set<string>();
    for (const m of fileMatches) {
      const ruleName = options.rules.find(r => 
        r.patterns.some(p => p.id === m.patternId))?.name || 'Unknown';
      ruleNames.add(ruleName);
    }

    output += `  Rules: ${Array.from(ruleNames).join(', ')}\n`;
    output += `  Matches: ${fileMatches.length}\n\n`;

    for (const match of fileMatches) {
      const ruleName = options.rules.find(r => 
        r.patterns.some(p => p.id === match.patternId))?.name || 'Unknown';
      
      output += `    [${ruleName}] Line ${match.lineNumber}:\n`;
      output += `      > "${match.matchText}"\n\n`;
    }
  }

  if (result.results.length === 0) {
    output += 'No matches found.\n';
  }

  return output;
}

// ============================================================================
// CLI INTERFACE
// ============================================================================

interface CliArgs {
  root: string;
  rulesFile?: string;
  format?: 'text' | 'json';
  quiet?: boolean;
  help?: boolean;
}

function parseCliArgs(args: string[]): CliArgs {
  const result: CliArgs = {
    root: '.',
    rulesFile: undefined,
    format: 'text',
    quiet: false,
    help: args.includes('--help') || args.includes('-h'),
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === '--root' || arg === '-r') {
      result.root = args[++i] || '.';
    } else if (arg === '--rules' || arg === '-R') {
      result.rulesFile = args[++i];
    } else if (arg === '--format' || arg === '-f') {
      const fmt = args[++i];
      result.format = (fmt as any) || 'text';
    } else if (arg === '--quiet' || arg === '-q') {
      result.quiet = true;
    } else if (arg === '--help' || arg === '-h') {
      result.help = true;
    } else if (!result.root && !result.rulesFile) {
      // First positional argument is root directory
      result.root = arg;
    }
  }

  return result;
}

function printHelp() {
  console.log(`
yararun - YARA-style pattern matcher for TypeScript projects

Usage: yararun [options] <directory>

Options:
  -r, --root <dir>     Directory to scan (default: current directory)
  -R, --rules <file>   JSON file containing rules (see below)
  -f, --format <fmt>   Output format: text|json (default: text)
  -q, --quiet          Suppress detailed output
  -h, --help           Show this help message

Rule File Format (JSON):
{
  "rules": [
    {
      "name": "rule-name",
      "description": "optional description",
      "patterns": [
        "pattern string or regex object"
      ]
    }
  ]
}

Examples:
  yararun /path/to/source
  yararun -R rules.json /path/to/source
  yararun --format json .
`);
}

function loadRulesFromJson(filepath: string): YaraRule[] {
  try {
    const data = JSON.parse(fs.readFileSync(filepath, 'utf-8'));
    
    if (!data.rules || !Array.isArray(data.rules)) {
      throw new Error('Invalid rules file format. Expected "rules" array.');
    }

    return data.rules;
  } catch (error) {
    throw new Error(`Failed to load rules from ${filepath}: ${(error as Error).message}`);
  }
}

// ============================================================================
// ENTRY POINT & DEMO
// ============================================================================

const options: ScanOptions = {
  rootDir: process.cwd(),
  rules: [],
  recursive: true,
  maxDepth: 10,
  minFileSize: 0,
  maxFileSize: Infinity,
  includeHidden: false,
  followSymlinks: false,
};

// Define some sample YARA-style patterns for demo purposes
const demoRules: YaraRule[] = [
  {
    name: