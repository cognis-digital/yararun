using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace polyglot.csharp
{
    /// <summary>
    /// YARA-style string/regex rule engine for scanning directories.
    /// </summary>
    public class MatchStringsEngine
    {
        private readonly List<RuleDefinition> _rules = new();
        private readonly Dictionary<string, Regex> _compiledRegexes = new();

        public void AddYaraFile(string path)
        {
            if (!File.Exists(path))
                throw new FileNotFoundException($"YARA file not found: {path}");

            var content = File.ReadAllText(path);
            ParseRules(content);
        }

        private void ParseRules(string source)
        {
            // Simple state machine parser for YARA-like syntax
            int pos = 0;
            while (pos < source.Length)
            {
                if (source[pos..].StartsWith("rule "))
                {
                    var rule = ParseRule(source, ref pos);
                    _rules.Add(rule);
                }
                else
                {
                    // Skip comments and whitespace
                    if (source[pos] == '/' && source[pos + 1..].StartsWith('/'))
                    {
                        while (pos < source.Length && !source[pos..].StartsWith("\n"))
                            pos++;
                    }
                    else
                    {
                        pos++;
                    }
                }
            }

            // Compile regexes for performance
            foreach (var rule in _rules)
            {
                if (!string.IsNullOrEmpty(rule.RegexPattern))
                {
                    var options = RegexOptions.IgnoreCase | RegexOptions.Compiled;
                    if (!string.IsNullOrEmpty(rule.Flags))
                    {
                        options |= ParseFlags(rule.Flags);
                    }
                    _compiledRegexes[rule.Name] = new Regex(rule.RegexPattern, options);
                }
            }
        }

        private RuleDefinition ParseRule(string source, ref int pos)
        {
            // Extract rule name
            var start = pos + 6; // skip "rule "
            while (source[start..].StartsWith(" ")) start++;
            var end = source.IndexOf('{', start);
            if (end == -1) throw new FormatException($"Missing '{' for rule");

            string name = source.Substring(start, end - start).Trim();
            pos = end + 2; // skip "name{"

            var strings = new List<RuleString>();
            var conditions = new List<string>();

            while (pos < source.Length)
            {
                if (source[pos..].StartsWith("strings:"))
                {
                    ParseStrings(source, ref pos, strings);
                }
                else if (source[pos..].StartsWith("regex:"))
                {
                    ParseRegex(source, ref pos);
                }
                else if (source[pos..].StartsWith("condition:"))
                {
                    ParseCondition(source, ref pos, conditions);
                }
                else if (source[pos..].StartsWith("meta:"))
                {
                    // Skip meta section for now
                    while (pos < source.Length && !source[pos..].StartsWith("{") || 
                           !source[pos..].Contains("}"))
                    {
                        pos++;
                    }
                }
                else if (source[pos..].StartsWith("{"))
                {
                    // End of rule definition
                    while (pos < source.Length && !source[pos..].StartsWith("}"))
                        pos++;
                    break;
                }
                else
                {
                    pos++;
                }
            }

            return new RuleDefinition
            {
                Name = name,
                Strings = strings,
                RegexPattern = string.Join("|", _compiledRegexes.Keys), // Simplified for demo
                Conditions = conditions,
                Flags = "i" // Default case-insensitive
            };
        }

        private void ParseStrings(string source, ref int pos, List<RuleString> strings)
        {
            while (pos < source.Length && !source[pos..].StartsWith("regex:") && 
                   !source[pos..].StartsWith("condition:"))
            {
                if (source[pos..].StartsWith("$") || source[pos..].StartsWith("\"\"\""))
                {
                    var str = ParseStringLiteral(source, ref pos);
                    strings.Add(new RuleString { Name = str.Name, Value = str.Value });
                }
                else
                {
                    pos++;
                }
            }
        }

        private (string Name, string Value) ParseStringLiteral(string source, ref int pos)
        {
            // Skip to $name or "..."
            while (!source[pos..].StartsWith("$") && !source[pos..].StartsWith("\"\"\""))
                pos++;

            if (source[pos..].StartsWith("$"))
            {
                var nameEnd = source.IndexOf('=', pos);
                string name = source.Substring(pos, nameEnd - pos).Trim();
                pos = nameEnd + 1; // skip '='
                
                while (source[pos..].StartsWith(" ")) pos++;
                var value = ParseStringLiteral(source, ref pos).Value;
                return (name, value);
            }

            if (source[pos..].StartsWith("\"\"\""))
            {
                int openQuote = source.IndexOf('"', pos);
                string content = "";
                while (openQuote != -1)
                {
                    var nextOpen = source.IndexOf('"', openQuote + 1);
                    if (nextOpen == -1 || source[nextOpen] == '"')
                    {
                        content += source.Substring(openQuote + 1, nextOpen - openQuote - 1);
                        break;
                    }
                    else
                    {
                        content += source.Substring(openQuote + 1, nextOpen - openQuote - 1);
                        openQuote = nextOpen;
                    }
                }

                // Find closing "..."
                var closePos = source.IndexOf("\"\"", pos) + 2;
                return (content, "");
            }

            return ("", "");
        }

        private void ParseRegex(string source, ref int pos)
        {
            while (source[pos..].StartsWith(" ")) pos++;
            var open = source.IndexOf('(', pos);
            if (open == -1) throw new FormatException($"Missing '(' for regex");

            string pattern = "";
            int close = source.IndexOf(')', open + 1);
            if (close != -1)
                pattern = source.Substring(open + 1, close - open - 1).Trim();
            else
                pattern = source.Substring(open + 1).Trim();

            pos = close + 2; // skip "){"
        }

        private void ParseCondition(string source, ref int pos, List<string> conditions)
        {
            while (source[pos..].StartsWith(" ")) pos++;
            var open = source.IndexOf('(', pos);
            if (open == -1) throw new FormatException($"Missing '(' for condition");

            string cond = "";
            int close = source.IndexOf(')', open + 1);
            if (close != -1)
                cond = source.Substring(open + 1, close - open - 1).Trim();
            else
                cond = source.Substring(open + 1).Trim();

            conditions.Add(cond);
            pos = close + 2; // skip "){"
        }

        private RegexOptions ParseFlags(string flags)
        {
            var result = RegexOptions.None;
            if (flags.Contains("i")) result |= RegexOptions.IgnoreCase;
            if (flags.Contains("s")) result |= RegexOptions.Singleline;
            if (flags.Contains("m")) result |= RegexOptions.Multiline;
            return result;
        }

        public async Task<List<MatchResult>> ScanDirectoryAsync(string directory)
        {
            var results = new List<MatchResult>();

            // Collect all files recursively
            var fileQueue = new Queue<string>(new[] { directory });
            while (fileQueue.Count > 0)
            {
                var path = fileQueue.Dequeue();
                if (Directory.Exists(path))
                {
                    foreach (var sub in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
                        fileQueue.Enqueue(sub);
                }
                else
                {
                    // Skip non-regular files
                    if (!File.Exists(path) || path.Length < 1024) continue;

                    var content = await File.ReadAllTextAsync(path);
                    results.AddRange(ScanContent(content, path));
                }
            }

            return results;
        }

        public List<MatchResult> ScanContent(string content, string filename)
        {
            var matches = new List<MatchResult>();

            foreach (var rule in _rules)
            {
                // Check if regex-based rule applies
                if (!string.IsNullOrEmpty(rule.RegexPattern))
                {
                    var compiled = _compiledRegexes[rule.Name];
                    var matchPos = 0;
                    while ((matchPos = compiled.Match(content, matchPos).Success))
                    {
                        matches.Add(new MatchResult
                        {
                            RuleName = rule.Name,
                            Filename = filename,
                            Offset = matchPos,
                            Length = matchPos + compiled.Length,
                            Context = content.Substring(Math.Max(0, matchPos - 128), 
                                                       Math.Min(content.Length, matchPos + 128))
                        });
                        matchPos += matched.Length;
                    }
                }

                // Check string-based rules
                if (rule.Strings.Count > 0)
                {
                    foreach (var str in rule.Strings)
                    {
                        var positions = FindAllStringOccurrences(content, str.Value);
                        foreach (var pos in positions)
                        {
                            matches.Add(new MatchResult
                            {
                                RuleName = rule.Name,
                                Filename = filename,
                                Offset = pos,
                                Length = 0, // String match is exact
                                Context = content.Substring(Math.Max(0, pos - 128), 
                                                           Math.Min(content.Length, pos + 128))
                            });
                        }
                    }
                }
            }

            return matches;
        }

        private static List<int> FindAllStringOccurrences(string text, string pattern)
        {
            var positions = new List<int>();
            int start = 0;
            while ((start = text.IndexOf(pattern, start)) != -1)
            {
                positions.Add(start);
                start += pattern.Length;
            }
            return positions;
        }

        public class RuleString
        {
            public string Name { get; set; } = "";
            public string Value { get; set; } = "";
        }

        public class RuleDefinition
        {
            public string Name { get; set; } = "";
            public List<RuleString> Strings { get; set; } = new();
            public string RegexPattern { get; set; } = "";
            public List<string> Conditions { get; set; } = new();
            public string Flags { get; set; } = "i";
        }

        public class MatchResult
        {
            public string RuleName { get; set; } = "";
            public string Filename { get; set; } = "";
            public int Offset { get; set; }
            public int Length { get; set; }
            public string Context { get; set; } = "";

            public override string ToString() => 
                $"{RuleName}: {Filename}:{Offset}";
        }
    }

    // Entry point with demo
    class Program
    {
        static void Main(string[] args)
        {
            var engine = new MatchStringsEngine();

            // Create a sample YARA file for testing
            string testYara = @"
rule TestRule1 {
    strings:
        $a = ""Hello""
        $b = ""World""
    condition:
        all of them
}

rule TestRule2 {
    strings:
        $c = """\"C:\\Windows\\System32"""
    regex:
        $d = /password|passw0rd/i
    condition:
        any of them
}

rule TestRule3 {
    meta:
        author = ""Demo""
    strings:
        $e = ""admin""
    regex:
        $f = /root/
    condition:
        all of them
}";

            File.WriteAllText("test.yar", testYara);
            engine.AddYaraFile("test.yar");

            // Create a sample directory with files to scan
            string testDir = "test_scan_dir";
            Directory.CreateDirectory(testDir);

            var testFiles = new[] {
                $@"{testDir}/file1.txt: Hello World",
                $@"{testDir}/file2.txt: C:\Windows\System32 admin password",
                $@"{testDir}/file3.txt: root access granted",
                $@"{testDir}/nested/file4.txt: nested Hello"
            };

            foreach (var (path, content) in testFiles)
            {
                var dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                File.WriteAllText(Path.GetFileName(path), content);
            }

            // Scan the directory
            Console.WriteLine("Scanning directory...");
            var matches = engine.ScanDirectoryAsync(testDir).Result;

            // Output results
            Console.WriteLine($"\nFound {matches.Count} matches:");
            foreach (var m in matches)
            {
                Console.WriteLine($"  [{m.RuleName}] {m.Filename}:{m.Offset}");
                Console.WriteLine($"    Context: {m.Context.Trim()}");
            }

            // Cleanup test files
            if (Directory.Exists(testDir))
            {
                foreach (var f in Directory.EnumerateFiles(testDir, "*", SearchOption.AllDirectories))
                    File.Delete(f);
                Directory.Delete(testDir);
            }

            Console.WriteLine("\nDone!");
        }
    }
}