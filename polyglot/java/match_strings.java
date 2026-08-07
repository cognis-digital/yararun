package polyglot.java;

import java.io.*;
import java.nio.file.*;
import java.util.regex.*;
import java.util.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * YARA-style string/regex rule scanner.
 * Parses simple rules and matches against files in a directory.
 */
public class match_strings {

    /**
     * Simple YARA rule parser.
     * Supports: rule name { conditions: re("pattern"), str("text") }
     */
    static class RuleParser {
        private String ruleName;
        private List<Condition> conditions = new ArrayList<>();

        public static List<Rule> parse(String content) throws Exception {
            List<Rule> rules = new ArrayList<>();
            
            // Find all rule blocks
            Pattern ruleBlockPattern = Pattern.compile(
                "rule\\s+(\\w+)\\s*\\{([^}]+)\\}", 
                Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
            
            Matcher m = ruleBlockPattern.matcher(content);
            while (m.find()) {
                RuleParser parser = new RuleParser();
                parser.ruleName = m.group(1).trim();
                
                // Parse conditions inside the block
                String blockContent = m.group(2);
                parseConditions(blockContent, parser.conditions);
                
                rules.add(new Rule(parser));
            }
            
            return rules;
        }

        private static void parseConditions(String content, List<Condition> list) {
            // Handle re("pattern") - regex condition
            Pattern rePattern = Pattern.compile(
                "re\\s*\\(\\s*\"([^\"]+)\"\\s*\\)", 
                Pattern.CASE_INSENSITIVE);
            
            Matcher m = rePattern.matcher(content);
            while (m.find()) {
                String pattern = m.group(1).trim();
                list.add(new Condition(pattern, true)); // true = is regex
            }

            // Handle str("text") - literal string condition  
            Pattern strPattern = Pattern.compile(
                "str\\s*\\(\\s*\"([^\"]+)\"\\s*\\)", 
                Pattern.CASE_INSENSITIVE);
            
            m = strPattern.matcher(content);
            while (m.find()) {
                String text = m.group(1).trim();
                list.add(new Condition(text, false)); // false = is literal
            }

            // Handle any("pattern") - case-insensitive regex
            Pattern anyPattern = Pattern.compile(
                "any\\s*\\(\\s*\"([^\"]+)\"\\s*\\)", 
                Pattern.CASE_INSENSITIVE);
            
            m = anyPattern.matcher(content);
            while (m.find()) {
                String pattern = m.group(1).trim();
                list.add(new Condition(pattern, true)); // regex, case-insensitive
            }

            // Handle ascii("text") - ASCII literal
            Pattern asciiPattern = Pattern.compile(
                "ascii\\s*\\(\\s*\"([^\"]+)\"\\s*\\)", 
                Pattern.CASE_INSENSITIVE);
            
            m = asciiPattern.matcher(content);
            while (m.find()) {
                String text = m.group(1).trim();
                list.add(new Condition(text, false)); // literal, ASCII only
            }
        }
    }

    static class Rule {
        final String name;
        final List<Condition> conditions;

        Rule(RuleParser parser) {
            this.name = parser.ruleName;
            this.conditions = new ArrayList<>(parser.conditions);
        }
    }

    static class Condition {
        final String pattern;
        final boolean isRegex;

        Condition(String pattern, boolean isRegex) {
            this.pattern = pattern;
            this.isRegex = isRegex;
        }
    }

    /**
     * Scan a directory for YARA rules and match strings.
     */
    public static void main(String[] args) throws Exception {
        // Default paths if not provided
        String rulePath = "yararun/rules/";
        String scanDir = ".";
        
        if (args.length >= 1) rulePath = args[0];
        if (args.length >= 2) scanDir = args[1];

        System.out.println("=== YARA-Style String Scanner ===");
        System.out.println("Rules directory: " + rulePath);
        System.out.println("Scan directory:   " + scanDir);
        System.out.println();

        // Load rules from file(s)
        List<Rule> rules = loadRules(rulePath);
        
        if (rules.isEmpty()) {
            System.out.println("No rules found. Creating a default rule for demo...");
            rules.add(createDemoRule());
        }

        System.out.println("Loaded " + rules.size() + " rule(s):");
        for (Rule r : rules) {
            System.out.println("  - " + r.name);
        }
        System.out.println();

        // Scan files
        Path scanPath = Paths.get(scanDir).toAbsolutePath().normalize();
        if (!Files.exists(scanPath)) {
            System.out.println("Scan directory not found: " + scanPath);
            return;
        }

        List<Path> files = Files.walk(scanPath)
                .filter(p -> !p.startsWith(Paths.get(rulePath))) // exclude rule dir
                .filter(p -> p.toString().endsWith(".java") || 
                            p.toString().endsWith(".py") || 
                            p.toString().endsWith(".c") || 
                            p.toString().endsWith(".h") || 
                            p.toString().endsWith(".txt"))
                .toList();

        System.out.println("Found " + files.size() + " file(s) to scan...");
        System.out.println();

        // Match and report
        int totalMatches = 0;
        
        for (Path file : files) {
            String fileName = file.getFileName().toString();
            
            try {
                List<String> matches = matchFile(file, rules);
                
                if (!matches.isEmpty()) {
                    System.out.println("=== " + fileName + " ===");
                    
                    // Group by rule name
                    Map<String, List<Match>> grouped = new LinkedHashMap<>();
                    for (String m : matches) {
                        Match parsed = parseMatchLine(m);
                        if (parsed != null) {
                            grouped.computeIfAbsent(parsed.ruleName, k -> new ArrayList<>())
                                    .add(new Match(fileName, parsed.offset));
                        } else {
                            // Raw match without rule name
                            grouped.put("RAW", new ArrayList<>(1));
                            grouped.get("RAW").add(new Match(fileName, -1));
                        }
                    }

                    for (Map.Entry<String, List<Match>> entry : grouped.entrySet()) {
                        String ruleName = entry.getKey();
                        System.out.println("  Rule: " + ruleName);
                        
                        // Show unique offsets
                        Set<Integer> offsets = new LinkedHashSet<>();
                        for (Match m : entry.getValue()) {
                            if (m.offset >= 0) offsets.add(m.offset);
                        }

                        for (int offset : offsets) {
                            String context = getContext(file, offset, 40);
                            System.out.println("    Offset: " + offset);
                            System.out.println("    Context: " + context.replace("\n", "\\n"));
                        }
                    }
                    
                    totalMatches += matches.size();
                } else {
                    // Only print if we want verbose output for files with no matches
                    // Uncomment below to see all files scanned
                    // System.out.println("  (no matches in " + fileName + ")");
                }

            } catch (Exception e) {
                System.err.println("Error scanning " + file.getFileName() + ": " + e.getMessage());
            }
        }

        System.out.println();
        System.out.println("=== Summary ===");
        System.out.println("Total matches: " + totalMatches);
    }

    /**
     * Load rules from a directory (recursively).
     */
    private static List<Rule> loadRules(String rulePath) throws Exception {
        Path root = Paths.get(rulePath).toAbsolutePath().normalize();
        
        if (!Files.exists(root)) {
            return new ArrayList<>();
        }

        List<String> ruleFiles = Files.walk(root)
                .filter(p -> p.toString().endsWith(".yar"))
                .map(Path::toString)
                .toList();

        if (ruleFiles.isEmpty()) {
            return new ArrayList<>();
        }

        StringBuilder combined = new StringBuilder();
        
        for (String file : ruleFiles) {
            try (BufferedReader br = Files.newBufferedReader(Paths.get(file))) {
                String line;
                while ((line = br.readLine()) != null) {
                    // Remove comments
                    int commentIdx = line.indexOf("//");
                    if (commentIdx >= 0) {
                        line = line.substring(0, commentIdx);
                    }
                    combined.append(line).append("\n");
                }
            }
        }

        return RuleParser.parse(combined.toString());
    }

    /**
     * Create a demo rule for testing.
     */
    private static Rule createDemoRule() {
        String demoContent = 
            "rule DemoStringScanner {\n" +
            "  conditions:\n" +
            "    re(\"\\\\b(password|secret|api_key)\\\\b\", i)\n" +
            "    str(\"TODO\")\n" +
            "    ascii(\"FIXME\")\n" +
            "}\n";

        List<Condition> conditions = new ArrayList<>();
        
        // Parse the demo rule manually for this one
        Pattern rePattern = Pattern.compile("re\\s*\\(\\s*\"([^\"]+)\"\\s*,?\\s*(i|I)?\\s*\\)", 
            Pattern.CASE_INSENSITIVE);
        Matcher m = rePattern.matcher(demoContent);
        while (m.find()) {
            String pattern = m.group(1).trim();
            conditions.add(new Condition(pattern, true));
        }

        return new Rule(new RuleParser() {{
            ruleName = "DemoStringScanner";
            parseConditions(demoContent, this.conditions);
        }});
    }

    /**
     * Match a single file against all rules.
     */
    private static List<String> matchFile(Path file, List<Rule> rules) throws Exception {
        List<String> matches = new ArrayList<>();
        
        // Read entire file content
        String content;
        try (BufferedReader br = Files.newBufferedReader(file)) {
            StringBuilder sb = new StringBuilder();
            int lineNum = 0;
            String line;
            
            while ((line = br.readLine()) != null) {
                lineNum++;
                sb.append(line).append("\n");
                
                // Check each rule against this line
                for (Rule r : rules) {
                    for (Condition c : r.conditions) {
                        if (c.isRegex) {
                            Pattern p = Pattern.compile(c.pattern, 
                                c.isRegex ? 0 : Pattern.CASE_INSENSITIVE);
                            
                            Matcher matcher = p.matcher(line);
                            while (matcher.find()) {
                                matches.add(formatMatch(r.name, lineNum, matcher.start(), matcher.end()));
                            }
                        } else {
                            // Literal string match
                            if (line.contains(c.pattern)) {
                                int start = line.indexOf(c.pattern);
                                int end = start + c.pattern.length();
                                
                                // Find all occurrences
                                while (start >= 0) {
                                    matches.add(formatMatch(r.name, lineNum, start, end));
                                    
                                    String after = line.substring(end);
                                    if (!after.isEmpty() && after.startsWith(c.pattern)) {
                                        start = end;
                                        end += c.pattern.length();
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            content = sb.toString();
        }

        return matches;
    }

    /**
     * Format a match line for output.
     */
    private static String formatMatch(String ruleName, int lineNum, int start, int end) {
        // Escape special characters in pattern
        String escapedPattern = escapeRegex(ruleName);
        
        return String.format(
            "  Rule: %s | Line: %d | Offset: %d-%d | Pattern: \"%s\"",
            ruleName, lineNum, start, end, escapedPattern
        );
    }

    /**
     * Escape regex special chars for display.
     */
    private static String escapeRegex(String input) {
        return input.replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace("\n", "\\n");
    }

    /**
     * Parse a match line back into components.
     */
    private static Match parseMatchLine(String line) {
    if (line == null || !line.contains("Rule:")) return null;
    
    // Extract rule name
    int ruleStart = line.indexOf("Rule: ") + 6;
    int ruleEnd = line.indexOf("|", ruleStart);
    String ruleName = line.substring(ruleStart, ruleEnd).trim();
    
    // Extract offset range
    int offsetStart = line.indexOf("Offset:") + 8;
    int offsetEnd = line.indexOf("-", offsetStart);
    if (offsetEnd < 0) return null;
    
    try {
        int start = Integer.parseInt(line.substring(offsetEnd + 1).trim());
        int end = line.indexOf("|", offsetEnd) - 1;
        int actualEnd = line.indexOf("Pattern:", end) > 0 ? 
                       line.indexOf("Pattern:", end) : line.length();
        
        return new Match(ruleName, start);
    } catch (Exception e) {
        return null;
    }
}

    /**
     * Get context around an offset.
     */
    private static String getContext(Path file, int offset, int radius) throws IOException {
        if (offset < 0 || offset >= Integer.MAX_VALUE) {
            return "Unknown";
        }
        
        // Read file as bytes and find line containing offset
        byte[] content = Files.readAllBytes(file);
        
        // Find which line contains the offset
        int lineStart = -1;
        for (int i = 0; i < content.length && lineStart == -1; i++) {
            if (content[i] == '\n') {
                if (i >= offset) {
                    lineStart = i + 1; // After newline
                    break;
                } else if (lineStart != -1 && i - lineStart <= radius * 2) {
                    lineStart = i + 1;
                }
            }
        }
        
        if (lineStart == -1 || lineStart > offset) {
            // Fallback: just read around the offset
            int safeOffset = Math.max(0, offset - radius);
            int safeEnd = Math.min(content.length, offset + 2 * radius + 1);
            
            return new String(content, safeOffset, 
                safeEnd - safeOffset).replace("\n", "\\n");
        }
        
        // Extract line content
        byte[] lineBytes = Arrays.copyOfRange(content, lineStart, 
            Math.min(content.length, lineStart + radius * 2 + 1));
        
        return new String(lineBytes).trim();
    }

    /**
     * Simple match container for internal use.
     */
    private static class Match {
        final String ruleName;
        final int offset;

        Match(String ruleName, int offset) {
            this.ruleName = ruleName;
            this.offset = offset;
        }
    }
}