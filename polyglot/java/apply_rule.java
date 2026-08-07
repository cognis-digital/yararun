package polyglot.java;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import java.util.stream.*;

/**
 * YARA-style rule engine for scanning directories.
 * Parses .yar/.yara files and matches strings against target content.
 */
public class ApplyRule {

    /** Represents a parsed YARA rule with compiled patterns. */
    public static class CompiledRule {
        String name;
        List<Pattern> stringPatterns = new ArrayList<>();
        Pattern conditionPattern;
        boolean caseSensitive = true;

        public CompiledRule(String name) { this.name = name; }

        /** Compile a YARA-style condition like "$a and $b or not $c" */
        static String compileCondition(String condition, List<Pattern> strings) {
            // Simple parser: find each string variable reference and check if it matched
            StringBuilder sb = new StringBuilder();
            for (String s : condition.split("\\s+")) {
                if (s.startsWith("$") && !s.equals("not")) {
                    String varName = s.substring(1);
                    // Find which pattern matches this variable name
                    int idx = -1;
                    for (int i = 0; i < strings.size(); i++) {
                        Pattern p = strings.get(i);
                        if (p.pattern().startsWith(varName)) {
                            idx = i;
                            break;
                        }
                    }
                    sb.append(idx >= 0 ? "(?:" + strings.get(idx).pattern() + ")" : "false");
                } else if (s.equals("and")) {
                    sb.append(" && ");
                } else if (s.equals("or")) {
                    sb.append(" || ");
                } else if (s.startsWith("not ")) {
                    String inner = s.substring(4);
                    int idx = -1;
                    for (int i = 0; i < strings.size(); i++) {
                        Pattern p = strings.get(i);
                        if (p.pattern().startsWith(inner)) {
                            idx = i;
                            break;
                        }
                    }
                    sb.append(idx >= 0 ? "!(" + strings.get(idx).pattern() + ")" : "!false");
                } else {
                    // Literal or unknown - treat as always true for simplicity
                    sb.append("true && ");
                }
            }
            return sb.toString();
        }

        /** Check if content matches this rule. */
        public boolean matches(String content) {
            try {
                String compiled = compileCondition(conditionPattern, stringPatterns);
                Pattern cond = Pattern.compile(compiled, caseSensitive ? 0 : Pattern.CASE_INSENSITIVE);
                return cond.matcher(content).find();
            } catch (Exception e) {
                // If condition parsing fails, fall back to checking any string match
                for (Pattern p : stringPatterns) {
                    if (p.matcher(content).find()) return true;
                }
                return false;
            }
        }
    }

    /** Result of scanning a single file. */
    public static class ScanResult {
        String path;
        List<CompiledRule> matches = new ArrayList<>();
        
        public ScanResult(String path) { this.path = path; }
    }

    /** Main entry point with demo. */
    public static void main(String[] args) throws Exception {
        // Demo: scan current directory for .yar rules and a sample file
        String ruleDir = ".";
        String targetFile = "sample.txt";

        if (args.length > 0) {
            ruleDir = args[0];
            if (args.length > 1) targetFile = args[1];
        }

        // Find all YARA rules in directory
        List<CompiledRule> rules = new ArrayList<>();
        
        try (Stream<Path> paths = Files.walk(Paths.get(ruleDir))) {
            paths.filter(p -> p.toString().endsWith(".yar") || 
                             p.toString().endsWith(".yara"))
                 .forEach(path -> {
                     try {
                         CompiledRule rule = parseYaraFile(path);
                         if (rule != null) rules.add(rule);
                     } catch (IOException e) {
                         System.err.println("Warning: could not read " + path + ": " + e.getMessage());
                     }
                 });
        }

        // If no target file specified, create a sample for demo
        if (!Files.exists(Paths.get(targetFile))) {
            Files.createDirectories(Paths.get(ruleDir));
            String sample = "This is a test file with some content.\n" +
                           "It contains the string hello world here!\n" +
                           "And maybe \"hello\" again later.";
            Files.write(Paths.get(targetFile), sample.getBytes());
        }

        // Scan target file against all rules
        if (Files.exists(Paths.get(targetFile))) {
            String content = new String(Files.readAllBytes(Paths.get(targetFile)));
            
            System.out.println("Scanning: " + targetFile);
            System.out.println("Found " + rules.size() + " YARA rule(s)");
            System.out.println();

            for (CompiledRule rule : rules) {
                if (rule.matches(content)) {
                    System.out.println("[MATCH] Rule: " + rule.name);
                    
                    // Show which strings matched
                    for (Pattern p : rule.stringPatterns) {
                        Matcher m = p.matcher(content);
                        while (m.find()) {
                            System.out.println("  -> Found: \"" + 
                                   escape(m.group()) + "\" at pos " + m.start());
                        }
                    }
                } else {
                    System.out.println("[NO MATCH] Rule: " + rule.name);
                }
            }
        } else {
            System.err.println("Target file not found: " + targetFile);
        }

        // Demo with embedded rules (no external files needed)
        System.out.println("\n--- Embedded Demo ---");
        demoEmbeddedRules();
    }

    /** Parse a .yar/.yara file into CompiledRule. */
    private static CompiledRule parseYaraFile(Path path) throws IOException {
        String content = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
        
        // Extract rule name from first line or comment
        String name = "Unnamed";
        int startIdx = 0;
        while (startIdx < content.length()) {
            int idx = content.indexOf("rule ", startIdx);
            if (idx == -1) break;
            
            int endIdx = content.indexOf("{", idx + 5);
            if (endIdx != -1) {
                String ruleNamePart = content.substring(idx, endIdx).trim();
                name = extractRuleName(ruleNamePart);
                startIdx = endIdx + 1;
                break;
            }
        }

        // Extract string patterns
        List<Pattern> strings = new ArrayList<>();
        
        // Simple regex to find "strings:" section and its contents
        String stringsSection = extractSection(content, "strings:", "{");
        if (stringsSection != null) {
            Pattern strRegex = Pattern.compile(
                "\\$\\w+\\s*=\\s*\"([^\"]+)\"\\s*(ascii|wide)?", 
                Pattern.CASE_INSENSITIVE);
            
            Matcher m = strRegex.matcher(stringsSection);
            while (m.find()) {
                String patternStr = m.group(1).replace("\\", "\\\\").replace("\"", "\\\"");
                strings.add(Pattern.compile(patternStr, 0)); // Default case-sensitive
            }
        }

        return new CompiledRule(name) {{
            this.stringPatterns = strings;
            this.conditionPattern = Pattern.compile("condition:\\s*(.+)");
        }};
    }

    /** Extract just the rule name from "rule Name {". */
    private static String extractRuleName(String line) {
        int braceIdx = line.indexOf('{');
        if (braceIdx == -1) return "Unnamed";
        
        // Remove everything after '{' and trim whitespace
        String beforeBrace = line.substring(0, braceIdx).trim();
        
        // Handle optional modifiers like "private", "global", etc.
        Pattern nameRegex = Pattern.compile("rule\\s+(\\w+)");
        Matcher m = nameRegex.matcher(beforeBrace);
        if (m.find()) {
            return m.group(1);
        }
        return "Unnamed";
    }

    /** Extract content between a marker and the next '{'. */
    private static String extractSection(String text, String marker, char open) {
        int start = text.indexOf(marker);
        if (start == -1) return null;
        
        // Find matching closing brace for this section
        int depth = 0;
        int end = start + marker.length();
        while (end < text.length()) {
            char c = text.charAt(end);
            if (c == open) depth++;
            else if (c == '}') depth--;
            
            if (depth == 0 && text.indexOf('{', end) != -1) break;
            end++;
        }
        
        return text.substring(start + marker.length(), end).trim();
    }

    /** Escape string for display. */
    private static String escape(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder(s.length() * 2);
        for (char c : s.toCharArray()) {
            switch (c) {
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 32 || c > 126) {
                        sb.append(String.format("\\u%04x", (int)c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    /** Demo with embedded rules - no external files required. */
    private static void demoEmbeddedRules() throws Exception {
        // Create a temporary directory with sample YARA rule
        Path tempDir = Files.createTempDirectory("yara-demo");
        
        try {
            // Write a sample YARA rule
            String yaraRule = 
                "rule HelloWorld {\n" +
                "    strings:\n" +
                "        $hello = \"hello\" ascii;\n" +
                "        $world = \"world\" ascii;\n" +
                "    condition:\n" +
                "        $hello and $world;\n" +
                "}\n";
            
            Path ruleFile = tempDir.resolve("test.yar");
            Files.write(ruleFile, yaraRule.getBytes());

            // Write a sample file that should match
            String matchingContent = 
                "Hello world! This is a test.\n" +
                "Another line with hello and world together.";
            
            Path targetFile = tempDir.resolve("target.txt");
            Files.write(targetFile, matchingContent.getBytes());

            // Write a non-matching file
            String nonMatchingContent = 
                "Hello there but no world here.\n" +
                "Just saying hi to everyone.";
            
            Path nonTargetFile = tempDir.resolve("non-target.txt");
            Files.write(nonTargetFile, nonMatchingContent.getBytes());

            // Scan both files
            System.out.println("Embedded Demo - Scanning files in: " + tempDir);
            System.out.println();

            for (Path file : Arrays.asList(targetFile, nonTargetFile)) {
                String content = new String(Files.readAllBytes(file));
                
                CompiledRule rule = parseYaraFile(ruleFile);
                boolean matched = rule.matches(content);
                
                if (matched) {
                    System.out.println("[MATCH] " + file.getFileName());
                    for (Pattern p : rule.stringPatterns) {
                        Matcher m = p.matcher(content);
                        while (m.find()) {
                            System.out.println("  -> \"" + escape(m.group()) + "\"");
                        }
                    }
                } else {
                    System.out.println("[NO MATCH] " + file.getFileName());
                }
            }

        } finally {
            // Clean up temp files
            Files.walk(tempDir)
                 .sorted(Comparator.reverseOrder())
                 .forEach(p -> { try { Files.deleteIfExists(p); } catch (IOException e) {} });
        }
    }
}