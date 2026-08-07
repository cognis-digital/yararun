import java.io.*;
import java.nio.file.*;
import java.util.*;

public class scan_directory {
    public static void main(String[] args) {
        if (args.length < 2) {
            System.err.println("Usage: java scan_directory <directory> <rule>");
            return;
        }

        String directoryPath = args[0];
        String rule = args[1];

        try {
            Files.walk(Paths.get(directoryPath))
                 .filter(Files::isRegularFile)
                 .forEach(file -> {
                     try {
                         byte[] content = Files.readAllBytes(file);
                         if (matchesRule(content, rule)) {
                             System.out.println("Match found in: " + file);
                         }
                     } catch (IOException e) {
                         System.err.println("Error reading file: " + file);
                         e.printStackTrace();
                     }
                 });
        } catch (IOException e) {
            System.err.println("Error walking directory: " + directoryPath);
            e.printStackTrace();
        }
    }

    private static boolean matchesRule(byte[] content, String rule) {
        // Simple regex-based rule matching for demonstration
        // Replace this with actual YARA-like parsing if needed
        return content.length > 0 && new String(content).matches(rule);
    }
}