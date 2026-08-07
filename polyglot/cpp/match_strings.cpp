#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <regex>
#include <filesystem>
#include <algorithm>
#include <iomanip>
#include <memory>

namespace fs = std::filesystem;

// Configuration defaults
constexpr size_t CHUNK_SIZE = 64 * 1024; // 64KB chunks for memory efficiency
constexpr int CONTEXT_LINES = 3;          // Lines of context around match

// Rule structure - supports named patterns with regex
struct MatchRule {
    std::string name;
    std::vector<std::regex> patterns;
};

// Result tracking to avoid duplicates
class MatchResult {
public:
    struct Entry {
        fs::path file_path;
        size_t offset;
        std::string pattern_name;
        std::string matched_text;
        
        bool operator<(const Entry& other) const {
            if (file_path != other.file_path) return file_path < other.file_path;
            if (offset != other.offset) return offset < other.offset;
            return pattern_name < other.pattern_name;
        }
    };

private:
    std::vector<Entry> results;
    
public:
    void add(const Entry& e) {
        // Check for duplicates before adding
        bool exists = false;
        for (const auto& existing : results) {
            if (existing.file_path == e.file_path && 
                existing.offset == e.offset &&
                existing.pattern_name == e.pattern_name) {
                exists = true;
                break;
            }
        }
        
        if (!exists) {
            results.push_back(e);
        }
    }

    void sort() {
        std::sort(results.begin(), results.end());
    }

    size_t count() const { return results.size(); }

    // Output formatted results
    void output(std::ostream& out, bool verbose = false) const {
        if (results.empty()) {
            out << "No matches found.\n";
            return;
        }

        out << "\n=== YARA-STYLE MATCH RESULTS ===\n\n";
        
        // Group by file for cleaner output
        std::vector<std::pair<fs::path, std::vector<Entry>>> grouped;
        for (const auto& entry : results) {
            auto it = std::find_if(grouped.begin(), grouped.end(),
                [&entry](const auto& p) { return p.first == entry.file_path; });
            
            if (it != grouped.end()) {
                it->second.push_back(entry);
            } else {
                grouped.emplace_back(entry.file_path, std::vector<Entry>{entry});
            }
        }

        for (const auto& [filepath, entries] : grouped) {
            out << "\n--- " << filepath << " ---\n";
            
            for (size_t i = 0; i < entries.size(); ++i) {
                const auto& e = entries[i];
                
                // Extract context from file
                std::string context;
                if (!e.file_path.empty()) {
                    try {
                        std::ifstream f(e.file_path, std::ios::binary);
                        if (f.is_open()) {
                            std::ostringstream buf;
                            
                            // Read lines around the match
                            size_t line_start = e.offset / 80; // Approximate line number
                            size_t line_end = line_start + CONTEXT_LINES * 2 + 1;
                            
                            while (line_start > 0 && f.tellg() < static_cast<std::streampos>(e.offset)) {
                                buf << "\n";
                                --line_start;
                            }
                            
                            for (; line_start <= line_end; ++line_start) {
                                std::string line;
                                while (f.good()) {
                                    char c = f.get();
                                    if (c == '\n') break;
                                    if (!line.empty() && !line.back().isspace()) line += ' ';
                                    line += c;
                                }
                                buf << line << "\n";
                            }
                            
                            context = buf.str();
                        }
                    } catch (...) {
                        // File read error, use offset as fallback
                        std::ostringstream oss;
                        oss << "Offset: 0x" << std::hex << e.offset << std::dec << "\n";
                        context = oss.str();
                    }
                }

                out << "  Pattern: " << e.pattern_name << "\n";
                out << "  Offset:  " << std::hex << e.offset << std::dec << "\n";
                out << "  Match:   '" << e.matched_text << "'\n\n" << context;
            }
        }

        out << "\n=== SUMMARY ===\n";
        out << "Total matches: " << results.size() << "\n";
    }
};

// Parse a single rule definition from string
MatchRule parse_rule(const std::string& line) {
    MatchRule rule;
    
    // Extract name (everything before first colon or pipe)
    size_t name_end = 0;
    for (size_t i = 0; i < line.size(); ++i) {
        if (line[i] == ':' || line[i] == '|') {
            name_end = i;
            break;
        }
    }
    
    rule.name = line.substr(0, name_end).trim();
    
    // Extract regex pattern(s) after the delimiter
    std::string patterns_str = line.substr(name_end + 1);
    
    if (!patterns_str.empty()) {
        // Split by comma for multiple patterns in one rule
        std::vector<std::string> pattern_strings;
        
        size_t start = 0, end = 0;
        while (end < patterns_str.size() && !patterns_str[end].isspace()) {
            if (end == 0 || patterns_str[end-1] == ',') {
                start = end;
            }
            ++end;
        }
        
        // Trim and add pattern
        std::string trimmed(patterns_str.substr(start, end - start));
        if (!trimmed.empty()) {
            rule.patterns.push_back(std::regex(trimmed));
        }
    }

    return rule;
}

// Helper to trim whitespace
std::string& trim(std::string& s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(0, 1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\n')) s.pop_back();
    return s;
}

// Scan a single file for all patterns
void scan_file(const fs::path& filepath, const std::vector<MatchRule>& rules, 
               MatchResult& result) {
    if (!fs::exists(filepath)) return;
    
    // Try to read as text first (faster), then binary if needed
    try {
        std::ifstream file(filepath, std::ios::binary);
        if (!file.is_open()) return;

        size_t total_size = 0;
        if (fs::is_regular_file(filepath)) {
            total_size = fs::file_size(filepath);
        } else {
            // For large files or directories, estimate with chunks
            total_size = CHUNK_SIZE * 1024; // Default for non-regular files
        }

        // Read file in chunks and search each chunk
        std::vector<char> buffer(CHUNK_SIZE);
        size_t offset = 0;
        
        while (offset < total_size) {
            size_t bytes_to_read = std::min(total_size - offset, static_cast<size_t>(CHUNK_SIZE));
            
            file.read(buffer.data(), bytes_to_read);
            if (!file.gcount()) break;

            // Search this chunk against all patterns
            for (const auto& rule : rules) {
                for (auto& pattern : rule.patterns) {
                    std::smatch match;
                    
                    // Find first occurrence in this chunk
                    size_t search_start = 0;
                    while (search_start < bytes_to_read) {
                        if (std::regex_search(buffer.data() + search_start, 
                                              buffer.data() + bytes_to_read, 
                                              pattern, match)) {
                            
                            // Calculate absolute offset
                            size_t abs_offset = offset + match.position();
                            
                            // Extract matched text
                            std::string matched_text;
                            if (match.length() > 0) {
                                matched_text.assign(match[0].first, 
                                                     match[0].second);
                            }

                            result.add({filepath, abs_offset, rule.name, matched_text});
                            
                            // Skip past this match to avoid duplicate reports
                            search_start = match.position() + match.length();
                        } else {
                            ++search_start;
                        }
                    }
                }
            }

            offset += bytes_to_read;
        }
        
        file.close();
    } catch (const std::exception& e) {
        // Log error but continue scanning
        std::cerr << "Warning: Error reading " << filepath << ": " << e.what() << "\n";
    }
}

// Recursively scan directory tree
void scan_directory(const fs::path& root, const std::vector<MatchRule>& rules, 
                   MatchResult& result) {
    for (const auto& entry : fs::recursive_directory_iterator(root)) {
        if (fs::is_regular_file(entry)) {
            // Skip common non-text files unless explicitly included
            std::string ext = entry.extension().string();
            
            bool is_text_like = true;
            const char* text_extensions[] = {".txt", ".c", ".h", ".cpp", ".hpp", 
                                             ".py", ".js", ".html", ".css", ".xml", 
                                             ".json", ".log", ".ini", ".cfg", ".conf",
                                             ".sh", ".bat", ".cmd", ".yaml", ".yml"};
            
            for (const char* tex : text_extensions) {
                if (ext == tex) { is_text_like = false; break; }
            }

            // For binary files, only scan if they're small or contain null bytes < 50%
            bool is_binary = !is_text_like && ext.empty();
            
            if (!is_binary || entry.file_size() < 10 * 1024 * 1024) {
                // Check if file contains mostly non-null bytes (likely text-ish binary)
                if (is_binary && entry.file_size() > 1024) {
                    std::ifstream f(entry, std::ios::binary);
                    size_t null_count = 0;
                    size_t total_bytes = 0;
                    
                    while (f.get()) {
                        ++total_bytes;
                        if (!f.peek()) break; // Check before reading next byte
                        f.ignore(1);
                    }
                    
                    if (total_bytes > 0 && null_count / static_cast<double>(total_bytes) < 0.5) {
                        scan_file(entry, rules, result);
                    }
                } else {
                    scan_file(entry, rules, result);
                }
            }
        }
    }
}

// Parse command-line arguments
int main(int argc, char* argv[]) {
    // Default configuration
    std::string root_dir = ".";
    std::vector<MatchRule> rules;
    
    // Build default patterns (YARA-style common signatures)
    auto add_default_patterns = [&rules]() {
        // Email addresses
        rules.push_back({ "Email", 
            std::regex(R"(^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$)") });
        
        // IP addresses (IPv4)
        rules.push_back({ "IPv4_Address", 
            std::regex(R"(\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b)") });
        
        // UUIDs
        rules.push_back({ "UUID", 
            std::regex(R"(\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b)") });
        
        // Base64 encoded strings (long sequences)
        rules.push_back({ "Base64_String", 
            std::regex(R"(\b[A-Za-z0-9+/]{50,}={0,2}\b)") });
        
        // Hex dumps of potential binary data
        rules.push_back({ "Hex_Dump", 
            std::regex(R"(0x[0-9a-fA-F]{4,}(?:\s*[,;=]\s*)?[0-9a-fA-F]{2})") });
    };
    
    add_default_patterns();

    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--help" || arg == "-h") {
            std::cout << "yararun - YARA-style string matcher\n\n";
            std::cout << "Usage: yararun [OPTIONS] <directory>\n\n";
            std::cout << "Options:\n";
            std::cout << "  --rules <file>    Load additional rules from file (YAML/JSON format)\n";
            std::cout << "  --pattern <regex> Add a custom regex pattern with name 'Custom'\n";
            std::cout << "  --chunk-size N    Set chunk size in bytes (default: 65536)\n";
            std::cout << "  --context N       Set context lines around match (default: 3)\n";
            std::cout << "  --quiet           Suppress progress output\n";
            std::cout << "  --help, -h        Show this help message\n";
            return 0;
        }

        if (arg == "--pattern" && i + 1 < argc) {
            rules.push_back({ "Custom", 
                std::regex(argv[++i]) });
        } else if (arg == "--chunk-size") {
            CHUNK_SIZE = std::stoul(argv[++i]);
        } else if (arg == "--context") {
            CONTEXT_LINES = std::stoi(argv[++i]);
        } else if (!arg.empty() && arg[0] != '-') {
            root_dir = arg;
        }
    }

    // Validate directory exists
    if (!fs::exists(root_dir) || !fs::is_directory(root_dir)) {
        std::cerr << "Error: Directory does not exist: " << root_dir << "\n";
        return 1;
    }

    // Perform scan
    MatchResult results;
    
    std::cout << "Scanning directory: " << root_dir << "\n";
    std::cout << "Rules loaded: " << rules.size() << "\n";
    std::cout << "Chunk size: " << CHUNK_SIZE << " bytes\n";
    std::cout << "Context lines: " << CONTEXT_LINES << "\n\n";

    scan_directory(root_dir, rules, results);

    // Output results
    results.output(std::cout);

    return 0;
}