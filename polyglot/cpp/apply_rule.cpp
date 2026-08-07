#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>
#include <vector>
#include <regex>

namespace fs = std::filesystem;

// Rule structure to represent a YARA-style rule
struct Rule {
    std::string name;
    std::string pattern;
    bool is_regex = false;
};

// Function to compile and apply a rule to a file
bool applyRule(const std::string& filePath, const Rule& rule) {
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "Error opening file: " << filePath << std::endl;
        return false;
    }

    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    try {
        if (rule.is_regex) {
            std::regex regexPattern(rule.pattern);
            if (std::regex_search(content, regexPattern)) {
                std::cout << "Matched rule \"" << rule.name << "\" in file: " << filePath << std::endl;
                return true;
            }
        } else {
            if (content.find(rule.pattern) != std::string::npos) {
                std::cout << "Matched rule \"" << rule.name << "\" in file: " << filePath << std::endl;
                return true;
            }
        }
    } catch (const std::regex_error& e) {
        std::cerr << "Regex error in rule \"" << rule.name << "\": " << e.what() << std::endl;
        return false;
    }

    return false;
}

// Function to apply rules to all files in a directory
void applyRulesToDirectory(const fs::path& dirPath, const std::vector<Rule>& rules) {
    for (const auto& entry : fs::directory_iterator(dirPath)) {
        if (entry.is_regular_file()) {
            for (const auto& rule : rules) {
                if (applyRule(entry.path().string(), rule)) {
                    // Optional: break early if needed
                }
            }
        }
    }
}

int main() {
    // Example YARA-style rules
    std::vector<Rule> rules = {
        {"ExampleStringRule", "secret_password", false},
        {"ExampleRegexRule", R"(\bpassword\s*=\s*"([^"]*)"\b)", true}
    };

    // Apply rules to all files in the current directory
    applyRulesToDirectory(fs::current_path(), rules);

    return 0;
}