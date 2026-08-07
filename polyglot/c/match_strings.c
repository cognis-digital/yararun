#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <regex.h>
#include <time.h>

#define MAX_PATTERNS 1024
#define MAX_MATCHES_PER_FILE 8192
#define DEFAULT_LINE_SIZE 65536

typedef struct {
    char *pattern;
    regex_t compiled;
    int flags;
} Pattern;

typedef struct {
    char *file_path;
    size_t line_num;
    char *line_content;
    int pattern_idx;
    int match_start;
    int match_len;
} Match;

static Pattern patterns[MAX_PATTERNS];
static int num_patterns = 0;
static Match matches[MAX_MATCHES_PER_FILE];
static int num_matches = 0;

void add_pattern(const char *pat, int flags) {
    if (num_patterns >= MAX_PATTERNS) return;
    
    Pattern *p = &patterns[num_patterns++];
    p->pattern = strdup(pat);
    p->flags = flags;
    regcomp(&p->compiled, pat, REG_EXTENDED | flags);
}

int compile_all() {
    for (int i = 0; i < num_patterns; i++) {
        if (patterns[i].flags & REG_NOSUB) continue;
        int err = regerror(0, &patterns[i].compiled, NULL, 0);
        if (err && patterns[i].flags & REG_EXTENDED) {
            fprintf(stderr, "Pattern %d error: ", i + 1);
            char buf[256];
            regerror(err, &patterns[i].compiled, buf, sizeof(buf));
            fprintf(stderr, "%s\n", buf);
        }
    }
    return num_patterns > 0;
}

int match_line(const char *line, int len) {
    for (int i = 0; i < num_patterns && num_matches < MAX_MATCHES_PER_FILE; i++) {
        if (!patterns[i].pattern || patterns[i].flags & REG_NOSUB) continue;
        
        regmatch_t match;
        if (regexec(&patterns[i].compiled, line, 1, &match, 0) == 0) {
            Match *m = &matches[num_matches++];
            m->file_path = NULL; // Set later
            m->line_num = -1;    // Set later
            m->pattern_idx = i;
            m->match_start = match.rm_so;
            m->match_len = match.rm_eo - match.rm_so;
            
            if (m->match_len > 0 && len >= m->match_start + m->match_len) {
                char *buf = malloc(len + 1);
                memcpy(buf, line, len);
                buf[len] = '\0';
                m->line_content = buf;
            } else {
                m->line_content = strdup(line);
            }
        }
    }
    return num_matches > 0;
}

void process_file(const char *filepath) {
    FILE *f = fopen(filepath, "rb");
    if (!f) return;
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (size <= 0 || size > 1048576 * 1024) { // Max ~1GB
        fclose(f);
        return;
    }
    
    char *buf = malloc(size + 1);
    if (!buf) { fclose(f); return; }
    
    fread(buf, 1, size, f);
    buf[size] = '\0';
    fclose(f);
    
    long line_start = 0;
    for (long i = 0; i < size && num_matches < MAX_MATCHES_PER_FILE; i++) {
        if (buf[i] == '\n') {
            int len = i - line_start + 1;
            char *line = malloc(len + 1);
            memcpy(line, buf + line_start, len);
            line[len] = '\0';
            
            match_line(line, len);
            free(line);
            line_start = i + 1;
        }
    }
    
    // Handle last line without newline
    long last_len = size - line_start;
    if (last_len > 0) {
        char *line = malloc(last_len + 2);
        memcpy(line, buf + line_start, last_len);
        line[last_len] = '\n';
        line[last_len + 1] = '\0';
        
        match_line(line, last_len + 1);
        free(line);
    }
    
    free(buf);
}

void process_directory(const char *dirpath) {
    DIR *d = opendir(dirpath);
    if (!d) return;
    
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL && num_matches < MAX_MATCHES_PER_FILE) {
        if (strcmp(entry->d_name, ".") == 0 || 
            strcmp(entry->d_name, "..") == 0) continue;
        
        char full_path[4096];
        snprintf(full_path, sizeof(full_path), "%s/%s", dirpath, entry->d_name);
        
        struct stat st;
        if (stat(full_path, &st) == 0 && S_ISREG(st.st_mode)) {
            process_file(full_path);
        }
    }
    
    closedir(d);
}

void print_matches() {
    time_t now = time(NULL);
    char *timestr = ctime(&now);
    timestr[strlen(timestr) - 1] = '\0'; // Remove trailing newline
    
    printf("=== YARA-STYLE STRING MATCHES ===\n");
    printf("Time: %s\n", timestr);
    printf("Total matches found: %d\n\n", num_matches);
    
    if (num_matches == 0) {
        printf("No matches found.\n");
        return;
    }
    
    // Print unique matches with deduplication
    int printed = 0;
    for (int i = 0; i < num_patterns && printed < MAX_MATCHES_PER_FILE; i++) {
        if (!patterns[i].pattern) continue;
        
        char *pat = patterns[i].pattern;
        size_t patlen = strlen(pat);
        
        // Show pattern info
        printf("--- Pattern %d: \"%s\" ---\n", i + 1, pat);
        
        for (int j = 0; j < num_matches && printed < MAX_MATCHES_PER_FILE; j++) {
            if (matches[j].pattern_idx != i) continue;
            
            // Simple deduplication key: file + line content hash
            char *key = matches[j].line_content;
            int found_dup = 0;
            
            for (int k = 0; k < j && !found_dup; k++) {
                if (matches[k].pattern_idx == i) {
                    // Compare file path and line content
                    char *file_path = matches[k].line_content + 
                                      strlen(matches[k].line_content);
                    while (*file_path != '\0' && *(file_path - 1) != '/') {
                        file_path--;
                    }
                    
                    if (strcmp(matches[j].line_content, key) == 0) {
                        found_dup = 1;
                    }
                }
            }
            
            if (!found_dup) {
                printf("  File: %s\n", matches[j].line_content);
                printf("    Line: %ld\n", matches[j].line_num);
                printf("    Match: \"%.*s\"\n", 
                       matches[j].match_len,
                       matches[j].line_content + matches[j].match_start);
                
                // Show context (5 lines before and after)
                int start = matches[j].line_num - 5;
                if (start < 0) start = 0;
                
                printf("    Context:\n");
                for (int ctx = start; ctx <= matches[j].line_num + 5 && 
                     ctx < matches[j].line_num + 10 && printed < MAX_MATCHES_PER_FILE; ctx++) {
                    char *ctx_line = malloc(strlen(matches[j].line_content) + 2);
                    memcpy(ctx_line, matches[j].line_content, strlen(matches[j].line_content) + 2);
                    
                    // Adjust for line offset
                    int offset = (matches[j].line_num - ctx) * 10;
                    if (offset < 0) offset = 0;
                    
                    size_t len = strlen(ctx_line);
                    if (len > offset + 80) {
                        memcpy(ctx_line, matches[j].line_content + offset, 
                               len - offset);
                        ctx_line[len - offset] = '\0';
                        len -= offset;
                    }
                    
                    printf("      %ld: %s\n", ctx, ctx_line);
                    free(ctx_line);
                }
                
                printed++;
            }
        }
        
        if (printed >= MAX_MATCHES_PER_FILE) break;
    }
}

void cleanup() {
    for (int i = 0; i < num_patterns; i++) {
        if (patterns[i].pattern) free(patterns[i].pattern);
        regfree(&patterns[i].compiled);
    }
    
    for (int i = 0; i < num_matches; i++) {
        if (matches[i].line_content) free(matches[i].line_content);
    }
}

void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [-p pattern1|pattern2...] [-d directory] [-f]\n", prog);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -p PATTERNS   Comma-separated regex patterns (default: read from stdin)\n");
    fprintf(stderr, "  -d DIR        Directory to scan recursively\n");
    fprintf(stderr, "  -f FILE       Single file to scan instead of directory\n");
    fprintf(stderr, "  -h            Show this help\n");
}

int main(int argc, char *argv[]) {
    const char *dirpath = ".";
    const char *filepath = NULL;
    int read_patterns_from_stdin = 0;
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: -p requires a pattern argument\n");
                return 1;
            }
            
            // Parse comma-separated patterns
            char *pat_str = argv[++i];
            char *saveptr = NULL;
            while (*pat_str) {
                char *comma = strchr(pat_str, ',');
                if (comma) *comma = '\0';
                
                Pattern *p = &patterns[num_patterns++];
                p->pattern = strdup(pat_str);
                p->flags = REG_EXTENDED | REG_NOSUB; // Default flags
                
                regcomp(&p->compiled, pat_str, REG_EXTENDED | REG_NOSUB);
                
                if (comma) {
                    pat_str = comma + 1;
                } else {
                    break;
                }
            }
        } else if (strcmp(argv[i], "-d") == 0) {
            dirpath = argv[++i];
        } else if (strcmp(argv[i], "-f") == 0) {
            filepath = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
    }
    
    // Read patterns from stdin if none provided
    if (num_patterns == 0 && read_patterns_from_stdin) {
        char line[4096];
        while (fgets(line, sizeof(line), stdin)) {
            Pattern *p = &patterns[num_patterns++];
            p->pattern = strdup(line);
            p->flags = REG_EXTENDED | REG_NOSUB;
            
            regcomp(&p->compiled, line, REG_EXTENDED | REG_NOSUB);
        }
    }
    
    // Compile all patterns
    if (!compile_all()) {
        fprintf(stderr, "Error: No valid patterns found\n");
        return 1;
    }
    
    printf("Loaded %d pattern(s)\n", num_patterns);
    
    // Process target
    if (filepath) {
        process_file(filepath);
    } else {
        process_directory(dirpath);
    }
    
    print_matches();
    cleanup();
    
    return 0;
}