#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <ctype.h>
#include <regex.h>

#define MAX_RULES 64
#define MAX_MATCHES 1024
#define MAX_PATH_LEN 4096
#define DEFAULT_PATTERN ".*"

typedef struct {
    char *name;
    char *pattern;
    int flags;
} rule_t;

typedef struct {
    char file[MAX_PATH_LEN];
    char match[MAX_PATH_LEN];
    size_t offset;
    size_t len;
} match_t;

static int g_matches = 0;
static match_t g_match_buf[MAX_MATCHES];

/* Compile a simple regex pattern (basic subset) */
static int compile_pattern(const char *pat, regex_t *re, int flags) {
    re->regex_len = 0;
    re->flags = REG_EXTENDED | REG_NOSUB | flags;
    
    if (!pat || !*pat) {
        pat = DEFAULT_PATTERN;
    }
    
    /* Escape special chars except . and * */
    char escaped[MAX_PATH_LEN];
    size_t i, j = 0;
    for (i = 0; pat[i] && j < MAX_PATH_LEN - 1; i++) {
        if (pat[i] == '.' || pat[i] == '*' || pat[i] == '?' || 
            pat[i] == '[' || pat[i] == ']' || pat[i] == '(' || 
            pat[i] == ')' || pat[i] == '{' || pat[i] == '|' || 
            pat[i] == '\\' || pat[i] == '$') {
            escaped[j++] = '\\';
        }
        escaped[j++] = pat[i];
    }
    escaped[j] = '\0';
    
    int ret = regcomp(re, escaped, re->flags);
    if (ret) {
        char errbuf[256];
        regerror(ret, re, errbuf, sizeof(errbuf));
        fprintf(stderr, "Pattern compile error: %s\n", errbuf);
    }
    return ret;
}

/* Search a file for pattern matches */
static int search_file(const char *filepath, rule_t *rule) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) return 0;
    
    size_t total_size = 0;
    unsigned char *buf = NULL;
    char match_str[MAX_PATH_LEN] = "";
    
    /* Get file size */
    fseek(fp, 0, SEEK_END);
    total_size = ftell(fp);
    rewind(fp);
    
    if (total_size == 0) {
        fclose(fp);
        return 0;
    }
    
    buf = malloc(total_size + 1);
    if (!buf) {
        fclose(fp);
        return -1;
    }
    
    size_t read_len = fread(buf, 1, total_size, fp);
    fclose(fp);
    buf[read_len] = '\0';
    
    regex_t re;
    int ret = compile_pattern(rule->pattern, &re, rule->flags);
    if (ret) {
        free(buf);
        return 0;
    }
    
    /* Search for matches */
    size_t offset = 0;
    while ((offset = regexec(&re, (char*)buf, 1, NULL, NOSTDREGS)) == 0) {
        if (g_matches < MAX_MATCHES - 1) {
            g_match_buf[g_matches].offset = offset;
            g_match_buf[g_matches].len = 0; /* Full match */
            strncpy(g_match_buf[g_matches].file, filepath, MAX_PATH_LEN - 1);
            
            /* Extract matched text for display */
            size_t end = (offset + re->match_len) < read_len ? 
                         offset + re->match_len : read_len;
            strncpy(match_str, buf + offset, end - offset);
            g_match_buf[g_matches].len = end - offset;
            
            if (g_matches == 0) {
                snprintf(g_match_buf[g_matches].match, MAX_PATH_LEN, 
                         "%s", match_str);
            } else {
                /* Concatenate for multi-match display */
                char tmp[MAX_PATH_LEN * 2];
                strncpy(tmp, g_match_buf[0].match, MAX_PATH_LEN - 1);
                strcat(tmp, " ");
                strcat(tmp, match_str);
                strncpy(g_match_buf[g_matches].match, tmp, MAX_PATH_LEN - 1);
            }
            
            g_matches++;
        }
        
        if (re->match_len > 0) {
            offset += re->match_len;
        } else {
            break; /* No more matches */
        }
    }
    
    regfree(&re);
    free(buf);
    
    return g_matches > 0;
}

/* Recursively scan directory for files */
static void scan_directory(const char *dirpath, rule_t *rule) {
    DIR *dp = opendir(dirpath);
    if (!dp) return;
    
    struct dirent *entry;
    while ((entry = readdir(dp)) != NULL) {
        size_t len = strlen(entry->d_name);
        
        /* Skip . and .. */
        if (len < 2 || 
            (strncmp(entry->d_name, ".", 1) == 0 && 
             (len == 1 || strncmp(entry->d_name + 1, "..", 1) == 0))) {
            continue;
        }
        
        char fullpath[MAX_PATH_LEN];
        snprintf(fullpath, MAX_PATH_LEN, "%s/%s", dirpath, entry->d_name);
        
        struct stat st;
        if (stat(fullpath, &st) == 0 && S_ISDIR(st.st_mode)) {
            scan_directory(fullpath, rule);
        } else if (S_ISREG(st.st_mode)) {
            search_file(fullpath, rule);
        }
    }
    
    closedir(dp);
}

/* Print all matches found */
static void print_matches(void) {
    for (int i = 0; i < g_matches; i++) {
        printf("MATCH: %s\n", g_match_buf[i].file);
        if (g_match_buf[i].len > 0) {
            printf("  Text: %.128s...\n", g_match_buf[i].match);
        } else {
            printf("  Offset: %zu\n", g_match_buf[i].offset);
        }
    }
}

/* Reset state */
static void reset_state(void) {
    g_matches = 0;
    memset(g_match_buf, 0, sizeof(g_match_buf));
}

/* Main apply_rule function - the core capability */
int apply_rule(const char *dirpath, const char *pattern, int flags) {
    if (!dirpath || !*dirpath) {
        fprintf(stderr, "Error: No directory specified\n");
        return 1;
    }
    
    reset_state();
    
    rule_t rule;
    rule.name = NULL;
    rule.pattern = pattern ? strdup(pattern) : DEFAULT_PATTERN;
    rule.flags = flags;
    
    /* Compile the pattern */
    regex_t re;
    if (compile_pattern(rule.pattern, &re, rule.flags)) {
        free(rule.pattern);
        return 1;
    }
    
    /* Scan directory */
    scan_directory(dirpath, &rule);
    
    regfree(&re);
    free(rule.pattern);
    
    printf("Scanned: %s\n", dirpath);
    printf("Pattern: %.64s...\n", rule.pattern ? rule.pattern : DEFAULT_PATTERN);
    printf("Matches found: %d\n", g_matches);
    
    if (g_matches > 0) {
        print_matches();
    } else {
        printf("No matches found.\n");
    }
    
    return g_matches;
}

/* Demo/test harness */
static void run_demo(void) {
    const char *test_dir = ".";
    const char *test_pattern = "password|secret|admin";
    
    printf("=== YARA-Style Rule Scanner Demo ===\n\n");
    
    int result = apply_rule(test_dir, test_pattern);
    
    printf("\n--- Summary ---\n");
    if (result == 0) {
        printf("SUCCESS: Scan completed\n");
    } else {
        printf("RESULT: %d matches found\n", g_matches);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <directory> [pattern]\n", argv[0]);
        fprintf(stderr, "       pattern defaults to: .*\n");
        return 1;
    }
    
    const char *dir = argv[1];
    int flags = REG_EXTENDED | REG_NOSUB;
    
    if (argc >= 3) {
        flags |= REG_ICASE; /* Case-insensitive by default */
    }
    
    return apply_rule(dir, NULL, flags);
}