import { promises as fs } from 'fs';
import { join, readdir, stat } from 'fs/promises';
import { parse } from 'path';

// Define the structure of a YARA rule
interface YaraRule {
  id: string;
  strings: Array<{
    name: string;
    content: string;
    type: 'string' | 'regex';
  }>;
}

// Define the structure of a match result
interface MatchResult {
  ruleId: string;
  filePath: string;
  matches: Array<{
    name: string;
    content: string;
    offset: number;
    length: number;
  }>;
}

// Function to apply a YARA rule to a file
async function applyRuleToContent(rule: YaraRule, content: string): Promise<MatchResult | null> {
  const matches: Array<{
    name: string;
    content: string;
    offset: number;
    length: number;
  }> = [];

  for (const str of rule.strings) {
    let match;
    if (str.type === 'string') {
      // Simple string match
      const escapedStr = str.content.replace(/([.*+?^${}()|[\]\\])/g, '\\$1');
      const regex = new RegExp(escapedStr, 'g');
      while ((match = regex.exec(content)) !== null) {
        matches.push({
          name: str.name,
          content: match[0],
          offset: match.index,
          length: match[0].length,
        });
      }
    } else if (str.type === 'regex') {
      // Regex match
      const regex = new RegExp(str.content, 'g');
      while ((match = regex.exec(content)) !== null) {
        matches.push({
          name: str.name,
          content: match[0],
          offset: match.index,
          length: match[0].length,
        });
      }
    }
  }

  if (matches.length > 0) {
    return {
      ruleId: rule.id,
      filePath: '',
      matches,
    };
  }
  return null;
}

// Function to apply a YARA rule to all files in a directory
async function applyRuleToDirectory(rule: YaraRule, dirPath: string): Promise<MatchResult[]> {
  const results: MatchResult[] = [];

  const entries = await readdir(dirPath, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = join(dirPath, entry.name);
    const stats = await stat(fullPath);

    if (stats.isDirectory()) {
      const subResults = await applyRuleToDirectory(rule, fullPath);
      results.push(...subResults);
    } else if (stats.isFile()) {
      const content = await fs.readFile(fullPath, 'utf-8');
      const result = await applyRuleToContent(rule, content);
      if (result) {
        result.filePath = fullPath;
        results.push(result);
      }
    }
  }

  return results;
}

// Example YARA rule
const exampleRule: YaraRule = {
  id: 'example_rule',
  strings: [
    {
      name: 'example_string',
      content: 'hello world',
      type: 'string',
    },
    {
      name: 'example_regex',
      content: '\\d{3}-\\d{3}-\\d{4}',
      type: 'regex',
    },
  ],
};

// Entry point to run the tool
async function main() {
  const dirPath = process.argv[2] || './test_directory';
  console.log(`Applying rule to directory: ${dirPath}`);

  try {
    const matches = await applyRuleToDirectory(exampleRule, dirPath);
    if (matches.length === 0) {
      console.log('No matches found.');
    } else {
      console.log(`Found ${matches.length} matches:`);
      for (const match of matches) {
        console.log(`- Rule: ${match.ruleId}`);
        console.log(`  File: ${match.filePath}`);
        for (const m of match.matches) {
          console.log(`  Match: ${m.name} at offset ${m.offset}, content: "${m.content}"`);
        }
      }
    }
  } catch (error) {
    console.error('Error applying rule:', error);
  }
}

// Run the main function
main();