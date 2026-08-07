import { promises as fs } from 'fs';
import { join, readdir, existsSync } from 'path';

interface Rule {
  id: string;
  text: string;
  regex: boolean;
}

interface Match {
  ruleId: string;
  filePath: string;
  content: string;
  matches: Array<{ offset: number; length: number }>;
}

async function scanDirectory(directoryPath: string, rules: Rule[]): Promise<Match[]> {
  const matches: Match[] = [];

  // Check if the directory exists
  if (!existsSync(directoryPath)) {
    throw new Error(`Directory not found: ${directoryPath}`);
  }

  // Read all files in the directory
  const files = await readdir(directoryPath, { withFileTypes: true });

  for (const file of files) {
    if (file.isDirectory()) continue; // Skip directories

    const filePath = join(directoryPath, file.name);
    const content = await fs.readFile(filePath, 'utf-8');

    // Check each rule against the file content
    for (const rule of rules) {
      const regex = new RegExp(rule.text, 'g');
      let match;
      const fileMatches: Array<{ offset: number; length: number }> = [];

      while ((match = regex.exec(content)) !== null) {
        fileMatches.push({
          offset: match.index,
          length: match[0].length
        });
      }

      if (fileMatches.length > 0) {
        matches.push({
          ruleId: rule.id,
          filePath,
          content,
          matches: fileMatches
        });
      }
    }
  }

  return matches;
}

// Example usage
async function runDemo() {
  const directoryPath = './test-data'; // Replace with your directory path
  const rules: Rule[] = [
    {
      id: 'rule1',
      text: 'secret_key',
      regex: false
    },
    {
      id: 'rule2',
      text: '\\b[A-Z0-9]{8}\\b',
      regex: true
    }
  ];

  try {
    const results = await scanDirectory(directoryPath, rules);
    console.log('Matches found:');
    for (const match of results) {
      console.log(`Rule: ${match.ruleId}`);
      console.log(`File: ${match.filePath}`);
      console.log(`Matches: ${match.matches.map(m => `Offset: ${m.offset}, Length: ${m.length}`).join(', ')}`);
      console.log();
    }
  } catch (error) {
    console.error('Error scanning directory:', error);
  }
}

// Run the demo
runDemo();