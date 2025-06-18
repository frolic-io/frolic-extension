import * as fs from 'fs';
import * as path from 'path';

type LogEntry = {
  timestamp: string;
  eventType: string;
  relativePath: string;
  language: string;
  lineCount: number;
  changes?: {
    lineCountDelta: number;
    likelyAI?: boolean;
    changeText?: string;
  }[];
};

type Digest = {
  filesEdited: number;
  totalLinesAdded: number;
  aiInsertions: number;
  topFiles: string[];
  languagesUsed: Record<string, number>;
  inferredTopics: string[];
};

function loadLogs(): LogEntry[] {
  const logPath = path.resolve(process.cwd(), '.frolic-log.json');
  const raw = fs.readFileSync(logPath, 'utf-8');
  return JSON.parse(raw);
}

function analyzeLogs(logs: LogEntry[]): Digest {
  const files = new Set<string>();
  const langCounts: Record<string, number> = {};
  let totalLinesAdded = 0;
  let aiInsertions = 0;
  const fileActivity: Record<string, number> = {};
  const topicTags = new Set<string>();

  const tagKeywords: Record<string, string[]> = {
    react: ["useState", "useEffect", "React.FC", "JSX"],
    supabase: ["createClient", "from", "@supabase"],
    regex: ["/[a-z]+/", ".match(", ".test("],
    auth: ["Auth0", "Clerk", "login", "token", "session"],
    fetch: ["fetch(", "axios", "GET", "POST"],
    typescript: ["interface", "type", "enum", ": string"],
  };

  for (const entry of logs) {
    if (entry.eventType !== 'file_edit') continue;

    files.add(entry.relativePath);
    langCounts[entry.language] = (langCounts[entry.language] || 0) + 1;
    fileActivity[entry.relativePath] = (fileActivity[entry.relativePath] || 0) + 1;

    for (const change of entry.changes || []) {
      totalLinesAdded += change.lineCountDelta || 0;
      if (change.likelyAI) aiInsertions++;

      for (const [topic, keywords] of Object.entries(tagKeywords)) {
        if (keywords.some(kw => change.changeText?.includes(kw))) {
          topicTags.add(topic);
        }
      }
    }
  }

  const topFiles = Object.entries(fileActivity)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([file]) => file);

  return {
    filesEdited: files.size,
    totalLinesAdded,
    aiInsertions,
    topFiles,
    languagesUsed: langCounts,
    inferredTopics: Array.from(topicTags)
  };
}

function runAnalysis() {
  const logs = loadLogs();
  const summary = analyzeLogs(logs);

  console.log("🧠 Frolic Weekly Summary:");
  console.log(JSON.stringify(summary, null, 2));
}

runAnalysis(); 