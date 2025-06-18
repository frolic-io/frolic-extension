import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import * as crypto from 'crypto';
const fetch = require('node-fetch');

const LOG_BUFFER: any[] = [];
const MAX_CHANGE_TEXT_LENGTH = 2000; // Truncate very large code changes
let isLoggingEnabled = true;
let sessionId = uuidv4();
let digestTimer: NodeJS.Timeout | null = null;
let bufferMemoryUsage = 0; // Track estimated memory usage in bytes
let statusBarItem: vscode.StatusBarItem;
let activityProvider: FrolicActivityProvider | undefined;
let extensionContext: vscode.ExtensionContext | undefined;

// Get configurable limits
function getBufferLimits() {
    const config = vscode.workspace.getConfiguration('frolic');
    return {
        maxBufferSize: config.get<number>('maxBufferSize', 10000),
        maxMemoryMB: config.get<number>('maxMemoryMB', 50)
    };
}

function logEvent(eventType: string, data: any) {
    if (!isLoggingEnabled) return;

    const filePath = data.file ?? "";
    if (filePath.includes(".git") || filePath.startsWith("git/") || filePath === "exthost") return;

    const entry = {
        timestamp: new Date().toISOString(),
        sessionId,
        eventType,
        file: filePath,
        relativePath: vscode.workspace.asRelativePath(filePath),
        language: data.language ?? "unknown",
        lineCount: data.lineCount ?? 0,
        isDirty: data.isDirty ?? false,
        isUntitled: data.isUntitled ?? false,
        cursorPosition: data.cursorPosition ?? null,
        selectionLength: data.selectionLength ?? 0,
        changes: (data.changes ?? []).map((c: any) => {
            // Truncate very large changes to prevent memory issues
            let changeText = c.text || '';
            let wasTruncated = false;
            if (changeText.length > MAX_CHANGE_TEXT_LENGTH) {
                changeText = changeText.substring(0, MAX_CHANGE_TEXT_LENGTH) + '...[TRUNCATED]';
                wasTruncated = true;
            }
            
            return {
            textLength: c.textLength,
            rangeLength: c.rangeLength,
            lineCountDelta: (c.text.match(/\n/g) || []).length,
            likelyAI: c.textLength > 100 && c.rangeLength === 0,
                changeText: changeText,
                wasTruncated: wasTruncated
            };
        })
    };

    // Add the entry to the buffer FIRST
    LOG_BUFFER.push(entry);

    // Update estimated memory usage
    const entrySize = JSON.stringify(entry).length * 2; // Rough estimate: 2 bytes per character
    bufferMemoryUsage += entrySize;

    // Check both buffer size and memory limits
    const limits = getBufferLimits();
    const maxMemoryBytes = limits.maxMemoryMB * 1024 * 1024;
    
    while (LOG_BUFFER.length > limits.maxBufferSize || bufferMemoryUsage > maxMemoryBytes) {
        const removedEntry = LOG_BUFFER.shift();
        if (removedEntry) {
            const removedSize = JSON.stringify(removedEntry).length * 2;
            bufferMemoryUsage -= removedSize;
        }
    }

    // Log memory usage periodically for monitoring
    if (LOG_BUFFER.length % 1000 === 0) {
        const memoryMB = (bufferMemoryUsage / 1024 / 1024).toFixed(2);
        console.log(`[FROLIC] Buffer: ${LOG_BUFFER.length} events, ~${memoryMB}MB memory`);
    }

    // Refresh tree view when activity changes
    if (activityProvider) {
        activityProvider.refresh();
    }

    // Send digest if buffer gets large (activity-based trigger)
    if (LOG_BUFFER.length >= 50 && LOG_BUFFER.length % 25 === 0) {
        console.log(`[FROLIC] Buffer reached ${LOG_BUFFER.length} events, considering digest send`);
        // Don't block logging - send in background
        if (extensionContext) {
            sendDigestImmediately(extensionContext).catch(err => {
                console.log('[FROLIC] Activity-based digest send failed, will retry later');
            });
        }
    }

    console.log(`[FROLIC] ${eventType}`, entry);
}

function writeLogsToFile() {
    const workspaceFolders = vscode.workspace.workspaceFolders;

    if (!workspaceFolders || workspaceFolders.length === 0) {
        console.warn("[FROLIC] No workspace folder found — cannot write logs.");
        return;
    }

    const workspacePath = workspaceFolders[0].uri.fsPath;
    const logFilePath = path.join(workspacePath, '.frolic-log.json');

    console.log(`[FROLIC] Attempting to write to: ${logFilePath}`);

    try {
        fs.writeFileSync(logFilePath, JSON.stringify(LOG_BUFFER, null, 2), 'utf8');
        console.log(`[FROLIC] Logs written to ${logFilePath}`);
    } catch (err) {
        console.error("[FROLIC] Failed to write logs:", err);
    }
}

function getApiBaseUrl(): string {
  const config = vscode.workspace.getConfiguration('frolic');
  const url = config.get<string>('apiBaseUrl') || 'https://getfrolic.io';
  
  // Validate URL format
  try {
    new URL(url);
    return url;
  } catch {
    console.warn('[FROLIC] Invalid API URL in settings, using default');
    return 'https://getfrolic.io';
  }
}

// Helper function to add timeout to fetch requests
async function fetchWithTimeout(url: string, options: any, timeoutMs: number = 30000): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  
  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    return response;
  } catch (error) {
    clearTimeout(timeoutId);
    throw error;
  }
}

// --- PKCE Utilities ---
function base64URLEncode(str: Buffer) {
  return str.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function generateCodeVerifier(): string {
  return base64URLEncode(crypto.randomBytes(32));
}

function generateCodeChallenge(verifier: string): string {
  return base64URLEncode(crypto.createHash('sha256').update(verifier).digest());
}

/**
 * Get a valid access token, refreshing it if necessary
 */
async function getValidAccessToken(context: vscode.ExtensionContext): Promise<string | null> {
  const accessToken = await context.secrets.get('frolic.accessToken');
  const refreshToken = await context.secrets.get('frolic.refreshToken');
  
  // If no access token, check if we have refresh token
  if (!accessToken) {
    if (refreshToken) {
      console.log('[FROLIC] No access token but refresh token exists, attempting refresh');
      return await refreshAccessToken(context, refreshToken);
    }
    return null;
  }
  
  // Check if access token is expired by trying to decode it
  if (isTokenExpired(accessToken)) {
    console.log('[FROLIC] Access token is expired, attempting refresh');
    if (refreshToken) {
      return await refreshAccessToken(context, refreshToken);
    } else {
      console.log('[FROLIC] No refresh token available, user needs to re-authenticate');
      await context.secrets.delete('frolic.accessToken');
      return null;
    }
  }
  
  return accessToken;
}

/**
 * Check if a JWT token is expired (without verifying signature)
 */
function isTokenExpired(token: string): boolean {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return true;
    
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    const now = Math.floor(Date.now() / 1000);
    
    // Check if token has exp claim and if it's expired
    return payload.exp && payload.exp < now;
  } catch (err) {
    console.log('[FROLIC] Error checking token expiration:', err);
    return true; // Assume expired if we can't parse
  }
}

/**
 * Refresh the access token using the refresh token
 */
async function refreshAccessToken(context: vscode.ExtensionContext, refreshToken: string): Promise<string | null> {
  const apiBaseUrl = getApiBaseUrl();
  const refreshUrl = `${apiBaseUrl}/api/auth/vscode/refresh`;
  
  try {
    console.log('[FROLIC] Attempting to refresh access token');
    const response = await fetchWithTimeout(refreshUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'VSCode-Frolic-Extension/1.0.0'
      },
      body: JSON.stringify({ refresh_token: refreshToken })
    }, 15000); // 15 second timeout for refresh
    
    if (!response.ok) {
      const errorText = await response.text();
      console.log(`[FROLIC] Token refresh failed: ${response.status} ${errorText}`);
      
      if (response.status === 401 || response.status === 403) {
        // Refresh token is also expired or invalid
        console.log('[FROLIC] Refresh token expired, clearing all tokens');
        await context.secrets.delete('frolic.accessToken');
        await context.secrets.delete('frolic.refreshToken');
        updateStatusBar('unauthenticated');
      }
      return null;
    }
    
    const data = await response.json();
    const newAccessToken = data.accessToken || data.access_token;
    const newRefreshToken = data.refresh_token; // Some systems rotate refresh tokens
    
    if (!newAccessToken) {
      console.log('[FROLIC] No access token in refresh response');
      return null;
    }
    
    // Store the new tokens
    await context.secrets.store('frolic.accessToken', newAccessToken);
    if (newRefreshToken) {
      await context.secrets.store('frolic.refreshToken', newRefreshToken);
    }
    
    console.log('[FROLIC] Access token refreshed successfully');
    updateStatusBar('authenticated');
    return newAccessToken;
    
  } catch (err: any) {
    console.log('[FROLIC] Token refresh error:', err.message);
    return null;
  }
}

/**
 * Send a session digest to your backend.
 * @param sessionId string (UUID)
 * @param digest object (summary)
 * @param context vscode.ExtensionContext for accessing secrets
 */
export async function sendDigestToBackend(
  sessionId: string,
  digest: any,
  context: vscode.ExtensionContext
) {
  const apiBaseUrl = getApiBaseUrl();
  const apiUrl = `${apiBaseUrl}/api/digests`;
  console.log(`[FROLIC] Sending digest to: ${apiUrl}`); // Debug log
  
  // Try to get a valid access token (will refresh if needed)
  const accessToken = await getValidAccessToken(context);
  
  if (!accessToken) {
    console.log('[FROLIC] No valid access token available, skipping digest upload');
    throw new Error('NO_AUTH_TOKEN');
  }

  console.log(`[FROLIC] Using access token: ${accessToken?.substring(0, 20)}...`); // Debug log

  try {
    const res = await fetchWithTimeout(apiUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
        'User-Agent': 'VSCode-Frolic-Extension/1.0.0'
      },
      body: JSON.stringify({ sessionId, digest })
    }, 30000); // 30 second timeout

    if (!res.ok) {
      const errorText = await res.text();
      
      // Handle specific HTTP status codes
      if (res.status === 401 || (res.status === 403 && errorText.includes('token is expired'))) {
        // Token expired - clear it and update status
        await context.secrets.delete('frolic.accessToken');
        console.log('[FROLIC] Token expired, cleared stored token');
        updateStatusBar('unauthenticated');
        throw new Error('AUTH_TOKEN_EXPIRED');
      } else if (res.status === 403) {
        console.error('[FROLIC] Access forbidden - check API permissions');
        throw new Error('ACCESS_FORBIDDEN');
      } else if (res.status >= 500) {
        console.error(`[FROLIC] Server error: ${res.status} ${errorText}`);
        throw new Error('SERVER_ERROR');
      } else {
        console.error(`[FROLIC] Client error: ${res.status} ${errorText}`);
        throw new Error('CLIENT_ERROR');
      }
    }

    // Success - only log, don't show notification for background operations
    console.log('[FROLIC] Digest uploaded successfully');
    return await res.json();
  } catch (err: any) {
    // Handle different types of errors appropriately
    if (err.name === 'AbortError' || err.code === 'ENOTFOUND' || err.code === 'ECONNREFUSED') {
      console.log('[FROLIC] Network unavailable, will retry later');
      throw new Error('NETWORK_ERROR');
    } else if (err.message === 'NO_AUTH_TOKEN' || err.message === 'AUTH_TOKEN_EXPIRED') {
      // Re-throw auth errors as-is
      throw err;
    } else {
      console.error('[FROLIC] Unexpected error sending digest:', err);
      throw new Error('UNKNOWN_ERROR');
    }
  }
}

// --- Digest analyzer logic (from scripts/analyzeLogs.ts) ---

function analyzeLogs(logs: any[]): any {
  const files = new Set<string>();
  const langCounts: Record<string, number> = {};
  let totalLinesAdded = 0;
  let aiInsertions = 0;
  const fileActivity: Record<string, { edits: number, linesChanged: number, timeSpent: number }> = {};
  const topicTags = new Set<string>();
  const importPatterns = new Set<string>();
  const codePatterns = new Set<string>();
  const learningSignals: string[] = [];
  const projectStructure: Record<string, string[]> = {};

  // Enhanced keyword detection for better topic inference
  const tagKeywords: Record<string, string[]> = {
    react: ["useState", "useEffect", "React.FC", "JSX", "Component", "props", "setState"],
    supabase: ["createClient", "from", "@supabase", "supabase", "database"],
    regex: ["/[a-z]+/", ".match(", ".test(", "RegExp", "replace("],
    auth: ["Auth0", "Clerk", "login", "token", "session", "authenticate", "jwt"],
    fetch: ["fetch(", "axios", "GET", "POST", "api", "endpoint", "request"],
    typescript: ["interface", "type", "enum", ": string", ": number", "generic", "extends"],
    testing: ["test(", "expect(", "describe(", "jest", "vitest", "cypress"],
    styling: ["className", "styled", "css", "tailwind", "@apply", "hover:"],
    database: ["SELECT", "INSERT", "UPDATE", "DELETE", "schema", "migration"],
    deployment: ["docker", "kubernetes", "deploy", "build", "ci/cd", "github actions"],
    performance: ["useMemo", "useCallback", "lazy(", "Suspense", "optimization"],
    state: ["redux", "zustand", "context", "provider", "store", "dispatch"],
    ai: ["openai", "anthropic", "langchain", "embeddings", "prompt", "llm"],
    security: ["bcrypt", "jwt", "cors", "helmet", "sanitize", "validation"],
    mobile: ["react-native", "expo", "ios", "android", "mobile"],
    devtools: ["webpack", "vite", "rollup", "babel", "eslint", "prettier"]
  };

  // Pattern recognition for code complexity and learning
  const codePatternDetection = {
    functions: /function\s+\w+|const\s+\w+\s*=\s*\(/g,
    classes: /class\s+\w+|interface\s+\w+/g,
    imports: /import\s+.*?from\s+['"`]([^'"`]+)['"`]/g,
    exports: /export\s+(default\s+)?/g,
    async: /async\s+|await\s+/g,
    errors: /try\s*{|catch\s*\(|throw\s+/g,
    loops: /for\s*\(|while\s*\(|\.map\(|\.forEach\(/g,
    conditionals: /if\s*\(|switch\s*\(|\?\s*:/g,
    hooks: /use[A-Z]\w*/g,
    components: /<[A-Z]\w*|function\s+[A-Z]\w*/g
  };

  // Session timing analysis
  const sessionStart = logs.length > 0 ? new Date(logs[0].timestamp) : new Date();
  const sessionEnd = logs.length > 0 ? new Date(logs[logs.length - 1].timestamp) : new Date();
  const sessionDuration = (sessionEnd.getTime() - sessionStart.getTime()) / 1000 / 60; // minutes

  // Process each log entry
  for (const entry of logs) {
    if (entry.eventType !== 'file_edit') continue;

    const filePath = entry.relativePath;
    files.add(filePath);
    langCounts[entry.language] = (langCounts[entry.language] || 0) + 1;

    // Enhanced file activity tracking
    if (!fileActivity[filePath]) {
      fileActivity[filePath] = { edits: 0, linesChanged: 0, timeSpent: 0 };
    }
    fileActivity[filePath].edits++;

    // Project structure analysis
    const pathParts = filePath.split('/');
    const directory = pathParts.slice(0, -1).join('/') || 'root';
    if (!projectStructure[directory]) {
      projectStructure[directory] = [];
    }
    if (!projectStructure[directory].includes(pathParts[pathParts.length - 1])) {
      projectStructure[directory].push(pathParts[pathParts.length - 1]);
    }

    // Analyze each code change
    for (const change of entry.changes || []) {
      const changeText = change.changeText || '';
      const linesChanged = Math.abs(change.lineCountDelta || 0);
      
      totalLinesAdded += change.lineCountDelta || 0;
      fileActivity[filePath].linesChanged += linesChanged;
      
      if (change.likelyAI) aiInsertions++;

      // Enhanced topic detection
      for (const [topic, keywords] of Object.entries(tagKeywords)) {
        if (keywords.some(kw => changeText.toLowerCase().includes(kw.toLowerCase()))) {
          topicTags.add(topic);
        }
      }

      // Import pattern detection with proper typing
      const importMatches = changeText.match(codePatternDetection.imports);
      if (importMatches) {
        importMatches.forEach((match: string) => {
          const importPath = match.match(/from\s+['"`]([^'"`]+)['"`]/)?.[1];
          if (importPath) {
            importPatterns.add(importPath);
          }
        });
      }

      // Code pattern analysis
      for (const [pattern, regex] of Object.entries(codePatternDetection)) {
        const matches = changeText.match(regex);
        if (matches && matches.length > 0) {
          codePatterns.add(`${pattern}:${matches.length}`);
        }
      }

      // Learning signal detection (new concepts, repeated patterns, etc.)
      if (changeText.length > 50 && change.textLength > change.rangeLength) {
        // Significant addition - might be learning something new
        const newConcepts = [];
        if (changeText.includes('interface ') && !learningSignals.some(s => s.includes('typescript-interfaces'))) {
          newConcepts.push('typescript-interfaces');
        }
        if (changeText.includes('useEffect') && !learningSignals.some(s => s.includes('react-effects'))) {
          newConcepts.push('react-effects');
        }
        if (changeText.includes('async ') && !learningSignals.some(s => s.includes('async-programming'))) {
          newConcepts.push('async-programming');
        }
        if (changeText.includes('useState') && !learningSignals.some(s => s.includes('react-state'))) {
          newConcepts.push('react-state');
        }
        if (changeText.includes('supabase') && !learningSignals.some(s => s.includes('database-integration'))) {
          newConcepts.push('database-integration');
        }
        if (changeText.includes('test(') && !learningSignals.some(s => s.includes('unit-testing'))) {
          newConcepts.push('unit-testing');
        }
        learningSignals.push(...newConcepts);
      }
    }
  }

  // Calculate derived insights
  const topFiles = Object.entries(fileActivity)
    .sort((a, b) => b[1].edits - a[1].edits)
    .slice(0, 5)
    .map(([file, stats]) => ({ file, ...stats }));

  const mostActiveDirectory = Object.entries(projectStructure)
    .sort((a, b) => b[1].length - a[1].length)[0];

  const codingVelocity = sessionDuration > 0 ? Math.round(totalLinesAdded / sessionDuration) : 0;
  
  // Project type inference
  const projectType = inferProjectType(Array.from(importPatterns), Array.from(topicTags));
  
  // Complexity analysis
  const complexityScore = calculateComplexityScore(Array.from(codePatterns), totalLinesAdded);

  return {
    // Basic metrics (backwards compatible)
    filesEdited: files.size,
    totalLinesAdded,
    aiInsertions,
    topFiles: topFiles.map(f => f.file), // Keep backwards compatibility
    languagesUsed: langCounts,
    inferredTopics: Array.from(topicTags),
    
    // Enhanced metrics for LLM processing
    sessionMetrics: {
      duration: Math.round(sessionDuration),
      startTime: sessionStart.toISOString(),
      endTime: sessionEnd.toISOString(),
      codingVelocity, // lines per minute
      filesPerMinute: sessionDuration > 0 ? Math.round(files.size / sessionDuration * 10) / 10 : 0,
      averageEditSize: totalLinesAdded / Math.max(1, topFiles.reduce((sum, f) => sum + f.edits, 0)),
      productivityLevel: getProductivityLevel(codingVelocity, files.size, sessionDuration)
    },
    
    detailedFileActivity: topFiles,
    
    codeInsights: {
      importPatterns: Array.from(importPatterns).slice(0, 10),
      codePatterns: Array.from(codePatterns).slice(0, 15),
      projectType,
      complexityScore,
      architecturalPatterns: detectArchitecturalPatterns(Array.from(topicTags), projectStructure)
    },
    
    learningAnalysis: {
      newConceptsEncountered: learningSignals,
      practicePatterns: detectPracticePatterns(fileActivity, codePatterns),
      problemSolvingSignals: detectProblemSolving(logs),
      knowledgeGaps: identifyKnowledgeGaps(Array.from(topicTags), Array.from(codePatterns))
    },
    
    projectStructure: {
      directories: Object.keys(projectStructure).length,
      mostActiveDirectory: mostActiveDirectory?.[0] || 'unknown',
      fileTypes: getFileTypeDistribution(Array.from(files)),
      structureComplexity: calculateStructureComplexity(projectStructure)
    },
    
    workflowInsights: {
      editingPatterns: analyzeEditingPatterns(logs),
      focusAreas: identifyFocusAreas(fileActivity, sessionDuration),
      developmentStage: inferDevelopmentStage(topicTags, codePatterns, totalLinesAdded),
      codingStyle: analyzeCodingStyle(Array.from(codePatterns), Array.from(topicTags)),
      timeDistribution: analyzeTimeDistribution(fileActivity, sessionDuration)
    },

    // Content generation hints for LLM
    contentHints: {
      newsletterTopics: generateNewsletterTopics(Array.from(topicTags), learningSignals, projectType),
      teachingOpportunities: identifyTeachingOpportunities(learningSignals, Array.from(codePatterns)),
      challengingAreas: identifyChallengingAreas(logs, Array.from(codePatterns)),
      celebrationMoments: identifyCelebrationMoments(totalLinesAdded, aiInsertions, learningSignals),
      nextSteps: suggestNextSteps(Array.from(topicTags), learningSignals, complexityScore)
    }
  };
}

// Helper functions for enhanced analysis
function inferProjectType(imports: string[], topics: string[]): string {
  if (imports.some(imp => imp.includes('next')) || topics.includes('react')) return 'Next.js/React App';
  if (imports.some(imp => imp.includes('express')) || topics.includes('node')) return 'Node.js Backend';
  if (imports.some(imp => imp.includes('vue'))) return 'Vue.js App';
  if (topics.includes('database') && topics.includes('api')) return 'Full-Stack Application';
  if (topics.includes('testing')) return 'Testing/QA Project';
  return 'Web Application';
}

function calculateComplexityScore(patterns: string[], linesAdded: number): number {
  let score = 0;
  patterns.forEach(pattern => {
    const [type, count] = pattern.split(':');
    const numCount = parseInt(count) || 0;
    switch (type) {
      case 'functions': score += numCount * 2; break;
      case 'classes': score += numCount * 3; break;
      case 'async': score += numCount * 2; break;
      case 'errors': score += numCount * 1; break;
      default: score += numCount * 1;
    }
  });
  return Math.min(100, Math.round(score + (linesAdded / 100)));
}

function detectArchitecturalPatterns(topics: string[], structure: Record<string, string[]>): string[] {
  const patterns = [];
  if (topics.includes('react') && Object.keys(structure).some(dir => dir.includes('components'))) {
    patterns.push('Component-Based Architecture');
  }
  if (Object.keys(structure).some(dir => dir.includes('api')) || topics.includes('fetch')) {
    patterns.push('API-Driven Development');
  }
  if (topics.includes('state') || topics.includes('redux')) {
    patterns.push('State Management Pattern');
  }
  return patterns;
}

function detectPracticePatterns(fileActivity: Record<string, any>, patterns: Set<string>): string[] {
  const practice = [];
  const totalEdits = Object.values(fileActivity).reduce((sum: number, f: any) => sum + f.edits, 0);
  
  if (totalEdits > 20) practice.push('intensive-coding-session');
  if (patterns.has('functions:5') || patterns.has('functions:10')) practice.push('function-composition-practice');
  if (Array.from(patterns).some(p => p.includes('errors'))) practice.push('error-handling-practice');
  
  return practice;
}

function detectProblemSolving(logs: any[]): string[] {
  const signals = [];
  let quickEdits = 0;
  
  for (let i = 1; i < logs.length; i++) {
    const timeDiff = new Date(logs[i].timestamp).getTime() - new Date(logs[i-1].timestamp).getTime();
    if (timeDiff < 30000 && logs[i].eventType === 'file_edit') { // Less than 30 seconds apart
      quickEdits++;
    }
  }
  
  if (quickEdits > 10) signals.push('rapid-iteration-debugging');
  if (logs.some(log => log.changes?.some((c: any) => c.changeText?.includes('console.log')))) {
    signals.push('debug-logging-approach');
  }
  
  return signals;
}

function identifyKnowledgeGaps(topics: string[], patterns: string[]): string[] {
  const gaps = [];
  
  if (topics.includes('typescript') && !patterns.some(p => p.includes('interfaces'))) {
    gaps.push('typescript-interface-usage');
  }
  if (topics.includes('react') && !topics.includes('testing')) {
    gaps.push('react-testing-patterns');
  }
  if (patterns.some(p => p.includes('async')) && !topics.includes('errors')) {
    gaps.push('async-error-handling');
  }
  
  return gaps;
}

function getFileTypeDistribution(files: string[]): Record<string, number> {
  const distribution: Record<string, number> = {};
  files.forEach(file => {
    const ext = file.split('.').pop() || 'unknown';
    distribution[ext] = (distribution[ext] || 0) + 1;
  });
  return distribution;
}

function calculateStructureComplexity(structure: Record<string, string[]>): number {
  const totalDirs = Object.keys(structure).length;
  const totalFiles = Object.values(structure).reduce((sum, files) => sum + files.length, 0);
  const avgFilesPerDir = totalFiles / Math.max(1, totalDirs);
  
  if (totalDirs > 10 || avgFilesPerDir > 8) return 3; // High
  if (totalDirs > 5 || avgFilesPerDir > 4) return 2; // Medium
  return 1; // Low
}

function analyzeEditingPatterns(logs: any[]): string[] {
  const patterns = [];
  const fileEdits: Record<string, number> = {};
  
  logs.forEach(log => {
    if (log.eventType === 'file_edit') {
      fileEdits[log.relativePath] = (fileEdits[log.relativePath] || 0) + 1;
    }
  });
  
  const maxEdits = Math.max(...Object.values(fileEdits));
  if (maxEdits > 20) patterns.push('deep-focus-single-file');
  if (Object.keys(fileEdits).length > 10) patterns.push('multi-file-coordination');
  
  return patterns;
}

function identifyFocusAreas(fileActivity: Record<string, any>, sessionDuration: number): string[] {
  const areas = [];
  const topFile = Object.entries(fileActivity)
    .sort((a, b) => b[1].edits - a[1].edits)[0];
  
  if (topFile && topFile[1].edits > 15) {
    if (topFile[0].includes('component') || topFile[0].includes('.tsx')) areas.push('frontend-components');
    if (topFile[0].includes('api') || topFile[0].includes('server')) areas.push('backend-api');
    if (topFile[0].includes('test')) areas.push('testing');
    if (topFile[0].includes('style') || topFile[0].includes('.css')) areas.push('styling');
  }
  
  return areas;
}

function inferDevelopmentStage(topics: Set<string>, patterns: Set<string>, linesAdded: number): string {
  if (linesAdded > 500 && Array.from(patterns).some(p => p.includes('functions'))) return 'active-development';
  if (topics.has('testing') || Array.from(patterns).some(p => p.includes('errors'))) return 'testing-debugging';
  if (linesAdded < 100 && topics.has('styling')) return 'refinement-polishing';
  if (topics.has('deployment') || topics.has('ci/cd')) return 'deployment-ops';
  return 'feature-building';
}

function getProductivityLevel(velocity: number, filesCount: number, duration: number): string {
  if (velocity > 10 && filesCount > 5) return 'high';
  if (velocity > 5 && filesCount > 2) return 'medium';
  if (duration > 30) return 'focused';
  return 'learning';
}

function analyzeCodingStyle(patterns: string[], topics: string[]): string {
  if (patterns.some(p => p.includes('functions')) && topics.includes('typescript')) return 'functional-typed';
  if (patterns.some(p => p.includes('classes'))) return 'object-oriented';
  if (patterns.some(p => p.includes('hooks')) && topics.includes('react')) return 'modern-react';
  if (topics.includes('testing')) return 'test-driven';
  return 'exploratory';
}

function analyzeTimeDistribution(fileActivity: Record<string, any>, totalDuration: number): Record<string, number> {
  const distribution: Record<string, number> = {};
  const totalEdits = Object.values(fileActivity).reduce((sum: any, f: any) => sum + f.edits, 0);
  
  Object.entries(fileActivity).forEach(([file, stats]: [string, any]) => {
    const timePercent = Math.round((stats.edits / totalEdits) * 100);
    const fileName = file.split('/').pop() || file;
    distribution[fileName] = timePercent;
  });
  
  return distribution;
}

function generateNewsletterTopics(topics: string[], learningSignals: string[], projectType: string): string[] {
  const newsletterTopics = [];
  
  if (topics.includes('react') && learningSignals.includes('react-effects')) {
    newsletterTopics.push('Mastering React useEffect: Side Effects and Cleanup');
  }
  if (topics.includes('typescript') && learningSignals.includes('typescript-interfaces')) {
    newsletterTopics.push('TypeScript Interfaces: Building Type-Safe Applications');
  }
  if (topics.includes('supabase') && projectType.includes('Full-Stack')) {
    newsletterTopics.push('Building Real-time Apps with Supabase');
  }
  if (topics.includes('performance')) {
    newsletterTopics.push('React Performance Optimization Strategies');
  }
  
  return newsletterTopics;
}

function identifyTeachingOpportunities(learningSignals: string[], patterns: string[]): string[] {
  const opportunities = [];
  
  if (learningSignals.includes('async-programming')) {
    opportunities.push('Deep dive into JavaScript Promises and async/await');
  }
  if (learningSignals.includes('react-state')) {
    opportunities.push('Understanding React state management patterns');
  }
  if (patterns.some(p => p.includes('errors'))) {
    opportunities.push('Error handling best practices in modern JavaScript');
  }
  
  return opportunities;
}

function identifyChallengingAreas(logs: any[], patterns: string[]): string[] {
  const challenges = [];
  
  // Look for rapid edits in same file (suggests struggling)
  const rapidEdits = logs.filter((log, i) => {
    if (i === 0) return false;
    const timeDiff = new Date(log.timestamp).getTime() - new Date(logs[i-1].timestamp).getTime();
    return timeDiff < 60000 && log.relativePath === logs[i-1].relativePath;
  });
  
  if (rapidEdits.length > 15) challenges.push('debugging-complex-issues');
  if (patterns.some(p => p.includes('async') && p.includes('errors'))) challenges.push('asynchronous-error-handling');
  
  return challenges;
}

function identifyCelebrationMoments(linesAdded: number, aiInsertions: number, learningSignals: string[]): string[] {
  const celebrations = [];
  
  if (linesAdded > 300) celebrations.push('productive-coding-session');
  if (learningSignals.length > 2) celebrations.push('multiple-new-concepts-learned');
  if (aiInsertions === 0 && linesAdded > 100) celebrations.push('independent-problem-solving');
  
  return celebrations;
}

function suggestNextSteps(topics: string[], learningSignals: string[], complexity: number): string[] {
  const nextSteps = [];
  
  if (topics.includes('react') && !topics.includes('testing')) {
    nextSteps.push('Add testing to your React components');
  }
  if (complexity < 30) {
    nextSteps.push('Try implementing more complex features');
  }
  if (topics.includes('supabase') && !topics.includes('security')) {
    nextSteps.push('Learn about database security and RLS policies');
  }
  
  return nextSteps;
}

export async function signInCommand(context: vscode.ExtensionContext) {
  const state = uuidv4();
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  const apiBaseUrl = getApiBaseUrl();
  
  // Get token expiration preference
  const config = vscode.workspace.getConfiguration('frolic');
  const tokenExpiration = config.get<string>('tokenExpiration', 'long');
  
  const authUrl = `${apiBaseUrl}/api/auth/vscode/start?state=${state}&code_challenge=${codeChallenge}&token_type=${tokenExpiration}`;
  vscode.env.openExternal(vscode.Uri.parse(authUrl));

  // Store the codeVerifier in SecretStorage for later token exchange
  await context.secrets.store('frolic.codeVerifier', codeVerifier);
  await context.secrets.store('frolic.state', state);

  const code = await vscode.window.showInputBox({
    prompt: 'Paste the code from the Frolic login page here',
    ignoreFocusOut: true
  });
  if (!code) {
    vscode.window.showWarningMessage('Frolic sign-in cancelled - no code entered');
    return;
  }

  try {
    // Retrieve the codeVerifier and state
    const storedCodeVerifier = await context.secrets.get('frolic.codeVerifier');
    const storedState = await context.secrets.get('frolic.state');
    
    // Get token expiration preference
    const config = vscode.workspace.getConfiguration('frolic');
    const tokenExpiration = config.get<string>('tokenExpiration', 'long');
    
    const res = await fetchWithTimeout(`${apiBaseUrl}/api/auth/vscode/token`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'User-Agent': 'VSCode-Frolic-Extension/1.0.0'
      },
      body: JSON.stringify({ 
        code, 
        state: storedState, 
        code_verifier: storedCodeVerifier,
        token_type: tokenExpiration
      })
    }, 15000); // 15 second timeout for auth
    if (!res.ok) {
      const errorText = await res.text();
      vscode.window.showErrorMessage(`🔐 Frolic sign-in failed: Invalid code or expired session`, 'Try Again');
      console.error(`[FROLIC] Sign-in failed: ${res.status} ${errorText}`);
      return;
    }
    const data = await res.json();
    const accessToken = data.accessToken || data.access_token;
    const refreshToken = data.refresh_token;
    
    // Store both tokens
    await context.secrets.store('frolic.accessToken', accessToken);
    if (refreshToken) {
      await context.secrets.store('frolic.refreshToken', refreshToken);
      console.log('[FROLIC] Stored both access and refresh tokens');
    } else {
      console.log('[FROLIC] Only access token received (no refresh token)');
    }
    
    updateStatusBar('authenticated');
    vscode.window.showInformationMessage('🎉 Welcome to Frolic! Your coding activity will now be tracked for personalized recaps.');
  } catch (err) {
    vscode.window.showErrorMessage('🔐 Frolic sign-in failed: Network error', 'Retry');
    console.error('[FROLIC] Sign-in error:', err);
    }
}

export function activate(context: vscode.ExtensionContext) {
    console.log('✅ Frolic Logger is now active!');

    // Store context globally for activity-based digest sending
    extensionContext = context;

    // Create status bar item
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.command = 'frolic.flushLogs';
    context.subscriptions.push(statusBarItem);
    updateStatusBar('initializing');

    // Create and register tree view
    activityProvider = new FrolicActivityProvider(context);
    const treeView = vscode.window.createTreeView('frolic-activity', {
        treeDataProvider: activityProvider,
        showCollapseAll: true
    });
    context.subscriptions.push(treeView);

    // Set context to show the tree view
    vscode.commands.executeCommand('setContext', 'frolic.showActivityView', true);

    // Function to refresh tree view when activity changes
    const refreshTreeView = () => {
        if (activityProvider) {
            activityProvider.refresh();
        }
    };

    // Toggle logging from settings
    const config = vscode.workspace.getConfiguration('frolic');
    isLoggingEnabled = config.get<boolean>('enableLogging', true);

    // Track config changes
    context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration(e => {
            if (e.affectsConfiguration('frolic.enableLogging')) {
                isLoggingEnabled = vscode.workspace.getConfiguration('frolic').get<boolean>('enableLogging', true);
            }
            if (e.affectsConfiguration('frolic.digestFrequencyHours')) {
                // Restart the digest timer with new frequency
                stopPeriodicDigestSending();
                startPeriodicDigestSending(context);
            }
            if (e.affectsConfiguration('frolic.maxBufferSize') || e.affectsConfiguration('frolic.maxMemoryMB')) {
                // Log the buffer limit changes
                const limits = getBufferLimits();
                console.log(`[FROLIC] Buffer limits updated: ${limits.maxBufferSize} events, ${limits.maxMemoryMB}MB`);
            }
        })
    );

    // Track file edits
    context.subscriptions.push(
        vscode.workspace.onDidChangeTextDocument((event) => {
            const editor = vscode.window.activeTextEditor;
            const doc = event.document;

            logEvent('file_edit', {
                file: doc.fileName,
                language: doc.languageId,
                lineCount: doc.lineCount,
                isUntitled: doc.isUntitled,
                isDirty: doc.isDirty,
                cursorPosition: editor?.selection.active,
                selectionLength: editor && editor.selection && editor.selection.end && editor.selection.start
                  ? editor.selection.end.character - editor.selection.start.character
                  : 0,
                changes: event.contentChanges.map(change => ({
                    text: change.text,
                    textLength: change.text.length,
                    rangeLength: change.rangeLength
                }))
            });
        })
    );

    // Track file opens
    context.subscriptions.push(
        vscode.workspace.onDidOpenTextDocument((doc) => {
            logEvent('file_open', {
                file: doc.fileName,
                language: doc.languageId,
                lineCount: doc.lineCount,
                isUntitled: doc.isUntitled,
                isDirty: doc.isDirty
            });
        })
    );

    // Manual flush command - writes to file and optionally sends digest
    const flushCommand = vscode.commands.registerCommand('frolic.flushLogs', async () => {
        writeLogsToFile();
        
        // Also offer to send digest immediately
        if (LOG_BUFFER.length > 0) {
            const choice = await vscode.window.showInformationMessage(
                `Frolic logs written to .frolic-log.json. Send ${LOG_BUFFER.length} events to backend now?`,
                'Send Now',
                'File Only'
            );
            
            if (choice === 'Send Now') {
                try {
                    await sendDigestImmediately(context);
                    vscode.window.showInformationMessage('✅ Frolic: Logs saved and digest sent successfully');
                } catch (err) {
                    vscode.window.showWarningMessage('⚠️ Frolic: Logs saved to file, but network upload failed', 'View Logs');
                }
            } else {
                vscode.window.showInformationMessage('✅ Frolic: Logs saved to .frolic-log.json');
            }
        } else {
            vscode.window.showInformationMessage('✅ Frolic: Logs saved (no new events to send)');
        }
    });
    context.subscriptions.push(flushCommand);

    // Register the sign-in command
    const signInCmd = vscode.commands.registerCommand('frolic.signIn', () => signInCommand(context));
    context.subscriptions.push(signInCmd);

    // Register dedicated digest send command for testing
    const sendDigestCmd = vscode.commands.registerCommand('frolic.sendDigest', async () => {
        if (LOG_BUFFER.length === 0) {
            vscode.window.showInformationMessage('📊 Frolic: No activity to send (buffer is empty). Try editing some files first.');
            return;
        }

        try {
            const eventCount = await sendDigestImmediately(context);
            vscode.window.showInformationMessage(`✅ Frolic: Digest sent successfully! (${eventCount} events processed)`);
        } catch (err: any) {
            if (err.message === 'NO_AUTH_TOKEN') {
                vscode.window.showWarningMessage('🔐 Frolic: Please sign in first to send digests', 'Sign In')
                    .then(selection => {
                        if (selection === 'Sign In') {
                            vscode.commands.executeCommand('frolic.signIn');
                        }
                    });
            } else {
                vscode.window.showErrorMessage(`❌ Frolic: Failed to send digest - ${err.message}`, 'Retry');
            }
        }
    });
    context.subscriptions.push(sendDigestCmd);

    // Start daily digest sending
    startPeriodicDigestSending(context);

    // On activation, check for token
    context.secrets.get('frolic.accessToken').then(accessToken => {
        if (!accessToken) {
            updateStatusBar('unauthenticated');
            // Show welcome message only once per session, not every activation
            const hasShownWelcome = context.globalState.get('frolic.hasShownWelcome', false);
            if (!hasShownWelcome) {
                vscode.window.showInformationMessage(
                    '🚀 Frolic: Get personalized coding recaps and insights',
                    'Sign In',
                    'Not Now'
                ).then(selection => {
                    if (selection === 'Sign In') {
                        vscode.commands.executeCommand('frolic.signIn');
                    }
                    context.globalState.update('frolic.hasShownWelcome', true);
                });
            }
        } else {
            updateStatusBar('authenticated');
        }
    });
}

export function deactivate() {
    console.log('🛑 Frolic Logger is deactivating...');
    
    // Stop the daily digest timer first
    stopPeriodicDigestSending();
    
    // Write logs to file as backup - this is synchronous and reliable
    writeLogsToFile();
    
    // For the final digest, we'll trigger an immediate send if there's unsent data
    // but we can't wait for it to complete due to VS Code's synchronous deactivate design
    if (LOG_BUFFER.length > 0) {
        console.log(`[FROLIC] Extension deactivating with ${LOG_BUFFER.length} unsent events.`);
        console.log('[FROLIC] Logs have been written to .frolic-log.json as backup.');
        
        // Attempt to send final digest in background (fire-and-forget)
        // This is the best we can do with VS Code's synchronous deactivate
        try {
            const logs = [...LOG_BUFFER]; // Create copy
            const digest = analyzeLogs(logs);
            console.log('[FROLIC] Final digest prepared but cannot be sent synchronously.');
            console.log('[FROLIC] Consider enabling more frequent digest sending to avoid data loss.');
        } catch (err) {
            console.error('[FROLIC] Failed to prepare final digest:', err);
        }
    }
    
    // Clear the buffer to free memory
    LOG_BUFFER.length = 0;
    bufferMemoryUsage = 0;
    
    console.log('🛑 Frolic Logger deactivated.');
}

// Helper for SecretStorage access - DEPRECATED
// Use context.secrets.get() directly instead of this circular pattern
export async function getSecret(key: string): Promise<string | undefined> {
  console.warn('[FROLIC] getSecret() is deprecated. Use context.secrets.get() directly.');
  const ext = vscode.extensions.getExtension('frolic.frolic-extension');
  if (!ext?.isActive) await ext?.activate();
  return await ext?.exports?.context?.secrets.get(key);
}

function startPeriodicDigestSending(context: vscode.ExtensionContext) {
    // Prevent multiple timers from being created
    if (digestTimer) {
        console.log('[FROLIC] Digest timer already running, stopping existing timer first');
        stopPeriodicDigestSending();
    }
    
    const config = vscode.workspace.getConfiguration('frolic');
    const frequencyHours = config.get<number>('digestFrequencyHours', 24);
    const intervalMs = frequencyHours * 60 * 60 * 1000; // Convert hours to milliseconds
    
    // Send initial digest if there's already data in buffer (from previous session)
    if (LOG_BUFFER.length > 0) {
        console.log(`[FROLIC] Found ${LOG_BUFFER.length} events from previous session, sending initial digest`);
        // Don't block startup - send in background
        sendDigestImmediately(context).catch(err => {
            console.log('[FROLIC] Initial digest send failed, will retry on next interval');
        });
    }
    
    digestTimer = setInterval(async () => {
        // Add some jitter to prevent thundering herd if many users have same interval
        const jitter = Math.random() * 60000; // 0-1 minute random delay
        setTimeout(async () => {
            await sendDigestImmediately(context);
        }, jitter);
    }, intervalMs);

    console.log(`[FROLIC] Periodic digest timer started (every ${frequencyHours} hours)`);
}

async function sendDigestImmediately(context: vscode.ExtensionContext, maxRetries: number = 3): Promise<number> {
    if (LOG_BUFFER.length > 0) {
        const eventCount = LOG_BUFFER.length; // Capture count before clearing
        console.log(`[FROLIC] Sending digest with ${eventCount} events`);
        updateStatusBar('sending');
        
        const digest = analyzeLogs(LOG_BUFFER);
        let lastError: Error | null = null;
        
        // Retry logic with exponential backoff
        for (let attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                await sendDigestToBackend(sessionId, digest, context);
                
                // Clear buffer and start new session after successful send
                LOG_BUFFER.length = 0;
                bufferMemoryUsage = 0; // Reset memory tracking
                sessionId = uuidv4();
                console.log(`[FROLIC] Digest sent successfully. New session: ${sessionId}`);
                updateStatusBar('authenticated');
                return eventCount; // Return the number of events processed
            } catch (err: any) {
                lastError = err;
                console.log(`[FROLIC] Digest send attempt ${attempt + 1}/${maxRetries + 1} failed: ${err.message}`);
                
                // Handle different error types
                if (err.message === 'NO_AUTH_TOKEN' || err.message === 'AUTH_TOKEN_EXPIRED') {
                    // Auth errors - don't retry, update status
                    updateStatusBar('unauthenticated');
                    return 0; // Exit without clearing buffer
                } else if (err.message === 'ACCESS_FORBIDDEN' || err.message === 'CLIENT_ERROR') {
                    // Client errors - don't retry
                    updateStatusBar('error');
                    return 0; // Exit without clearing buffer
                }
                
                // For network/server errors, retry with exponential backoff
                if (attempt < maxRetries) {
                    const delay = Math.min(1000 * Math.pow(2, attempt), 10000); // Cap at 10 seconds
                    console.log(`[FROLIC] Retrying in ${delay}ms...`);
                    await new Promise(resolve => setTimeout(resolve, delay));
                }
            }
        }
        
        // All retries failed
        console.error(`[FROLIC] Failed to send digest after ${maxRetries + 1} attempts. Last error: ${lastError?.message}`);
        updateStatusBar('error');
        // Don't clear buffer - will retry next interval
        return 0;
    } else {
        console.log('[FROLIC] No activity to send in digest');
        updateStatusBar('authenticated');
        return 0;
    }
}

function stopPeriodicDigestSending() {
    if (digestTimer) {
        clearInterval(digestTimer);
        digestTimer = null;
        console.log('[FROLIC] Daily digest timer stopped');
    }
}

function updateStatusBar(status: 'initializing' | 'authenticated' | 'unauthenticated' | 'sending' | 'error') {
    if (!statusBarItem) return;
    
    switch (status) {
        case 'initializing':
            statusBarItem.text = '$(sync~spin) Frolic';
            statusBarItem.tooltip = 'Frolic is initializing...';
            statusBarItem.backgroundColor = undefined;
            break;
        case 'authenticated':
            statusBarItem.text = `$(check) Frolic (${LOG_BUFFER.length})`;
            statusBarItem.tooltip = `Frolic: ${LOG_BUFFER.length} events logged. Click to flush.`;
            statusBarItem.backgroundColor = undefined;
            break;
        case 'unauthenticated':
            statusBarItem.text = '$(warning) Frolic';
            statusBarItem.tooltip = 'Frolic: Sign in to enable cloud sync';
            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
            break;
        case 'sending':
            statusBarItem.text = '$(cloud-upload) Frolic';
            statusBarItem.tooltip = 'Frolic: Sending digest...';
            statusBarItem.backgroundColor = undefined;
            break;
        case 'error':
            statusBarItem.text = '$(error) Frolic';
            statusBarItem.tooltip = 'Frolic: Connection error. Click to retry.';
            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
            break;
    }
    statusBarItem.show();
}

// Tree view data provider for Frolic activity
class FrolicActivityProvider implements vscode.TreeDataProvider<FrolicTreeItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<FrolicTreeItem | undefined | null | void> = new vscode.EventEmitter<FrolicTreeItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<FrolicTreeItem | undefined | null | void> = this._onDidChangeTreeData.event;
    
    constructor(private context: vscode.ExtensionContext) {}

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element: FrolicTreeItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: FrolicTreeItem): Thenable<FrolicTreeItem[]> {
        if (!element) {
            // Root level items
            const items: FrolicTreeItem[] = [];
            
            // Session info with custom Frolic logo
            const logoPath = vscode.Uri.file(path.join(this.context.extensionPath, 'images', 'frolic_logo.png'));
            items.push(new FrolicTreeItem(
                `Session: ${LOG_BUFFER.length} events`,
                vscode.TreeItemCollapsibleState.None,
                'session-info',
                undefined,
                logoPath
            ));

            // Active files
            const activeFiles = this.getActiveFiles();
            if (activeFiles.length > 0) {
                items.push(new FrolicTreeItem(
                    `📄 Active Files (${activeFiles.length})`,
                    vscode.TreeItemCollapsibleState.Collapsed,
                    'active-files'
                ));
            }

            // Actions
            items.push(new FrolicTreeItem(
                '⚙️ Actions',
                vscode.TreeItemCollapsibleState.Collapsed,
                'actions'
            ));

            return Promise.resolve(items);
        } else if (element.contextValue === 'active-files') {
            // Show active files
            const activeFiles = this.getActiveFiles();
            return Promise.resolve(activeFiles.map(file => 
                new FrolicTreeItem(
                    `📄 ${file.name} (${file.count})`,
                    vscode.TreeItemCollapsibleState.None,
                    'file-item'
                )
            ));
        } else if (element.contextValue === 'actions') {
            // Show action items
            return Promise.resolve([
                new FrolicTreeItem(
                    '🚀 Send Digest Now',
                    vscode.TreeItemCollapsibleState.None,
                    'action-send-digest',
                    {
                        command: 'frolic.sendDigest',
                        title: 'Send Digest Now'
                    }
                ),
                new FrolicTreeItem(
                    '💾 Flush Logs',
                    vscode.TreeItemCollapsibleState.None,
                    'action-flush-logs',
                    {
                        command: 'frolic.flushLogs',
                        title: 'Flush Logs'
                    }
                ),
                new FrolicTreeItem(
                    '🔐 Sign In',
                    vscode.TreeItemCollapsibleState.None,
                    'action-sign-in',
                    {
                        command: 'frolic.signIn',
                        title: 'Sign In'
                    }
                )
            ]);
        }

        return Promise.resolve([]);
    }

    private getActiveFiles(): {name: string, count: number}[] {
        const fileActivity: {[key: string]: number} = {};
        
        LOG_BUFFER.forEach(entry => {
            if (entry.eventType === 'file_edit' && entry.relativePath) {
                fileActivity[entry.relativePath] = (fileActivity[entry.relativePath] || 0) + 1;
            }
        });

        return Object.entries(fileActivity)
            .map(([path, count]) => ({
                name: path.split('/').pop() || path,
                count
            }))
            .sort((a, b) => b.count - a.count)
            .slice(0, 5); // Show top 5 most active files
    }
}

class FrolicTreeItem extends vscode.TreeItem {
    constructor(
        public readonly label: string,
        public readonly collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly contextValue: string,
        public readonly command?: vscode.Command,
        public readonly iconPath?: vscode.ThemeIcon | vscode.Uri | { light: vscode.Uri; dark: vscode.Uri }
    ) {
        super(label, collapsibleState);
        this.tooltip = this.label;
        if (iconPath) {
            this.iconPath = iconPath;
        }
    }
}