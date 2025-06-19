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

    // Only log in development to avoid logging potentially sensitive code content
    if (isExtensionDevelopment()) {
    console.log(`[FROLIC] ${eventType}`, entry);
    }
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
  // Auto-detect development environment
  const isDevelopment = isExtensionDevelopment();
  
  if (isDevelopment) {
    console.log('[FROLIC] Development environment detected, using localhost');
    return 'http://localhost:3000';
  }
  
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

function isExtensionDevelopment(): boolean {
  // Check if we're running in extension development mode
  try {
    // Method 1: Check if running from extension development host
    if (extensionContext?.extensionMode === vscode.ExtensionMode.Development) {
      return true;
    }
    
    // Method 2: Check if we're in the workspace that contains package.json with our extension
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (workspaceFolders) {
      for (const folder of workspaceFolders) {
        try {
          const packagePath = path.join(folder.uri.fsPath, 'package.json');
          if (fs.existsSync(packagePath)) {
            const packageContent = fs.readFileSync(packagePath, 'utf8');
            const packageJson = JSON.parse(packageContent);
            // Check if this is our extension's package.json
            if (packageJson.name === 'frolic' && packageJson.publisher === 'frolic') {
              return true;
            }
          }
        } catch (err) {
          // Ignore errors reading package.json files
        }
      }
    }
    
    // Method 3: Check extension installation path
    if (extensionContext?.extensionPath && extensionContext.extensionPath.includes('/.vscode/extensions/') === false) {
      // If not installed in standard extensions folder, likely development
      return true;
    }
    
    return false;
  } catch (err) {
    console.log('[FROLIC] Error detecting development environment:', err);
    return false;
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
  // === RAW DATA COLLECTION (Minimal Processing) ===
  const files = new Set<string>();
  const langCounts: Record<string, number> = {};
  let totalLinesAdded = 0;
  let aiInsertions = 0;
  const fileActivity: Record<string, { 
    edits: number; 
    linesChanged: number; 
    firstEdit: string; 
    lastEdit: string;
    editPattern: number[]; // Time intervals between edits
  }> = {};

  // Session timing
  const sessionStart = logs.length > 0 ? new Date(logs[0].timestamp) : new Date();
  const sessionEnd = logs.length > 0 ? new Date(logs[logs.length - 1].timestamp) : new Date();
  const sessionDuration = (sessionEnd.getTime() - sessionStart.getTime()) / 1000 / 60; // minutes

  // Raw text aggregation for backend analysis
  let codeChangesText = '';
  const codeChangesSample: any[] = [];
  const importStatements: string[] = [];
  const fileExtensions = new Set<string>();
  const directoryStructure: Record<string, number> = {};

  // Process each log entry - MINIMAL processing, maximum raw data
  for (let i = 0; i < logs.length; i++) {
    const entry = logs[i];
    if (entry.eventType !== 'file_edit') continue;

    const filePath = entry.relativePath;
    files.add(filePath);
    langCounts[entry.language] = (langCounts[entry.language] || 0) + 1;

    // File extension tracking
    const ext = filePath.split('.').pop()?.toLowerCase() || 'unknown';
    fileExtensions.add(ext);

    // Directory structure (for project understanding)
    const dir = filePath.split('/').slice(0, -1).join('/') || 'root';
    directoryStructure[dir] = (directoryStructure[dir] || 0) + 1;

    // File activity tracking with timing
    if (!fileActivity[filePath]) {
      fileActivity[filePath] = { 
        edits: 0, 
        linesChanged: 0, 
        firstEdit: entry.timestamp,
        lastEdit: entry.timestamp,
        editPattern: []
      };
    }
    fileActivity[filePath].edits++;
    fileActivity[filePath].lastEdit = entry.timestamp;

    // Calculate edit intervals for pattern analysis
    if (i > 0 && logs[i-1].relativePath === filePath) {
      const timeDiff = (new Date(entry.timestamp).getTime() - new Date(logs[i-1].timestamp).getTime()) / 1000;
      fileActivity[filePath].editPattern.push(timeDiff);
    }

    // Process code changes - collect raw data
    for (const change of entry.changes || []) {
      const changeText = change.changeText || '';
      
      totalLinesAdded += change.lineCountDelta || 0;
      fileActivity[filePath].linesChanged += Math.abs(change.lineCountDelta || 0);
      
      if (change.likelyAI) aiInsertions++;

      // Collect raw code samples (first 100 significant changes)
      if (changeText.length > 20 && codeChangesSample.length < 100) {
        codeChangesSample.push({
          file: filePath,
          language: entry.language,
          timestamp: entry.timestamp,
          change: changeText.substring(0, 500), // Limit size but keep raw
          size: change.textLength,
          type: change.textLength > change.rangeLength ? 'addition' : 'modification'
        });
      }

      // Extract import statements (structural information)
      const importMatches = changeText.match(/import\s+.*?from\s+['"`]([^'"`]+)['"`]/g);
      if (importMatches) {
        importStatements.push(...importMatches.slice(0, 5)); // Limit to prevent spam
      }

      // Aggregate all code changes for backend analysis
      if (changeText.length > 10) {
        codeChangesText += `\n--- ${filePath} (${entry.language}) ---\n${changeText}\n`;
        }
      }
    }

  // === BASIC STRUCTURAL ANALYSIS (No Semantic Interpretation) ===
  const topFiles = Object.entries(fileActivity)
    .sort((a, b) => b[1].edits - a[1].edits)
    .slice(0, 10)
    .map(([file, stats]) => ({
      file,
      edits: stats.edits,
      linesChanged: stats.linesChanged,
      sessionDuration: (new Date(stats.lastEdit).getTime() - new Date(stats.firstEdit).getTime()) / 1000 / 60,
      editFrequency: stats.editPattern.length > 0 ? stats.editPattern.reduce((a, b) => a + b, 0) / stats.editPattern.length : 0
    }));

  const workingDirectories = Object.entries(directoryStructure)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  // === RETURN RAW DATA + MINIMAL STRUCTURE ===
  return {
    // === BACKWARDS COMPATIBLE (keep existing fields) ===
    filesEdited: files.size,
    totalLinesAdded,
    aiInsertions,
    topFiles: topFiles.map(f => f.file),
    languagesUsed: langCounts,
    inferredTopics: [], // Empty - let backend infer

    // === RAW DATA FOR BACKEND ANALYSIS ===
    rawData: {
      // Session context
      sessionId: sessionId,
      duration: Math.round(sessionDuration),
      startTime: sessionStart.toISOString(),
      endTime: sessionEnd.toISOString(),
      
      // File and code structure
      fileExtensions: Array.from(fileExtensions),
      workingDirectories: workingDirectories,
      detailedFileActivity: topFiles,
      
      // Raw code samples for LLM analysis
      codeChangesSample: codeChangesSample,
      importStatements: Array.from(new Set(importStatements)).slice(0, 20),
      
      // Behavioral patterns (structural, not semantic)
      codingVelocity: sessionDuration > 0 ? Math.round(totalLinesAdded / sessionDuration) : 0,
      editPatterns: {
        rapidEdits: logs.filter((log, i) => {
          if (i === 0) return false;
          const timeDiff = new Date(log.timestamp).getTime() - new Date(logs[i-1].timestamp).getTime();
          return timeDiff < 30000 && log.relativePath === logs[i-1].relativePath;
        }).length,
        fileJumping: new Set(logs.map(log => log.relativePath)).size,
        sessionIntensity: logs.length / Math.max(sessionDuration, 1)
      },
      
      // Context for backend analysis
      projectStructure: {
        totalDirectories: Object.keys(directoryStructure).length,
        fileTypeDistribution: Object.fromEntries(
          Array.from(fileExtensions).map(ext => [ext, 
            Array.from(files).filter(f => f.endsWith(`.${ext}`)).length
          ])
        ),
                 complexityIndicators: {
           avgEditsPerFile: files.size > 0 ? logs.filter(l => l.eventType === 'file_edit').length / files.size : 0,
           totalCodeChanges: codeChangesSample.length,
           largestChangeSize: codeChangesSample.length > 0 ? Math.max(...codeChangesSample.map(c => c.size)) : 0
         }
      }
    },

    // === ANALYSIS HINTS FOR BACKEND (Not hardcoded conclusions) ===
    analysisContext: {
      // What the backend should consider analyzing
      suggestedAnalysis: [
        'technology_stack_identification',
        'learning_progress_detection', 
        'coding_patterns_analysis',
        'project_complexity_assessment',
        'productivity_insights',
        'personalized_recommendations'
      ],
      
      // Provide context, not conclusions
      sessionCharacteristics: {
        isLongSession: sessionDuration > 60,
        isIntenseSession: logs.length > 100,
        isMultiFileSession: files.size > 5,
        hasLargeChanges: totalLinesAdded > 200,
        showsAIUsage: aiInsertions > 0
      }
    }
  };
}

// Removed all helper functions - analysis now done by backend

export async function signInCommand(context: vscode.ExtensionContext) {
  console.log('[FROLIC] Starting enhanced sign-in flow...');
  
  // Show loading state
  updateStatusBar('initializing');
  
  try {
    // Generate PKCE parameters
    const state = uuidv4();
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    const apiBaseUrl = getApiBaseUrl();
    
    // Get token expiration preference
    const config = vscode.workspace.getConfiguration('frolic');
    const tokenExpiration = config.get<string>('tokenExpiration', 'long');
    
    // Store PKCE parameters securely
    await context.secrets.store('frolic.codeVerifier', codeVerifier);
    await context.secrets.store('frolic.state', state);
    
    // Build auth URL
    const authUrl = `${apiBaseUrl}/api/auth/vscode/start?state=${state}&code_challenge=${codeChallenge}&token_type=${tokenExpiration}`;
    
    // Show initial progress message
    const progressResult = await vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification,
      title: "Frolic Sign-In",
      cancellable: true
    }, async (progress, token) => {
      
      progress.report({ message: "Opening browser for authentication..." });
      
      // Open browser
      const opened = await vscode.env.openExternal(vscode.Uri.parse(authUrl));
      if (!opened) {
        throw new Error('Failed to open browser');
      }
      
      progress.report({ message: "Waiting for authentication code..." });
      
      // Wait a moment for the browser to open
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Check if cancelled
      if (token.isCancellationRequested) {
        throw new Error('Sign-in cancelled by user');
      }
      
      // Prompt for code with enhanced UX
      const code = await vscode.window.showInputBox({
        title: 'Frolic Authentication',
        prompt: 'Paste the authentication code from your browser',
        placeHolder: 'e.g., abc123def456...',
        ignoreFocusOut: true,
        validateInput: (value) => {
          if (!value || value.trim().length === 0) {
            return 'Please enter the authentication code';
          }
          if (value.trim().length < 10) {
            return 'Authentication code seems too short';
          }
          return null;
        }
      });
      
      if (!code) {
        throw new Error('No authentication code provided');
      }
      
      progress.report({ message: "Exchanging code for tokens..." });
      
      // Exchange code for tokens
      const storedCodeVerifier = await context.secrets.get('frolic.codeVerifier');
      const storedState = await context.secrets.get('frolic.state');
      
      const tokenResponse = await fetchWithTimeout(`${apiBaseUrl}/api/auth/vscode/token`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'User-Agent': 'VSCode-Frolic-Extension/1.0.3'
        },
        body: JSON.stringify({ 
          code: code.trim(), 
          state: storedState, 
          code_verifier: storedCodeVerifier,
          token_type: tokenExpiration
        })
      }, 15000);
      
      if (!tokenResponse.ok) {
        const errorText = await tokenResponse.text();
        console.error(`[FROLIC] Token exchange failed: ${tokenResponse.status} ${errorText}`);
        
        if (tokenResponse.status === 400) {
          throw new Error('Invalid or expired authentication code. Please try again.');
        } else if (tokenResponse.status === 401) {
          throw new Error('Authentication failed. Please try again.');
        } else {
          throw new Error(`Authentication server error (${tokenResponse.status}). Please try again later.`);
        }
      }
      
      const tokenData = await tokenResponse.json();
      const accessToken = tokenData.accessToken || tokenData.access_token;
      const refreshToken = tokenData.refresh_token;
      
      if (!accessToken) {
        throw new Error('No access token received from server');
      }
      
      progress.report({ message: "Saving authentication..." });
      
      // Store tokens securely
      await context.secrets.store('frolic.accessToken', accessToken);
      if (refreshToken) {
        await context.secrets.store('frolic.refreshToken', refreshToken);
        console.log('[FROLIC] Stored both access and refresh tokens');
      } else {
        console.log('[FROLIC] Only access token received (no refresh token)');
      }
      
      // Clean up PKCE parameters
      await context.secrets.delete('frolic.codeVerifier');
      await context.secrets.delete('frolic.state');
      
      return { accessToken, refreshToken };
    });
    
    // Success!
    updateStatusBar('authenticated');
    
    // Show success message with next steps
    const action = await vscode.window.showInformationMessage(
      '🎉 Successfully signed in to Frolic! Your coding activity will now be tracked for personalized recaps.',
      'Send Test Digest',
      'View Activity'
    );
    
    if (action === 'Send Test Digest') {
      vscode.commands.executeCommand('frolic.sendDigest');
    } else if (action === 'View Activity') {
      vscode.commands.executeCommand('frolic-activity.focus');
    }
    
    console.log('[FROLIC] Sign-in completed successfully');
    
  } catch (error: any) {
    console.error('[FROLIC] Sign-in error:', error);
    
    // Update status bar to show error or unauthenticated state
    updateStatusBar('unauthenticated');
    
    // Clean up any stored PKCE parameters on error
    await context.secrets.delete('frolic.codeVerifier');
    await context.secrets.delete('frolic.state');
    
    // Show appropriate error message
    let errorMessage = 'Sign-in failed: ';
    if (error.message.includes('cancelled')) {
      errorMessage += 'Sign-in was cancelled';
    } else if (error.message.includes('network') || error.message.includes('fetch')) {
      errorMessage += 'Network error. Please check your connection and try again.';
    } else if (error.message.includes('browser')) {
      errorMessage += 'Could not open browser. Please try again.';
    } else {
      errorMessage += error.message || 'Unknown error occurred';
    }
    
    vscode.window.showErrorMessage(`🔐 Frolic: ${errorMessage}`, 'Try Again', 'Show Guide')
      .then(selection => {
        if (selection === 'Try Again') {
          vscode.commands.executeCommand('frolic.signIn');
        } else if (selection === 'Show Guide') {
          vscode.commands.executeCommand('frolic.showWelcome');
        }
      });
  }
}

/**
 * Initialize comprehensive authentication flow with multiple sign-in triggers
 */
async function initializeAuthenticationFlow(context: vscode.ExtensionContext) {
    try {
        const accessToken = await context.secrets.get('frolic.accessToken');
        const isFirstRun = context.globalState.get('frolic.hasEverRun', false);
        const hasShownWelcome = context.globalState.get('frolic.hasShownWelcome', false);
        
        if (!accessToken) {
            updateStatusBar('unauthenticated');
            
            // 1. FIRST-TIME ACTIVATION TRIGGER: Show walkthrough on first install
            if (!isFirstRun) {
                console.log('[FROLIC] First-time activation detected, showing welcome walkthrough');
                context.globalState.update('frolic.hasEverRun', true);
                
                // Small delay to ensure VS Code is fully loaded
                setTimeout(() => {
                    vscode.commands.executeCommand('workbench.action.openWalkthrough', 'frolic.frolic#frolic.welcome');
                }, 2000);
                
                return; // Don't show other prompts on first run
            }
            
            // 2. ACTIVATION EVENT TRIGGER: Show welcome message for returning users
            if (!hasShownWelcome) {
                const response = await vscode.window.showInformationMessage(
                    '🚀 Welcome to Frolic! Let\'s get you signed in to enable personalized coding recaps.',
                    'Sign In',
                    'Show Guide',
                    'Not Now'
                );
                
                if (response === 'Sign In') {
                    vscode.commands.executeCommand('frolic.signIn');
                } else if (response === 'Show Guide') {
                    vscode.commands.executeCommand('frolic.showWelcome');
                }
                
                context.globalState.update('frolic.hasShownWelcome', true);
            }
        } else {
            // User is authenticated
            updateStatusBar('authenticated');
            
            // Validate token and refresh if needed
            const validToken = await getValidAccessToken(context);
            if (!validToken) {
                console.log('[FROLIC] Token validation failed, showing sign-in prompt');
                updateStatusBar('unauthenticated');
                
                vscode.window.showWarningMessage(
                    'Frolic: Your session has expired. Please sign in again.',
                    'Sign In'
                ).then(selection => {
                    if (selection === 'Sign In') {
                        vscode.commands.executeCommand('frolic.signIn');
                    }
                });
            }
        }
    } catch (error) {
        console.error('[FROLIC] Error during authentication flow initialization:', error);
        updateStatusBar('error');
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

    // Register welcome walkthrough command
    const showWelcomeCmd = vscode.commands.registerCommand('frolic.showWelcome', () => {
        vscode.commands.executeCommand('workbench.action.openWalkthrough', 'frolic.frolic#frolic.welcome');
    });
    context.subscriptions.push(showWelcomeCmd);

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

    // Enhanced activation with multiple sign-in triggers
    initializeAuthenticationFlow(context);
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
            statusBarItem.command = undefined;
            break;
        case 'authenticated':
            statusBarItem.text = `$(check) Frolic (${LOG_BUFFER.length})`;
            statusBarItem.tooltip = `Frolic: ${LOG_BUFFER.length} events logged. Click to flush.`;
            statusBarItem.backgroundColor = undefined;
            statusBarItem.command = 'frolic.flushLogs';
            break;
        case 'unauthenticated':
            statusBarItem.text = '$(sign-in) Sign in to Frolic';
            statusBarItem.tooltip = 'Frolic: Sign in to enable cloud sync and get personalized recaps';
            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
            statusBarItem.command = 'frolic.signIn';
            break;
        case 'sending':
            statusBarItem.text = '$(cloud-upload) Frolic';
            statusBarItem.tooltip = 'Frolic: Sending digest...';
            statusBarItem.backgroundColor = undefined;
            statusBarItem.command = undefined;
            break;
        case 'error':
            statusBarItem.text = '$(error) Frolic';
            statusBarItem.tooltip = 'Frolic: Connection error. Click to retry.';
            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
            statusBarItem.command = 'frolic.signIn';
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