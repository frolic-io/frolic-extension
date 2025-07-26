import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
// Use crypto.randomUUID() instead of uuid package to avoid bundling issues
// This is built into Node.js 15+ and VS Code runtime
import * as crypto from 'crypto';
// Use built-in fetch instead of node-fetch to avoid bundling issues
// Built-in fetch is available in Node.js 18+ and VS Code runtime

const LOG_BUFFER: any[] = [];
const MAX_CHANGE_TEXT_LENGTH = 2000; // Truncate very large code changes
let isLoggingEnabled = true;
let sessionId = crypto.randomUUID();
let digestTimer: NodeJS.Timeout | null = null;
let lastDigestSentTime = 0; // Track when we last sent a digest
let pendingDigestSend = false; // Debounce flag for digest sends
let isFirstDigestSent = false; // Track if we've sent the first digest for onboarding
let bufferMemoryUsage = 0; // Track estimated memory usage in bytes
let statusBarItem: vscode.StatusBarItem;
let activityProvider: FrolicActivityProvider | undefined;
let extensionContext: vscode.ExtensionContext | undefined;

// Offline digest queue for graceful degradation
let offlineDigestQueue: Array<{sessionId: string, digest: any, timestamp: number}> = [];
const MAX_OFFLINE_DIGESTS = 1000;

// 🔄 PHASE 1.3: Smart Backup Triggers - Global state
let periodicBackupTimer: NodeJS.Timeout | null = null;
let inactivityBackupTimer: NodeJS.Timeout | null = null;
let lastBackupTime = 0;
let lastActivityTime = 0;
const BACKUP_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes
const ACTIVITY_BACKUP_THRESHOLD = 25; // Backup after 25 events
const MIN_BACKUP_INTERVAL_MS = 30 * 1000; // Minimum 30 seconds between backups

// 🔄 PHASE 1.4: Enhanced Break-Pattern Backup - Additional state
const MICRO_SESSION_THRESHOLD = 10; // Backup after 10 events (for short bursts)
const INACTIVITY_BACKUP_DELAY = 3 * 60 * 1000; // 3 minutes of inactivity
const QUICK_FIX_THRESHOLD = 5; // Backup after 5 events if 2+ minutes since last activity

// Removed notification throttling - now only showing notifications for first digest and manual sends

// 🔄 ENHANCED: Background token refresh management
let backgroundTokenRefreshTimer: NodeJS.Timeout | null = null;
const TOKEN_REFRESH_CHECK_INTERVAL = 5 * 60 * 1000; // Check every 5 minutes for more aggressive refresh
const TOKEN_REFRESH_BUFFER = 5 * 60; // Refresh 5 minutes before expiry (in seconds)
let tokenExpiresAt: number | null = null; // Store token expiration timestamp
let lastHealthCheck: number = 0; // Track last health check time
const HEALTH_CHECK_INTERVAL = 10 * 60 * 1000; // Check health every 10 minutes

// 🔄 PERSISTENT AUTH: Device registration and grace period
let deviceId: string | null = null;
let isDeviceRegistered: boolean = false;
const TOKEN_GRACE_PERIOD_DAYS = 7; // Allow expired tokens for 7 days
const MAX_AUTH_RETRY_ATTEMPTS = 10; // Increased from 3
const AUTH_RETRY_DELAYS = [1000, 2000, 4000, 8000, 16000, 30000, 30000, 30000, 30000, 30000]; // Exponential backoff up to 30s

// 📊 External Edit Tracking - Track file line counts for external edits (e.g., Claude)
const fileLineBaseline = new Map<string, number>();

// 🔄 PHASE 2.2: Learning Struggle Detection - Global state
let userActionHistory: Array<{
    timestamp: number;
    action: 'undo' | 'redo' | 'pause' | 'file_switch' | 'error_fix' | 'rapid_edit';
    context?: any;
}> = [];
let pauseStartTime: number | null = null;
let lastSignificantAction: number = Date.now();
let recentFileOpenings: Array<{ file: string; timestamp: number }> = [];
let undoRedoSequence: Array<{ timestamp: number; type: 'undo' | 'redo' }> = [];

// 🔄 PHASE 2.3: Error and Debugging Tracking - Global state
let diagnosticHistory: Array<{
    timestamp: number;
    uri: string;
    diagnostics: vscode.Diagnostic[];
    eventType: 'added' | 'removed' | 'changed';
}> = [];
let activeErrorSessions: Map<string, {
    startTime: number;
    errorCount: number;
    errorTypes: string[];
    lastErrorTimestamp: number;
}> = new Map();
let previousDiagnostics: Map<string, vscode.Diagnostic[]> = new Map();

// Diagnostic logging throttle to prevent LOG_BUFFER flooding
let lastDiagnosticLogTime: Map<string, number> = new Map();
const DIAGNOSTIC_LOG_THROTTLE_MS = 10 * 1000; // Only log diagnostics every 10 seconds per file

// Clean up old diagnostic throttle entries periodically
function cleanupDiagnosticThrottle() {
    const now = Date.now();
    const cutoff = now - DIAGNOSTIC_LOG_THROTTLE_MS * 2; // Clean entries older than 20 seconds
    for (const [filePath, lastTime] of lastDiagnosticLogTime) {
        if (lastTime < cutoff) {
            lastDiagnosticLogTime.delete(filePath);
        }
    }
}

// Thresholds for struggle detection
const RAPID_UNDO_REDO_THRESHOLD = 5; // 5 undo/redo actions within 30 seconds
const RAPID_UNDO_REDO_TIME_WINDOW = 30 * 1000; // 30 seconds
const LONG_PAUSE_THRESHOLD = 2 * 60 * 1000; // 2 minutes
const FREQUENT_SWITCHING_THRESHOLD = 8; // 8 file switches within 2 minutes
const FREQUENT_SWITCHING_TIME_WINDOW = 2 * 60 * 1000; // 2 minutes
const ERROR_HEAVY_SESSION_THRESHOLD = 10; // 10+ errors in a file

// Removed getNotificationThrottleMs - notifications now only for first digest and manual sends

// Path validation utilities
function isValidPath(filePath: string): boolean {
    if (!filePath || typeof filePath !== 'string') {
        return false;
    }
    
    // Check for path traversal attempts
    if (filePath.includes('..') || filePath.includes('~')) {
        return false;
    }
    
    // Check for null bytes
    if (filePath.includes('\0')) {
        return false;
    }
    
    return true;
}

function sanitizePath(filePath: string): string {
    if (!isValidPath(filePath)) {
        console.warn('[FROLIC] Invalid path detected:', filePath);
        return '';
    }
    
    // Remove any potentially dangerous characters
    return filePath.replace(/[<>:"|?*]/g, '');
}

// Privacy mode utilities
function hashPath(filePath: string): string {
    // Use a simple hash function for privacy mode
    // This provides consistency across sessions while protecting actual paths
    const crypto = require('crypto');
    const hash = crypto.createHash('sha256');
    hash.update(filePath);
    const fullHash = hash.digest('hex');
    
    // Keep file extension for language detection
    const ext = path.extname(filePath);
    
    // Return first 8 chars of hash + extension
    return `file_${fullHash.substring(0, 8)}${ext}`;
}

function getPrivacyModePath(filePath: string): string {
    const config = vscode.workspace.getConfiguration('frolic');
    const privacyMode = config.get<boolean>('privacyMode', false);
    
    if (privacyMode && filePath) {
        return hashPath(filePath);
    }
    
    return filePath;
}

// Get configurable limits
function getBufferLimits() {
    const config = vscode.workspace.getConfiguration('frolic');
    return {
        maxBufferSize: config.get<number>('maxBufferSize', 10000),
        maxMemoryMB: config.get<number>('maxMemoryMB', 50)
    };
}

// 🔄 PHASE 2.2: Learning Struggle Detection Helper Functions

function logStruggleEvent(eventType: string, data: any) {
    logEvent('struggle_indicator', {
        ...data,
        struggleType: eventType,
        sessionContext: getCurrentSessionContext(),
        timestamp: new Date().toISOString()
    });
}

function getCurrentSessionContext(): any {
    const activeEditor = vscode.window.activeTextEditor;
    return {
        activeFile: activeEditor?.document.fileName,
        language: activeEditor?.document.languageId,
        lineCount: activeEditor?.document.lineCount,
        cursorPosition: activeEditor?.selection.active ? {
            line: activeEditor.selection.active.line,
            character: activeEditor.selection.active.character
        } : null,
        recentFiles: recentFileOpenings.slice(-3).map(f => f.file)
    };
}

function detectRapidUndoRedo(timestamp: number, type: 'undo' | 'redo') {
    // Clean old entries
    const cutoff = timestamp - RAPID_UNDO_REDO_TIME_WINDOW;
    undoRedoSequence = undoRedoSequence.filter(entry => entry.timestamp > cutoff);
    
    // Add current action
    undoRedoSequence.push({ timestamp, type });
    
    // Check if we've exceeded the threshold
    if (undoRedoSequence.length >= RAPID_UNDO_REDO_THRESHOLD) {
        logStruggleEvent('rapid_undo_redo', {
            sequenceLength: undoRedoSequence.length,
            timeSpan: timestamp - undoRedoSequence[0].timestamp,
            pattern: undoRedoSequence.map(s => s.type).join('->'),
            context: getCurrentSessionContext()
        });
        
        // Reset to avoid duplicate detection
        undoRedoSequence = [];
    }
}

function detectLongPause(timestamp: number) {
    const pauseDuration = timestamp - lastSignificantAction;
    
    if (pauseDuration > LONG_PAUSE_THRESHOLD) {
        logStruggleEvent('long_pause', {
            duration: pauseDuration,
            durationMinutes: Math.round(pauseDuration / 60000),
            context: getCurrentSessionContext()
        });
    }
}

function detectFrequentFileSwitching(fileName: string, timestamp: number) {
    // Clean old entries
    const cutoff = timestamp - FREQUENT_SWITCHING_TIME_WINDOW;
    recentFileOpenings = recentFileOpenings.filter(entry => entry.timestamp > cutoff);
    
    // Add current opening
    recentFileOpenings.push({ file: fileName, timestamp });
    
    // Check if we've exceeded the threshold
    if (recentFileOpenings.length >= FREQUENT_SWITCHING_THRESHOLD) {
        const uniqueFiles = new Set(recentFileOpenings.map(f => f.file));
        
        logStruggleEvent('frequent_file_switching', {
            switchCount: recentFileOpenings.length,
            uniqueFiles: uniqueFiles.size,
            timeSpan: timestamp - recentFileOpenings[0].timestamp,
            files: Array.from(uniqueFiles),
            context: getCurrentSessionContext()
        });
        
        // Reset to avoid duplicate detection
        recentFileOpenings = recentFileOpenings.slice(-3);
    }
}

function cleanupOldStruggleData() {
    const cutoff = Date.now() - (24 * 60 * 60 * 1000); // 24 hours
    
    userActionHistory = userActionHistory.filter(entry => entry.timestamp > cutoff);
    recentFileOpenings = recentFileOpenings.filter(entry => entry.timestamp > cutoff);
    undoRedoSequence = undoRedoSequence.filter(entry => entry.timestamp > cutoff);
}

// 🔄 PHASE 2.3: Error and Debugging Tracking Helper Functions

function categorizeError(diagnostic: vscode.Diagnostic): string {
    const message = diagnostic.message.toLowerCase();
    const code = diagnostic.code?.toString().toLowerCase() || '';
    
    if (message.includes('syntax') || message.includes('unexpected') || 
        message.includes('parse') || code.includes('syntax')) {
        return 'syntax';
    } else if (message.includes('undefined') || message.includes('not found') || 
               message.includes('cannot find') || message.includes('unresolved')) {
        return 'reference';
    } else if (message.includes('type') || message.includes('expected') || 
               code.includes('type')) {
        return 'type';
    } else if (message.includes('import') || message.includes('module') || 
               message.includes('require')) {
        return 'import';
    } else {
        return 'logic';
    }
}

function getDiagnosticChangeType(uri: vscode.Uri, currentDiagnostics: vscode.Diagnostic[]): 'added' | 'removed' | 'changed' {
    const uriString = uri.toString();
    const previous = previousDiagnostics.get(uriString) || [];
    
    if (previous.length === 0 && currentDiagnostics.length > 0) {
        return 'added';
    } else if (previous.length > 0 && currentDiagnostics.length === 0) {
        return 'removed';
    } else {
        return 'changed';
    }
}

function updateErrorSession(filePath: string, diagnostics: vscode.Diagnostic[]) {
    const errors = diagnostics.filter(d => d.severity === vscode.DiagnosticSeverity.Error);
    const warnings = diagnostics.filter(d => d.severity === vscode.DiagnosticSeverity.Warning);
    const timestamp = Date.now();
    
    if (errors.length > 0 || warnings.length > 0) {
        if (!activeErrorSessions.has(filePath)) {
            activeErrorSessions.set(filePath, {
                startTime: timestamp,
                errorCount: 0,
                errorTypes: [],
                lastErrorTimestamp: timestamp
            });
        }
        
        const session = activeErrorSessions.get(filePath)!;
        session.errorCount = errors.length;
        session.errorTypes = errors.map(e => categorizeError(e));
        session.lastErrorTimestamp = timestamp;
        
        // Check for error-heavy session
        if (errors.length >= ERROR_HEAVY_SESSION_THRESHOLD) {
            logStruggleEvent('error_heavy_session', {
                file: filePath,
                errorCount: errors.length,
                warningCount: warnings.length,
                errorTypes: session.errorTypes,
                sessionDuration: timestamp - session.startTime,
                context: getCurrentSessionContext()
            });
        }
    } else {
        // Session ended - log the debugging session
        const session = activeErrorSessions.get(filePath);
        if (session) {
            const sessionDuration = timestamp - session.startTime;
            
            logEvent('debugging_session_end', {
                file: filePath,
                duration: sessionDuration,
                durationMinutes: Math.round(sessionDuration / 60000),
                maxErrorCount: session.errorCount,
                errorTypes: session.errorTypes,
                resolution: 'errors_cleared',
                context: getCurrentSessionContext()
            });
            
            activeErrorSessions.delete(filePath);
        }
    }
}

function cleanupOldErrorData() {
    const cutoff = Date.now() - (24 * 60 * 60 * 1000); // 24 hours
    
    diagnosticHistory = diagnosticHistory.filter(entry => entry.timestamp > cutoff);
    
    // Clean up stale error sessions (over 2 hours old)
    const staleCutoff = Date.now() - (2 * 60 * 60 * 1000);
    for (const [filePath, session] of activeErrorSessions.entries()) {
        if (session.lastErrorTimestamp < staleCutoff) {
            activeErrorSessions.delete(filePath);
        }
    }
}

function logEvent(eventType: string, data: any) {
    if (!isLoggingEnabled) return;

    const rawFilePath = data.file ?? "";
    
    // Validate and sanitize the file path
    if (!isValidPath(rawFilePath)) {
        console.warn('[FROLIC] Skipping event due to invalid file path');
        return;
    }
    
    const filePath = sanitizePath(rawFilePath);
    
    // Use minimal filtering like stable version
    if (filePath.includes(".git") || filePath.startsWith("git/") || filePath === "exthost" || 
        filePath.includes(".frolic-session.json") || filePath.includes(".frolic-log.json")) return;

    // Apply privacy mode if enabled
    const privacyPath = getPrivacyModePath(filePath);
    const privacyRelativePath = getPrivacyModePath(vscode.workspace.asRelativePath(filePath));
    
    // Check if AI detection is disabled
    const config = vscode.workspace.getConfiguration('frolic');
    const disableAIDetection = config.get<boolean>('disableAIDetection', false);

    const entry = {
        timestamp: new Date().toISOString(),
        sessionId,
        eventType,
        file: privacyPath,
        relativePath: privacyRelativePath,
        language: data.language ?? "unknown",
        lineCount: data.lineCount ?? 0,
        isDirty: data.isDirty ?? false,
        isUntitled: data.isUntitled ?? false,
        cursorPosition: data.cursorPosition ? {
            line: data.cursorPosition.line || 0,
            character: data.cursorPosition.character || 0
        } : null,
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
                likelyAI: disableAIDetection ? false : (c.textLength > 100 && c.rangeLength === 0),
                changeText: changeText,
                wasTruncated: wasTruncated
            };
        })
    };

    // Add the entry to the buffer FIRST
    LOG_BUFFER.push(entry);

    // 🔄 PHASE 1.3: Update activity tracking for smart backups
    lastActivityTime = Date.now();
    
    // 🔄 PHASE 2.2: Learning Struggle Detection
    const now = Date.now();
    if (eventType === 'file_edit' && data.changes && data.changes.length > 0) {
        // Detect long pauses before significant edits
        detectLongPause(now);
        
        // Update last significant action
        lastSignificantAction = now;
        
        // Track rapid editing patterns
        const changeText = data.changes.map((c: any) => c.changeText || '').join('');
        if (changeText.includes('undo') || changeText.includes('redo')) {
            const type = changeText.includes('undo') ? 'undo' : 'redo';
            detectRapidUndoRedo(now, type);
        }
    }

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

    // 🔄 PHASE 1.3: Smart backup trigger - activity-based backup
    if (LOG_BUFFER.length > 0 && LOG_BUFFER.length % ACTIVITY_BACKUP_THRESHOLD === 0) {
        // Don't block logging - create backup in background
        createSmartBackup(`activity-${LOG_BUFFER.length}-events`).catch(err => {
            console.log('[FROLIC] Activity-based backup failed, will retry later');
        });
    }

    // 🔄 PHASE 1.4: Enhanced break-pattern backup triggers
    const timeSinceLastActivity = Date.now() - (lastActivityTime - 60000); // Previous activity time
    
    // Micro-session backup: 10 events for short bursts
    if (LOG_BUFFER.length > 0 && LOG_BUFFER.length % MICRO_SESSION_THRESHOLD === 0) {
        createSmartBackup(`micro-session-${LOG_BUFFER.length}-events`).catch(err => {
            console.log('[FROLIC] Micro-session backup failed, will retry later');
        });
    }
    
    // Quick-fix backup: 5 events if it's been 2+ minutes since last activity
    if (LOG_BUFFER.length > 0 && LOG_BUFFER.length % QUICK_FIX_THRESHOLD === 0 && timeSinceLastActivity > 2 * 60 * 1000) {
        createSmartBackup(`quick-fix-${LOG_BUFFER.length}-events`).catch(err => {
            console.log('[FROLIC] Quick-fix backup failed, will retry later');
        });
    }
    
    // Reset inactivity timer on each activity
    resetInactivityBackupTimer();

    // Send digest if buffer gets large (activity-based trigger)
    if (LOG_BUFFER.length >= 1000 && LOG_BUFFER.length % 500 === 0) {
        console.log(`[FROLIC] Buffer reached ${LOG_BUFFER.length} events, considering digest send`);
        // Don't block logging - send in background
        if (extensionContext) {
            sendDigestImmediately(extensionContext, 3, false).catch(err => {
                console.log('[FROLIC] Activity-based digest send failed, will retry later');
            });
        }
    }

    // Debug logging (removed environment detection)
    // console.log(`[FROLIC] ${eventType}`, entry);

    // Update status bar to reflect current event count in tooltip
    // Only update if status bar is already in authenticated state
    if (statusBarItem && statusBarItem.text.includes('$(check)')) {
        updateStatusBar('authenticated');
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

/**
 * Recover session data from backup files on extension startup
 * This fixes the Friday→Monday data loss issue
 */
async function recoverSessionData(context: vscode.ExtensionContext): Promise<number> {
    let recoveredEvents = 0;
    
    try {
        // Try to recover from workspace backup file first
        const workspaceEvents = await recoverFromWorkspaceBackup();
        if (workspaceEvents > 0) {
            console.log(`[FROLIC] Recovered ${workspaceEvents} events from workspace backup`);
            recoveredEvents += workspaceEvents;
        }
        
        // Try to recover from VS Code extension storage as fallback
        if (recoveredEvents === 0) {
            const storageEvents = await recoverFromExtensionStorage(context);
            if (storageEvents > 0) {
                console.log(`[FROLIC] Recovered ${storageEvents} events from extension storage`);
                recoveredEvents += storageEvents;
            }
        }
        
        // 🔄 PHASE 1.3: Try to recover from temp directory as final fallback
        if (recoveredEvents === 0) {
            const tempEvents = await recoverFromTempDirectory();
            if (tempEvents > 0) {
                console.log(`[FROLIC] Recovered ${tempEvents} events from temp directory`);
                recoveredEvents += tempEvents;
            }
        }
        
        if (recoveredEvents > 0) {
            console.log(`[FROLIC] 🔄 Session recovery complete: ${recoveredEvents} total events restored`);
            
            // Clean up old backup files after successful recovery
            await cleanupOldBackups();
            
            // Recalculate memory usage after recovery
            recalculateBufferMemoryUsage();
        } else {
            console.log('[FROLIC] No previous session data found to recover');
        }
        
    } catch (error) {
        console.error('[FROLIC] Session recovery failed:', error);
        // Don't fail extension activation on recovery errors
    }
    
    return recoveredEvents;
}

/**
 * Recover data from workspace backup files (.frolic-log.json and emergency backups)
 */
async function recoverFromWorkspaceBackup(): Promise<number> {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
        return 0;
    }
    
    const workspacePath = workspaceFolders[0].uri.fsPath;
    let totalRecovered = 0;
    
    try {
        // 1. Try new smart backup file first (.frolic-session.json)
        const smartBackupPath = path.join(workspacePath, '.frolic-session.json');
        if (fs.existsSync(smartBackupPath)) {
            const recovered = await recoverFromBackupFile(smartBackupPath, 'smart-primary');
            totalRecovered += recovered;
        }
        
        // 2. Try legacy backup file (.frolic-log.json) for backwards compatibility
        const legacyBackupPath = path.join(workspacePath, '.frolic-log.json');
        if (fs.existsSync(legacyBackupPath) && totalRecovered === 0) {
            const recovered = await recoverFromBackupFile(legacyBackupPath, 'legacy-primary');
            totalRecovered += recovered;
        }
        
        // 3. Try emergency backup files (timestamped) if no primary recovery
        if (totalRecovered === 0) {
            const files = fs.readdirSync(workspacePath);
            const emergencyBackups = files
                .filter(file => file.startsWith('.frolic-backup-') && file.endsWith('.json'))
                .map(file => ({
                    file,
                    path: path.join(workspacePath, file),
                    timestamp: fs.statSync(path.join(workspacePath, file)).mtime
                }))
                .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime()); // Newest first
            
            for (const backup of emergencyBackups) {
                const recovered = await recoverFromBackupFile(backup.path, 'emergency');
                totalRecovered += recovered;
                
                // Only recover from the most recent emergency backup
                if (recovered > 0) break;
            }
        }
        
    } catch (error) {
        console.error(`[FROLIC] Failed to recover from workspace backups: ${error}`);
    }
    
    return totalRecovered;
}

/**
 * Recover data from a specific backup file
 */
async function recoverFromBackupFile(filePath: string, backupType: string): Promise<number> {
    try {
        const backupData = fs.readFileSync(filePath, 'utf8');
        const backupJson = JSON.parse(backupData);
        
        // Handle both old format (array) and new format (object with events)
        const backupEvents = Array.isArray(backupJson) ? backupJson : backupJson.events;
        
        if (Array.isArray(backupEvents) && backupEvents.length > 0) {
            // Filter out events older than 7 days to prevent stale data
            const sevenDaysAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);
            const recentEvents = backupEvents.filter(event => {
                const eventTime = new Date(event.timestamp).getTime();
                return eventTime > sevenDaysAgo;
            });
            
            if (recentEvents.length > 0) {
                // Merge with existing buffer (in case there's already some data)
                LOG_BUFFER.push(...recentEvents);
                
                // Delete the backup file after successful recovery
                fs.unlinkSync(filePath);
                console.log(`[FROLIC] Deleted processed ${backupType} backup: ${path.basename(filePath)}`);
                
                return recentEvents.length;
            }
        }
    } catch (error) {
        console.error(`[FROLIC] Failed to recover from ${backupType} backup ${filePath}: ${error}`);
    }
    
    return 0;
}

/**
 * Recover data from VS Code extension storage (fallback)
 */
async function recoverFromExtensionStorage(context: vscode.ExtensionContext): Promise<number> {
    try {
        // Try new smart backup first
        let backupData = context.globalState.get<any>('frolic.smartBackup');
        let backupType = 'smart';
        let backupKey = 'frolic.smartBackup';
        
        // Fall back to legacy backup if no smart backup found
        if (!backupData) {
            backupData = context.globalState.get<any[]>('frolic.sessionBackup');
            backupType = 'legacy';
            backupKey = 'frolic.sessionBackup';
        }
        
        if (!backupData) {
            return 0;
        }
        
        let eventsToRecover: any[] = [];
        
        // Handle different backup formats
        if (backupType === 'smart' && backupData.events) {
            eventsToRecover = backupData.events;
        } else if (backupType === 'legacy' && Array.isArray(backupData)) {
            eventsToRecover = backupData;
        }
        
        if (eventsToRecover.length > 0) {
            // Filter out events older than 7 days
            const sevenDaysAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);
            const recentEvents = eventsToRecover.filter(event => {
                const eventTime = new Date(event.timestamp).getTime();
                return eventTime > sevenDaysAgo;
            });
            
            if (recentEvents.length > 0) {
                // Merge with existing buffer
                LOG_BUFFER.push(...recentEvents);
                
                // Clear the storage backup after successful recovery
                await context.globalState.update(backupKey, undefined);
                console.log(`[FROLIC] Extension storage recovery (${backupType}): ${recentEvents.length} events restored`);
                
                return recentEvents.length;
            }
        }
    } catch (error) {
        console.error(`[FROLIC] Failed to recover from extension storage: ${error}`);
    }
    
    return 0;
}

/**
 * 🔄 PHASE 1.3: Recover data from temp directory as final fallback
 */
async function recoverFromTempDirectory(): Promise<number> {
    try {
        const os = require('os');
        const tempDir = os.tmpdir();
        
        if (!fs.existsSync(tempDir)) {
            return 0;
        }
        
        const files = fs.readdirSync(tempDir);
        const tempBackups = files
            .filter(file => file.startsWith('frolic-emergency-') && file.endsWith('.json'))
            .map(file => ({
                file,
                path: path.join(tempDir, file),
                timestamp: fs.statSync(path.join(tempDir, file)).mtime
            }))
            .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime()); // Newest first
        
        for (const backup of tempBackups) {
            const recovered = await recoverFromBackupFile(backup.path, 'temp-emergency');
            if (recovered > 0) {
                // Clean up the temp backup after successful recovery
                try {
                    fs.unlinkSync(backup.path);
                    console.log(`[FROLIC] Cleaned up temp backup: ${backup.file}`);
                } catch (err) {
                    console.warn(`[FROLIC] Failed to clean up temp backup: ${backup.file}`);
                }
                return recovered;
            }
        }
        
    } catch (error) {
        console.error('[FROLIC] Temp directory recovery failed:', error);
    }
    
    return 0;
}

/**
 * Clean up old backup files (older than 7 days)
 */
async function cleanupOldBackups(): Promise<void> {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
        return;
    }
    
    const workspacePath = workspaceFolders[0].uri.fsPath;
    const sevenDaysAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);
    
    try {
        // Look for any .frolic-*.json files in workspace
        const files = fs.readdirSync(workspacePath);
        const frolicsFiles = files.filter(file => file.startsWith('.frolic-') && file.endsWith('.json'));
        
        for (const file of frolicsFiles) {
            const filePath = path.join(workspacePath, file);
            const stats = fs.statSync(filePath);
            
            if (stats.mtime.getTime() < sevenDaysAgo) {
                fs.unlinkSync(filePath);
                console.log(`[FROLIC] Cleaned up old backup file: ${file}`);
            }
        }
    } catch (error) {
        console.warn(`[FROLIC] Backup cleanup failed: ${error}`);
    }
}

/**
 * Recalculate buffer memory usage after recovery
 */
function recalculateBufferMemoryUsage(): void {
    bufferMemoryUsage = 0;
    for (const entry of LOG_BUFFER) {
        const entrySize = JSON.stringify(entry).length * 2;
        bufferMemoryUsage += entrySize;
    }
    console.log(`[FROLIC] Recalculated buffer memory usage: ${(bufferMemoryUsage / 1024 / 1024).toFixed(2)}MB`);
}

/**
 * 🔄 PHASE 1.3: Smart backup system with multiple triggers
 * Creates backups at strategic points to prevent data loss
 */
async function createSmartBackup(trigger: string, force = false): Promise<void> {
    const now = Date.now();
    
    // Prevent too frequent backups (unless forced)
    if (!force && (now - lastBackupTime) < MIN_BACKUP_INTERVAL_MS) {
        return;
    }
    
    // Only backup if there's meaningful data
    if (LOG_BUFFER.length === 0) {
        return;
    }
    
    try {
        console.log(`[FROLIC] 💾 Smart backup triggered by: ${trigger} (${LOG_BUFFER.length} events)`);
        
        // Create multiple backup layers for safety
        await Promise.all([
            createWorkspaceBackup(),
            createExtensionStorageBackup(),
            createTempDirectoryBackup()
        ]);
        
        lastBackupTime = now;
        console.log(`[FROLIC] ✅ Smart backup completed (${trigger})`);
        
    } catch (error) {
        console.error(`[FROLIC] ❌ Smart backup failed (${trigger}):`, error);
    }
}

/**
 * Create workspace backup file
 */
async function createWorkspaceBackup(): Promise<void> {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
        return;
    }
    
    const workspacePath = workspaceFolders[0].uri.fsPath;
    const backupPath = path.join(workspacePath, '.frolic-session.json');
    
    const backupData = {
        timestamp: new Date().toISOString(),
        sessionId: sessionId,
        eventCount: LOG_BUFFER.length,
        events: LOG_BUFFER,
        metadata: {
            version: '1.3.0',
            trigger: 'smart-backup',
            memoryUsage: bufferMemoryUsage
        }
    };
    
    fs.writeFileSync(backupPath, JSON.stringify(backupData, null, 2), 'utf8');
}

/**
 * Create VS Code extension storage backup
 */
async function createExtensionStorageBackup(): Promise<void> {
    if (!extensionContext) return;
    
    const backupData = {
        timestamp: new Date().toISOString(),
        sessionId: sessionId,
        eventCount: LOG_BUFFER.length,
        events: LOG_BUFFER.slice(-1000), // Limit to last 1000 events for storage efficiency
        metadata: {
            version: '1.3.0',
            trigger: 'smart-backup-storage',
            truncated: LOG_BUFFER.length > 1000
        }
    };
    
    await extensionContext.globalState.update('frolic.smartBackup', backupData);
}

/**
 * Create OS temp directory backup as final fallback
 */
async function createTempDirectoryBackup(): Promise<void> {
    try {
        const os = require('os');
        const tempDir = os.tmpdir();
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const tempBackupPath = path.join(tempDir, `frolic-emergency-${timestamp}.json`);
        
        const backupData = {
            timestamp: new Date().toISOString(),
            sessionId: sessionId,
            eventCount: LOG_BUFFER.length,
            events: LOG_BUFFER,
            metadata: {
                version: '1.3.0',
                trigger: 'smart-backup-temp',
                workspace: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || 'unknown'
            }
        };
        
        fs.writeFileSync(tempBackupPath, JSON.stringify(backupData, null, 2), 'utf8');
        
        // Clean up old temp backups (keep only last 3)
        await cleanupTempBackups(tempDir);
        
    } catch (error) {
        console.warn('[FROLIC] Temp directory backup failed:', error);
    }
}

/**
 * Clean up old temp backup files
 */
async function cleanupTempBackups(tempDir: string): Promise<void> {
    try {
        const files = fs.readdirSync(tempDir);
        const frolicsBackups = files
            .filter(file => file.startsWith('frolic-emergency-') && file.endsWith('.json'))
            .map(file => ({
                file,
                path: path.join(tempDir, file),
                timestamp: fs.statSync(path.join(tempDir, file)).mtime
            }))
            .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
        
        // Keep only the 3 most recent backups
        const filesToDelete = frolicsBackups.slice(3);
        for (const backup of filesToDelete) {
            fs.unlinkSync(backup.path);
        }
        
    } catch (error) {
        console.warn('[FROLIC] Temp backup cleanup failed:', error);
    }
}

/**
 * Start periodic backup timer (every 5 minutes during active coding)
 */
function startPeriodicBackup(): void {
    if (periodicBackupTimer) {
        clearInterval(periodicBackupTimer);
    }
    
    periodicBackupTimer = setInterval(async () => {
        const now = Date.now();
        const timeSinceLastActivity = now - lastActivityTime;
        
        // Only backup if there was recent activity (within last 10 minutes)
        if (timeSinceLastActivity < 10 * 60 * 1000) {
            await createSmartBackup('periodic-5min');
        }
        
        // Clean up diagnostic throttle map to prevent memory leaks
        cleanupDiagnosticThrottle();
    }, BACKUP_INTERVAL_MS);
    
    console.log('[FROLIC] ⏰ Periodic backup timer started (every 5 minutes)');
}

/**
 * Stop periodic backup timer
 */
function stopPeriodicBackup(): void {
    if (periodicBackupTimer) {
        clearInterval(periodicBackupTimer);
        periodicBackupTimer = null;
        console.log('[FROLIC] ⏰ Periodic backup timer stopped');
    }
}

/**
 * 🔄 PHASE 1.4: Reset inactivity backup timer
 * Called on each coding activity to restart the inactivity countdown
 */
function resetInactivityBackupTimer(): void {
    // Clear existing timer
    if (inactivityBackupTimer) {
        clearTimeout(inactivityBackupTimer);
        inactivityBackupTimer = null;
    }
    
    // Start new inactivity timer
    inactivityBackupTimer = setTimeout(async () => {
        // Only backup if there's meaningful data and user hasn't been active
        if (LOG_BUFFER.length > 0) {
            const timeSinceLastActivity = Date.now() - lastActivityTime;
            if (timeSinceLastActivity >= INACTIVITY_BACKUP_DELAY) {
                await createSmartBackup('inactivity-3min');
                console.log('[FROLIC] 💤 Inactivity backup created (3 minutes of no coding)');
            }
        }
        inactivityBackupTimer = null;
    }, INACTIVITY_BACKUP_DELAY);
}

/**
 * 🔄 PHASE 1.4: Stop inactivity backup timer
 */
function stopInactivityBackupTimer(): void {
    if (inactivityBackupTimer) {
        clearTimeout(inactivityBackupTimer);
        inactivityBackupTimer = null;
        console.log('[FROLIC] 💤 Inactivity backup timer stopped');
    }
}

function getApiBaseUrl(): string {
  const config = vscode.workspace.getConfiguration('frolic');
  const url = config.get<string>('apiBaseUrl') || 'https://getfrolic.dev';
  
  // Remove debugging log
  return url;
}

// Helper function to add timeout to fetch requests
async function fetchWithTimeout(url: string, options: any, timeoutMs: number = 30000): Promise<Response> {
  // Check if we're in a test environment or if fetch is not available
  if (typeof fetch === 'undefined') {
    // For Node.js environment in tests, we'll return a mock response
    // In actual VS Code environment, fetch is available
    console.log('[FROLIC] Fetch not available in this environment');
    throw new Error('Fetch not available');
  }

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
    .replace(/=/g, '');
}

function generateCodeVerifier(): string {
  return base64URLEncode(crypto.randomBytes(32));
}

function generateCodeChallenge(verifier: string): string {
  return base64URLEncode(crypto.createHash('sha256').update(verifier).digest());
}

// Track ongoing refresh attempts to prevent race conditions
let isRefreshing = false;
let refreshPromise: Promise<string | null> | null = null;

/**
 * Get a valid access token, refreshing it if necessary
 */
async function getValidAccessToken(context: vscode.ExtensionContext): Promise<string | null> {
  const accessToken = await context.secrets.get('frolic.accessToken');
  const refreshToken = await context.secrets.get('frolic.refreshToken');
  
  // If no access token, check if we have refresh token
  if (!accessToken) {
    if (refreshToken) {
      return await performTokenRefresh(context, refreshToken);
    }
    return null;
  }
  
  // Check if access token is expired by trying to decode it
  if (isTokenExpired(accessToken)) {
    console.log('[FROLIC] Access token is expired, attempting refresh...');
    if (refreshToken) {
      console.log('[FROLIC] Refresh token available, refreshing access token...');
      return await performTokenRefresh(context, refreshToken);
    } else {
      console.log('[FROLIC] No refresh token available, user needs to sign in again');
      await context.secrets.delete('frolic.accessToken');
      return null;
    }
  }
  
  // Check if we should proactively refresh (5 minutes before expiry)
  if (tokenExpiresAt && refreshToken) {
    const now = Math.floor(Date.now() / 1000);
    const timeUntilExpiry = tokenExpiresAt - now;
    
    if (timeUntilExpiry < TOKEN_REFRESH_BUFFER) {
      console.log(`[FROLIC] Token expiring in ${timeUntilExpiry}s, proactively refreshing...`);
      return await performTokenRefresh(context, refreshToken);
    }
  }
  
  return accessToken;
}

/**
 * Check if we have network connectivity
 */
async function checkNetworkConnectivity(): Promise<boolean> {
  try {
    // Try to reach a reliable endpoint with a short timeout
    const response = await fetchWithTimeout('https://www.google.com/generate_204', {
      method: 'HEAD'
    }, 5000);
    return response.ok || response.status === 204;
  } catch {
    // If Google fails, try GitHub as backup
    try {
      const response = await fetchWithTimeout('https://api.github.com', {
        method: 'HEAD'
      }, 5000);
      return response.ok;
    } catch {
      return false;
    }
  }
}

/**
 * Helper function to retry an operation with exponential backoff
 */
async function retryWithBackoff<T>(
  operation: () => Promise<T>,
  maxRetries: number = 3,
  initialDelay: number = 2000
): Promise<T | null> {
  let lastError: any;
  
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;
      
      // Don't retry on the last attempt
      if (attempt < maxRetries - 1) {
        // Use AUTH_RETRY_DELAYS array if available for auth operations
        const delay = (maxRetries === MAX_AUTH_RETRY_ATTEMPTS && AUTH_RETRY_DELAYS[attempt]) 
          ? AUTH_RETRY_DELAYS[attempt] 
          : initialDelay * Math.pow(2, attempt);
        console.log(`[FROLIC] Retry attempt ${attempt + 1}/${maxRetries} after ${delay}ms`);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }
  
  console.log(`[FROLIC] All ${maxRetries} retry attempts failed:`, lastError?.message);
  return null;
}

/**
 * Queue a digest for offline processing when network/auth issues occur
 */
function queueDigestForOfflineProcessing(sessionId: string, digest: any): void {
  const queueEntry = {
    sessionId,
    digest,
    timestamp: Date.now()
  };
  
  // Add to queue
  offlineDigestQueue.push(queueEntry);
  
  // Limit queue size to prevent memory issues
  if (offlineDigestQueue.length > MAX_OFFLINE_DIGESTS) {
    offlineDigestQueue.shift(); // Remove oldest entry
  }
  
  console.log(`[FROLIC] Queued digest for offline processing (queue size: ${offlineDigestQueue.length})`);
}

/**
 * Process offline digest queue when authentication is restored
 */
async function processOfflineDigestQueue(context: vscode.ExtensionContext): Promise<void> {
  if (offlineDigestQueue.length === 0) {
    return;
  }
  
  console.log(`[FROLIC] Processing offline digest queue (${offlineDigestQueue.length} items)`);
  
  let processed = 0;
  const startTime = Date.now();
  
  // Process queue while we have items and valid authentication
  while (offlineDigestQueue.length > 0) {
    const isAuthenticated = await getValidAccessToken(context);
    if (!isAuthenticated) {
      console.log('[FROLIC] Lost authentication during offline queue processing');
      break;
    }
    
    const queueEntry = offlineDigestQueue.shift()!;
    
    try {
      // Try to send the queued digest
      await sendDigestToBackend(queueEntry.sessionId, queueEntry.digest, context);
      processed++;
      
      // Small delay to avoid overwhelming the server
      if (offlineDigestQueue.length > 0) {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
      
    } catch (error: any) {
      // If we get auth errors, re-queue and stop processing
      if (error.message === 'AUTH_TOKEN_EXPIRED' || error.message === 'NO_AUTH_TOKEN') {
        offlineDigestQueue.unshift(queueEntry); // Put it back at the front
        console.log('[FROLIC] Auth error during offline queue processing, stopping');
        break;
      }
      
      // For other errors, skip this item and continue
      console.log(`[FROLIC] Skipping failed offline digest: ${error.message}`);
    }
  }
  
  const duration = Date.now() - startTime;
  console.log(`[FROLIC] Offline queue processing complete: ${processed} processed in ${duration}ms`);
  
  // Update status bar if queue is now empty
  if (offlineDigestQueue.length === 0) {
    vscode.window.setStatusBarMessage('$(cloud) Frolic: All offline data synced', 5000);
  }
}

/**
 * Perform token refresh with race condition protection
 */
async function performTokenRefresh(context: vscode.ExtensionContext, refreshToken: string): Promise<string | null> {
  // If already refreshing, wait for the existing refresh to complete
  if (isRefreshing && refreshPromise) {
    console.log('[FROLIC] Token refresh already in progress, waiting for completion');
    return await refreshPromise;
  }
  
  // Start new refresh with retry logic
  console.log('[FROLIC] Starting new token refresh');
  isRefreshing = true;
  
  // Create the refresh promise with improved error handling
  refreshPromise = (async (): Promise<string | null> => {
    try {
      const result = await retryWithBackoff(
        () => refreshAccessToken(context, refreshToken),
        MAX_AUTH_RETRY_ATTEMPTS, // Use increased retry attempts
        AUTH_RETRY_DELAYS[0] // Use new delay array
      );
      
      // If all retries failed, check network before clearing tokens
      if (!result) {
        const hasNetwork = await checkNetworkConnectivity();
        
        if (!hasNetwork) {
          console.log('[FROLIC] Token refresh failed but no network connectivity detected - keeping tokens');
          // Don't clear tokens if we're offline
        } else {
          const accessToken = await context.secrets.get('frolic.accessToken');
          if (accessToken) {
            console.log('[FROLIC] Token refresh failed after retries with network available, clearing all tokens');
            await context.secrets.delete('frolic.accessToken');
            await context.secrets.delete('frolic.refreshToken');
            updateStatusBar('unauthenticated');
          }
        }
      }
      
      return result;
    } finally {
      // Clear refresh state only after the entire operation is complete
      isRefreshing = false;
      refreshPromise = null;
    }
  })();
  
  return await refreshPromise;
}

/**
 * Clear all authentication tokens and reset auth state
 */
async function clearAllAuthTokens(context: vscode.ExtensionContext): Promise<void> {
  // Clear API key (new auth method)
  await context.secrets.delete('frolic.apiKey');
  
  // Clear OAuth tokens (legacy)
  await context.secrets.delete('frolic.accessToken');
  await context.secrets.delete('frolic.refreshToken');
  await context.secrets.delete('frolic.codeVerifier');
  await context.secrets.delete('frolic.state');
  
  // Clear any existing refresh promise
  refreshPromise = null;
  
  // Stop background token refresh when clearing tokens
  stopBackgroundTokenRefresh();
  
  // Clear stored expiration time
  tokenExpiresAt = null;
  await context.globalState.update('frolic.tokenExpiresAt', undefined);
}

/**
 * Start background token refresh timer
 */
function startBackgroundTokenRefresh(context: vscode.ExtensionContext): void {
  // Clear any existing timer
  stopBackgroundTokenRefresh();
  
  console.log('[FROLIC] Starting background token refresh timer');
  
  // Set up periodic check
  backgroundTokenRefreshTimer = setInterval(async () => {
    try {
      const accessToken = await context.secrets.get('frolic.accessToken');
      const refreshToken = await context.secrets.get('frolic.refreshToken');
      
      if (!accessToken || !refreshToken) {
        console.log('[FROLIC] Background refresh: no tokens available');
        stopBackgroundTokenRefresh();
        return;
      }
      
      // Check if token is expired or about to expire
      const now = Math.floor(Date.now() / 1000);
      let shouldRefresh = false;
      
      // First check our stored expiration time
      if (tokenExpiresAt) {
        const timeUntilExpiry = tokenExpiresAt - now;
        if (timeUntilExpiry < TOKEN_REFRESH_BUFFER) {
          console.log(`[FROLIC] Background refresh: token expiring in ${timeUntilExpiry}s`);
          shouldRefresh = true;
        }
      }
      
      // Also check by decoding the token
      if (!shouldRefresh && isTokenExpired(accessToken)) {
        console.log('[FROLIC] Background refresh: token is expired');
        shouldRefresh = true;
      }
      
      // Perform health check periodically
      if (!shouldRefresh && (now - lastHealthCheck) > HEALTH_CHECK_INTERVAL / 1000) {
        const isHealthy = await performHealthCheck(context, accessToken);
        lastHealthCheck = now;
        
        if (!isHealthy) {
          console.log('[FROLIC] Background refresh: health check failed, refreshing token');
          shouldRefresh = true;
        }
      }
      
      if (shouldRefresh) {
        console.log('[FROLIC] Background refresh: refreshing token...');
        await performTokenRefresh(context, refreshToken);
      }
    } catch (err: any) {
      console.error('[FROLIC] Background token refresh error:', err.message);
    }
  }, TOKEN_REFRESH_CHECK_INTERVAL);
}

/**
 * Stop background token refresh timer
 */
function stopBackgroundTokenRefresh(): void {
  if (backgroundTokenRefreshTimer) {
    clearInterval(backgroundTokenRefreshTimer);
    backgroundTokenRefreshTimer = null;
    console.log('[FROLIC] Stopped background token refresh timer');
  }
}

/**
 * Perform a lightweight health check to verify token validity
 */
async function performHealthCheck(context: vscode.ExtensionContext, accessToken: string): Promise<boolean> {
  try {
    const apiBaseUrl = getApiBaseUrl();
    const response = await fetchWithTimeout(`${apiBaseUrl}/api/auth/vscode/health`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'User-Agent': 'VSCode-Frolic-Extension/1.1.1'
      }
    }, 5000); // 5 second timeout for health check
    
    if (!response.ok) {
      console.log(`[FROLIC] Health check failed: ${response.status}`);
      return false;
    }
    
    const data = await response.json();
    return data.authenticated === true;
  } catch (err: any) {
    console.log('[FROLIC] Health check error:', err.message);
    return false; // Assume unhealthy on error
  }
}

/**
 * Get or generate a unique device ID for this VS Code installation
 */
async function getDeviceId(context: vscode.ExtensionContext): Promise<string> {
  // Check if we already have a device ID stored
  let storedDeviceId = await context.globalState.get<string>('frolic.deviceId');
  
  if (!storedDeviceId) {
    // Generate a new device ID based on machine ID and VS Code session
    const machineId = vscode.env.machineId;
    const sessionId = vscode.env.sessionId;
    
    // Create a hash of machine ID + a random component for uniqueness
    const uniqueString = `${machineId}-${crypto.randomUUID()}`;
    storedDeviceId = crypto.createHash('sha256').update(uniqueString).digest('hex').substring(0, 32);
    
    // Store it for future use
    await context.globalState.update('frolic.deviceId', storedDeviceId);
    console.log('[FROLIC] Generated new device ID:', storedDeviceId);
  }
  
  deviceId = storedDeviceId;
  return storedDeviceId;
}

/**
 * Register this device with the backend
 */
async function registerDevice(context: vscode.ExtensionContext, accessToken: string): Promise<boolean> {
  try {
    const apiBaseUrl = getApiBaseUrl();
    const deviceId = await getDeviceId(context);
    const deviceName = `${vscode.env.appHost} - ${vscode.env.appName}`;
    
    const response = await fetchWithTimeout(`${apiBaseUrl}/api/auth/vscode/device/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
      },
      body: JSON.stringify({
        deviceId: deviceId,
        deviceName: deviceName,
        vscodeVersion: vscode.version,
        platform: process.platform
      })
    }, 10000);
    
    if (response.ok) {
      isDeviceRegistered = true;
      console.log('[FROLIC] Device registered successfully');
      return true;
    } else {
      console.error('[FROLIC] Failed to register device:', response.status);
      return false;
    }
  } catch (err: any) {
    console.error('[FROLIC] Error registering device:', err.message);
    return false;
  }
}

/**
 * Check if token is expired beyond the grace period
 */
async function isTokenExpiredBeyondGracePeriod(context: vscode.ExtensionContext): Promise<boolean> {
  try {
    const accessToken = await context.secrets.get('frolic.accessToken');
    if (!accessToken) return true;
    
    const parts = accessToken.split('.');
    if (parts.length !== 3) return true;
    
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    const now = Math.floor(Date.now() / 1000);
    
    if (!payload.exp) return false; // No expiration
    
    // Check if token expired more than grace period days ago
    const gracePeriodSeconds = TOKEN_GRACE_PERIOD_DAYS * 24 * 60 * 60;
    const expiredForSeconds = now - payload.exp;
    
    return expiredForSeconds > gracePeriodSeconds;
  } catch (err) {
    console.error('[FROLIC] Error checking token grace period:', err);
    return true;
  }
}

/**
 * Check if a JWT token is expired (without verifying signature)
 */
function isTokenExpired(token: string): boolean {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return true;
    }
    
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    const now = Math.floor(Date.now() / 1000);
    
    if (!payload.exp) {
      return false; // No expiration claim means token doesn't expire
    }
    
    // Return true ONLY if actually expired
    return payload.exp < now;
  } catch (err) {
    return true; // Assume expired if we can't parse
  }
}

/**
 * Get token expiration time for debugging
 */
function getTokenExpirationTime(token: string): string {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return 'Invalid token format';
    
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    if (!payload.exp) return 'No expiration time';
    
    const expDate = new Date(payload.exp * 1000);
    const now = new Date();
    const diffMinutes = Math.round((expDate.getTime() - now.getTime()) / 1000 / 60);
    
    return `${expDate.toISOString()} (${diffMinutes > 0 ? `${diffMinutes}m remaining` : `expired ${Math.abs(diffMinutes)}m ago`})`;
  } catch (err) {
    return 'Could not parse token';
  }
}

/**
 * Check if token should be proactively refreshed (when 50% of lifetime remains)
 */
function shouldProactivelyRefreshToken(token: string): boolean {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return false;
    }
    
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    const now = Math.floor(Date.now() / 1000);
    
    if (!payload.exp) {
      return false; // No expiration claim means token doesn't expire
    }
    
    // Get issued at time (iat) to calculate total lifetime
    const issuedAt = payload.iat || now;
    const totalLifetime = payload.exp - issuedAt;
    const timeElapsed = now - issuedAt;
    const timeUntilExpiry = payload.exp - now;
    
    // Refresh when 50% of token lifetime has passed, or within 10 minutes of expiry (whichever is more aggressive)
    const halfLifetimePassed = timeElapsed >= (totalLifetime / 2);
    const withinTenMinutes = timeUntilExpiry <= 600;
    
    // Only refresh if token is not yet expired
    return (halfLifetimePassed || withinTenMinutes) && timeUntilExpiry > 0;
  } catch (err) {
    return false;
  }
}

/**
 * 🔄 ENHANCED: Background token refresh to prevent expiration
 */
async function performBackgroundTokenRefresh(context: vscode.ExtensionContext): Promise<void> {
  try {
    const accessToken = await context.secrets.get('frolic.accessToken');
    const refreshToken = await context.secrets.get('frolic.refreshToken');
    const shouldRefreshProactively = accessToken ? shouldProactivelyRefreshToken(accessToken) : false;
    
    if (!accessToken || !refreshToken) {
      return;
    }
    
    if (isTokenExpired(accessToken)) {
      console.log('[FROLIC] Background refresh: token expired, refreshing...');
      await performTokenRefresh(context, refreshToken);
    } else if (shouldRefreshProactively) {
      console.log('[FROLIC] Background refresh: proactive refresh triggered');
      await performTokenRefresh(context, refreshToken);
    }
  } catch (err: any) {
    // Log errors but don't show to user
    console.error('[FROLIC] Background token refresh error:', err.message);
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
        'User-Agent': 'VSCode-Frolic-Extension/1.1.1'
      },
      body: JSON.stringify({ refresh_token: refreshToken })
    }, 15000); // 15 second timeout for refresh
    
    if (!response.ok) {
      const errorText = await response.text();
      console.log(`[FROLIC] Token refresh failed: ${response.status} ${errorText}`);
      
      if (response.status === 401 || response.status === 403) {
        // Don't immediately clear tokens - let retry logic handle it
        throw new Error(`Auth failed: ${response.status} ${errorText}`);
      }
      return null;
    }
    
    const data = await response.json();
    console.log('[FROLIC] Refresh response keys:', Object.keys(data));
    const newAccessToken = data.accessToken || data.access_token;
    const newRefreshToken = data.refresh_token; // Some systems rotate refresh tokens
    
    if (!newAccessToken) {
      console.log('[FROLIC] No access token in refresh response');
      console.log('[FROLIC] Response data:', data);
      return null;
    }
    
    console.log(`[FROLIC] Got new access token: ${newAccessToken.substring(0, 30)}...`);
    if (newRefreshToken) {
      console.log('[FROLIC] Got new refresh token (rotated)');
    } else {
      console.log('[FROLIC] No new refresh token (not rotated)');
    }
    
    // Validate the new token before storing it
    if (isTokenExpired(newAccessToken)) {
      console.log('[FROLIC] Refreshed token is already expired! Server issue?');
      await context.secrets.delete('frolic.accessToken');
      await context.secrets.delete('frolic.refreshToken');
      updateStatusBar('unauthenticated');
      return null;
    }
    
    // Store the new tokens
    await context.secrets.store('frolic.accessToken', newAccessToken);
    if (newRefreshToken) {
      await context.secrets.store('frolic.refreshToken', newRefreshToken);
    }
    
    // Store token expiration time if provided
    if (data.expires_at) {
      tokenExpiresAt = Number(data.expires_at);
      await context.globalState.update('frolic.tokenExpiresAt', tokenExpiresAt);
      console.log(`[FROLIC] Token expires at: ${new Date(tokenExpiresAt * 1000).toISOString()}`);
    } else if (data.expires_in) {
      // Calculate expiration from expires_in
      const now = Math.floor(Date.now() / 1000);
      tokenExpiresAt = now + Number(data.expires_in);
      await context.globalState.update('frolic.tokenExpiresAt', tokenExpiresAt);
      console.log(`[FROLIC] Token expires in ${data.expires_in}s, at: ${new Date(tokenExpiresAt * 1000).toISOString()}`);
    }
    
    console.log('[FROLIC] Access token refreshed and validated successfully');
    updateStatusBar('authenticated');
    
    // 🔄 ENHANCED: Start background token refresh after successful refresh
    startBackgroundTokenRefresh(context);
    
    // Process any queued offline digests after successful authentication
    if (offlineDigestQueue.length > 0) {
      console.log('[FROLIC] Processing queued offline digests after token refresh');
      processOfflineDigestQueue(context).catch(error => {
        console.log('[FROLIC] Error processing offline queue:', error.message);
      });
    }
    
    return newAccessToken;
    
  } catch (err: any) {
    console.log('[FROLIC] Token refresh error:', err.message);
    return null;
  }
}

// --- Digest analyzer logic (from scripts/analyzeLogs.ts) ---

/**
 * 🔄 PHASE 2.1: Enhanced AI Collaboration Pattern Detection
 * Analyzes code changes to identify AI collaboration patterns and learning signals
 */
function detectAICollaborationPatterns(changeText: string, change: any): any {
  const signals = {
    // AI Usage Patterns
    isLikelyAI: change.likelyAI || false,
    aiConfidence: 0,
    aiPatterns: [] as string[],
    
    // Learning Collaboration Patterns
    learningSignals: [] as string[],
    complexityLevel: 'unknown' as 'simple' | 'moderate' | 'complex' | 'advanced' | 'unknown',
    
    // Code Quality Indicators
    codeQualitySignals: [] as string[],
    
    // Problem-Solving Patterns
    problemSolvingSignals: [] as string[]
  };

  // Enhanced AI detection patterns
  const aiPatterns = {
    // Large, complete code blocks (typical AI generation)
    largeInsertion: change.textLength > 100 && change.rangeLength === 0,
    
    // Complete function/component patterns
    completeFunction: /^(function|const|class|export|async function|const \w+ = \(|const \w+ = async)/m.test(changeText),
    
    // Multi-line structured code
    structuredCode: changeText.split('\n').length > 5 && /^[\s]*[{}();][\s]*$/m.test(changeText),
    
    // Import statement blocks
    importBlock: /^import\s+.*?from\s+['"`][^'"`]+['"`];?$/m.test(changeText) && changeText.split('\n').length > 2,
    
    // Complete JSX/HTML structures
    completeJSX: /<[A-Z][a-zA-Z0-9]*[^>]*>[\s\S]*<\/[A-Z][a-zA-Z0-9]*>/.test(changeText),
    
    // Configuration/boilerplate patterns
    configPattern: /(module\.exports|export default|\.config\.|\.json|package\.json)/.test(changeText)
  };

  // Calculate AI confidence score
  let aiScore = 0;
  if (aiPatterns.largeInsertion) aiScore += 30;
  if (aiPatterns.completeFunction) aiScore += 25;
  if (aiPatterns.structuredCode) aiScore += 20;
  if (aiPatterns.importBlock) aiScore += 15;
  if (aiPatterns.completeJSX) aiScore += 20;
  if (aiPatterns.configPattern) aiScore += 10;
  if (change.likelyAI) aiScore += 40; // Existing detection

  signals.aiConfidence = Math.min(aiScore, 100);
  signals.isLikelyAI = signals.aiConfidence > 50;

  // Identify specific AI patterns
  if (aiPatterns.largeInsertion) signals.aiPatterns.push('large_code_insertion');
  if (aiPatterns.completeFunction) signals.aiPatterns.push('complete_function_generation');
  if (aiPatterns.structuredCode) signals.aiPatterns.push('structured_code_block');
  if (aiPatterns.importBlock) signals.aiPatterns.push('import_statement_block');
  if (aiPatterns.completeJSX) signals.aiPatterns.push('complete_component_structure');
  if (aiPatterns.configPattern) signals.aiPatterns.push('configuration_boilerplate');

  // Learning collaboration signals
  const learningPatterns = {
    // Experimental/learning code
    hasComments: /\/\/|\/\*|\*\/|#/.test(changeText),
    hasConsoleLog: /console\.(log|warn|error|debug)/.test(changeText),
    hasTodoComments: /TODO|FIXME|NOTE|HACK/i.test(changeText),
    
    // Error handling patterns (learning to handle edge cases)
    hasErrorHandling: /(try|catch|throw|Error|exception)/i.test(changeText),
    
    // Testing patterns (learning to test)
    hasTestCode: /(test|spec|describe|it|expect|assert)/i.test(changeText),
    
    // Documentation patterns (learning to document)
    hasDocumentation: /\/\*\*|@param|@returns|@example/i.test(changeText)
  };

  if (learningPatterns.hasComments) signals.learningSignals.push('code_documentation');
  if (learningPatterns.hasConsoleLog) signals.learningSignals.push('debugging_exploration');
  if (learningPatterns.hasTodoComments) signals.learningSignals.push('planning_annotations');
  if (learningPatterns.hasErrorHandling) signals.learningSignals.push('error_handling_practice');
  if (learningPatterns.hasTestCode) signals.learningSignals.push('testing_implementation');
  if (learningPatterns.hasDocumentation) signals.learningSignals.push('documentation_writing');

  // Complexity assessment
  const complexityIndicators = {
    lineCount: changeText.split('\n').length,
    functionCount: (changeText.match(/function|=>/g) || []).length,
    conditionalCount: (changeText.match(/if|else|switch|case|\?|&&|\|\|/g) || []).length,
    loopCount: (changeText.match(/for|while|forEach|map|filter|reduce/g) || []).length,
    asyncCount: (changeText.match(/async|await|Promise|then|catch/g) || []).length
  };

  let complexityScore = 0;
  complexityScore += Math.min(complexityIndicators.lineCount / 5, 10);
  complexityScore += complexityIndicators.functionCount * 5;
  complexityScore += complexityIndicators.conditionalCount * 3;
  complexityScore += complexityIndicators.loopCount * 4;
  complexityScore += complexityIndicators.asyncCount * 6;

  if (complexityScore < 5) signals.complexityLevel = 'simple';
  else if (complexityScore < 15) signals.complexityLevel = 'moderate';
  else if (complexityScore < 30) signals.complexityLevel = 'complex';
  else signals.complexityLevel = 'advanced';

  // Code quality signals
  const qualityPatterns = {
    hasTypeAnnotations: /(: string|: number|: boolean|: \w+\[\]|interface|type)/.test(changeText),
    hasProperNaming: !/\b(temp|tmp|foo|bar|test123|asdf)\b/i.test(changeText),
    hasModularStructure: /(export|import|module)/.test(changeText),
    hasErrorBoundaries: /(try|catch|finally|throw)/.test(changeText)
  };

  if (qualityPatterns.hasTypeAnnotations) signals.codeQualitySignals.push('type_safety');
  if (qualityPatterns.hasProperNaming) signals.codeQualitySignals.push('good_naming_conventions');
  if (qualityPatterns.hasModularStructure) signals.codeQualitySignals.push('modular_architecture');
  if (qualityPatterns.hasErrorBoundaries) signals.codeQualitySignals.push('error_handling');

  // Problem-solving patterns
  const problemSolvingPatterns = {
    hasRefactoring: change.rangeLength > 0 && change.textLength > change.rangeLength,
    hasDebugging: /console\.(log|warn|error)|debugger|\.log\(/.test(changeText),
    hasOptimization: /(useMemo|useCallback|memo|lazy|React\.lazy)/.test(changeText),
    hasAPIIntegration: /(fetch|axios|api|endpoint|request|response)/.test(changeText)
  };

  if (problemSolvingPatterns.hasRefactoring) signals.problemSolvingSignals.push('code_refactoring');
  if (problemSolvingPatterns.hasDebugging) signals.problemSolvingSignals.push('debugging_session');
  if (problemSolvingPatterns.hasOptimization) signals.problemSolvingSignals.push('performance_optimization');
  if (problemSolvingPatterns.hasAPIIntegration) signals.problemSolvingSignals.push('api_integration');

  return signals;
}

/**
 * Enhanced Code Capture: Importance Scoring System
 * Determines how important a code change is for LLM context
 */
interface ImportanceFactors {
  size: number;
  pattern: number;
  context: number;
  editPattern: number;
  aiSignal: number;
}

function calculateImportanceScore(
  change: any,
  changeText: string,
  context: {
    isTestFile: boolean;
    isConfigFile: boolean;
    isFirstEditInSession: boolean;
    editFrequency: number;
    hasMultipleRevisions: boolean;
    hasRevert: boolean;
    rapidEdits: number;
  }
): { score: number; factors: ImportanceFactors } {
  const factors: ImportanceFactors = {
    size: 0,
    pattern: 0,
    context: 0,
    editPattern: 0,
    aiSignal: 0
  };
  
  // Size scoring (0-25 points)
  if (change.textLength > 200) factors.size = 25;
  else if (change.textLength > 100) factors.size = 20;
  else if (change.textLength > 50) factors.size = 15;
  else if (change.textLength > 20) factors.size = 10;
  
  // Pattern scoring (0-30 points)
  const importantPatterns = [
    { regex: /^(export\s+)?(default\s+)?(class|interface|type|enum)\s+\w+/m, points: 30 },
    { regex: /^(export\s+)?(async\s+)?function\s+\w+/m, points: 28 },
    { regex: /^(export\s+)?const\s+[A-Z]\w+\s*[:=]/m, points: 26 },
    { regex: /\.(get|post|put|delete|patch)\s*\(/, points: 25 },
    { regex: /^(describe|it|test)\s*\(/m, points: 24 },
    { regex: /try\s*{|catch\s*\(|\.catch\(/, points: 22 },
    { regex: /import\s+.*from|export\s+/, points: 15 }
  ];
  
  for (const { regex, points } of importantPatterns) {
    if (regex.test(changeText)) {
      factors.pattern = Math.max(factors.pattern, points);
    }
  }
  
  // Context scoring (0-20 points)
  if (context.isTestFile) factors.context += 10;
  if (context.isConfigFile) factors.context += 10;
  if (context.isFirstEditInSession) factors.context += 5;
  if (context.editFrequency > 0.3) factors.context += 5;
  
  // Edit pattern scoring (0-15 points)
  if (context.hasMultipleRevisions) factors.editPattern = 15;
  else if (context.hasRevert) factors.editPattern = 10;
  else if (context.rapidEdits > 3) factors.editPattern = 5;
  
  // AI signal scoring (0-10 points)
  if (change.aiCollaborationSignals?.isLikelyAI || change.likelyAI) {
    factors.aiSignal = 10;
  }
  
  const totalScore = Object.values(factors).reduce((sum, val) => sum + val, 0);
  
  return { score: totalScore, factors };
}

/**
 * Fetch API key from backend after OAuth authentication
 */
async function fetchApiKeyAfterOAuth(context: vscode.ExtensionContext): Promise<string | null> {
  try {
    const accessToken = await context.secrets.get('frolic.accessToken');
    if (!accessToken) {
      console.log('[FROLIC] No access token available to fetch API key');
      return null;
    }
    
    const apiBaseUrl = getApiBaseUrl();
    const response = await fetchWithTimeout(`${apiBaseUrl}/api/user/api-key`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
        'User-Agent': 'VSCode-Frolic-Extension/1.2.6-rc2'
      }
    }, 10000);
    
    if (response.ok) {
      const data = await response.json();
      if (data.api_key) {
        console.log('[FROLIC] Successfully fetched API key from backend');
        return data.api_key;
      }
    }
    
    console.log('[FROLIC] Failed to fetch API key:', response.status);
    return null;
  } catch (error) {
    console.log('[FROLIC] Error fetching API key:', error);
    return null;
  }
}

/**
 * Enhanced Code Capture: Intelligent Code Extraction
 * Extracts meaningful, complete code blocks instead of arbitrary truncation
 */
function extractMeaningfulCode(changeText: string, maxLength: number): string {
  // Try to find complete functions
  const functionRegex = /((?:export\s+)?(?:async\s+)?function\s+\w+\s*\([^)]*\)\s*(?::\s*\w+\s*)?\s*\{[\s\S]*?\n\})/g;
  const functions = changeText.match(functionRegex);
  if (functions) {
    for (const func of functions) {
      if (func.length <= maxLength) return func;
    }
  }
  
  // Try to find complete classes
  const classRegex = /((?:export\s+)?(?:abstract\s+)?class\s+\w+(?:\s+extends\s+\w+)?(?:\s+implements\s+\w+)?\s*\{[\s\S]*?\n\})/g;
  const classes = changeText.match(classRegex);
  if (classes) {
    for (const cls of classes) {
      if (cls.length <= maxLength) return cls;
    }
  }
  
  // Try to find complete React components
  const componentRegex = /((?:export\s+)?(?:const|function)\s+[A-Z]\w+\s*[:=]\s*(?:\([^)]*\)\s*=>|\([^)]*\):\s*\w+\s*=>|function\s*\([^)]*\))\s*(?:\{[\s\S]*?\n\}|\([\s\S]*?\n\)))/g;
  const components = changeText.match(componentRegex);
  if (components) {
    for (const comp of components) {
      if (comp.length <= maxLength) return comp;
    }
  }
  
  // Skip past comments/headers to actual code
  const codeStart = changeText.search(/^(?!\/\/|\/\*|\s*\*|#|\s*$)/m);
  if (codeStart > 0 && codeStart < 200) {
    return changeText.substring(codeStart, codeStart + maxLength);
  }
  
  // Default: return from start
  return changeText.substring(0, maxLength);
}

/**
 * Categorizes the type of code change for better understanding
 */
function categorizeChange(changeText: string): string {
  if (/import\s+.*from/.test(changeText)) return 'import';
  if (/export\s+(?:default|const|function|class)/.test(changeText)) return 'export';
  if (/interface\s+\w+|type\s+\w+\s*=/.test(changeText)) return 'type_definition';
  if (/class\s+\w+/.test(changeText)) return 'class_definition';
  if (/(?:function\s+\w+|const\s+\w+\s*=\s*(?:async\s*)?\()/.test(changeText)) return 'function_definition';
  if (/\.(test|spec|describe|it|expect)\s*\(/.test(changeText)) return 'test';
  if (/return\s+|if\s*\(|for\s*\(|while\s*\(/.test(changeText)) return 'implementation';
  return 'other';
}

/**
 * Enhanced Code Capture: Semantic Entity Extraction
 * Extracts function names, classes, components, and other entities from code
 */
interface ExtractedEntities {
  functions: string[];
  classes: string[];
  components: string[];
  imports: string[];
  exports: string[];
}

function extractSemanticEntities(changeText: string): ExtractedEntities {
  const entities: ExtractedEntities = {
    functions: [],
    classes: [],
    components: [],
    imports: [],
    exports: []
  };
  
  // Extract function names
  const functionMatches = changeText.matchAll(/(?:(?:export\s+)?(?:async\s+)?function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*(?:=>|{))/g);
  for (const match of functionMatches) {
    const name = match[1] || match[2];
    if (name && !entities.functions.includes(name)) {
      entities.functions.push(name);
    }
  }
  
  // Extract class names
  const classMatches = changeText.matchAll(/class\s+(\w+)/g);
  for (const match of classMatches) {
    if (!entities.classes.includes(match[1])) {
      entities.classes.push(match[1]);
    }
  }
  
  // Extract React components (PascalCase functions/consts)
  const componentMatches = changeText.matchAll(/(?:export\s+)?(?:const|function)\s+([A-Z]\w+)\s*[:=]/g);
  for (const match of componentMatches) {
    if (!entities.components.includes(match[1])) {
      entities.components.push(match[1]);
    }
  }
  
  // Extract imports (just the package/module names)
  const importMatches = changeText.matchAll(/import\s+(?:.*?)\s+from\s+['"`]([^'"`]+)['"`]/g);
  for (const match of importMatches) {
    const pkg = match[1].split('/')[0]; // Get package name
    if (!entities.imports.includes(pkg)) {
      entities.imports.push(pkg);
    }
  }
  
  // Extract exports
  const exportMatches = changeText.matchAll(/export\s+(?:default\s+)?(?:const|function|class)?\s*(\w+)/g);
  for (const match of exportMatches) {
    if (match[1] && !entities.exports.includes(match[1])) {
      entities.exports.push(match[1]);
    }
  }
  
  return entities;
}

/**
 * Detects code patterns for better understanding of what was implemented
 */
function detectCodePatterns(changeText: string): any {
  return {
    hasErrorHandling: /try\s*{|catch\s*\(|\.catch\(|throw\s+/.test(changeText),
    hasTests: /\.(test|spec)\(|describe\(|it\(|expect\(/.test(changeText),
    hasAsync: /async|await|Promise|\.then\(/.test(changeText),
    hasStateManagement: /useState|useReducer|setState|dispatch/.test(changeText),
    hasTypeDefinitions: /interface\s+|type\s+\w+\s*=|:\s*\w+(?:\[\])?(?:\s*[|&])?\s*[;,=]/.test(changeText)
  };
}

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
    externalEdits?: number; // Edits made outside VS Code (e.g., Claude)
    externalLinesAdded?: number; // Lines added by external tools
  }> = {};

  // Session timing
  const sessionStart = logs.length > 0 ? new Date(logs[0].timestamp) : new Date();
  const sessionEnd = logs.length > 0 ? new Date(logs[logs.length - 1].timestamp) : new Date();
  const sessionDuration = (sessionEnd.getTime() - sessionStart.getTime()) / 1000 / 60; // minutes

  // Raw text aggregation for backend analysis
  let codeChangesText = '';
  const codeChangesSample: any[] = [];
  const importStatements: string[] = [];
  
  // Enhanced semantic tracking
  const semanticSummary = {
    entitiesCreated: {
      functions: [] as string[],
      classes: [] as string[],
      components: [] as string[],
      totalCount: 0
    },
    codingPatterns: {
      primaryLanguage: '',
      frameworksUsed: [] as string[],
      testingApproach: undefined as string | undefined,
      architectureStyle: undefined as string | undefined
    },
    sessionInsights: {
      focusArea: '',
      complexityLevel: 'moderate' as 'simple' | 'moderate' | 'complex' | 'advanced',
      refactoringRatio: 0,
      debuggingTime: 0
    }
  };
  const importantCodeSamples: any[] = [];
  const processedFiles = new Set<string>();
  const fileExtensions = new Set<string>();
  const directoryStructure: Record<string, number> = {};

  // Process each log entry - MINIMAL processing, maximum raw data
  for (let i = 0; i < logs.length; i++) {
    const entry = logs[i];
    if (entry.eventType !== 'file_edit') continue;

    const filePath = entry.relativePath;
    files.add(filePath);
    langCounts[entry.language] = (langCounts[entry.language] || 0) + 1;
    
    // Check if entry has pre-calculated totals (newer format)
    if (entry.totalLinesAdded > 0) {
      totalLinesAdded += entry.totalLinesAdded;
    }

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
        editPattern: [],
        externalEdits: 0,
        externalLinesAdded: 0
      };
    }
    fileActivity[filePath].edits++;
    fileActivity[filePath].lastEdit = entry.timestamp;
    
    // Track external edits separately
    if (entry.externalEdit || entry.saveTriggered) {
      fileActivity[filePath].externalEdits = (fileActivity[filePath].externalEdits || 0) + 1;
      fileActivity[filePath].externalLinesAdded = (fileActivity[filePath].externalLinesAdded || 0) + (entry.totalLinesAdded || 0);
    }

    // Calculate edit intervals for pattern analysis
    if (i > 0 && logs[i-1].relativePath === filePath) {
      const timeDiff = (new Date(entry.timestamp).getTime() - new Date(logs[i-1].timestamp).getTime()) / 1000;
      fileActivity[filePath].editPattern.push(timeDiff);
    }

    // Process code changes - collect raw data
    for (const change of entry.changes || []) {
      const changeText = change.changeText || ''; // Use change.changeText from the logged structure
      
      // Use pre-calculated lineCountDelta if available, otherwise calculate
      let lineCountDelta = 0;
      if (change.lineCountDelta !== undefined) {
        lineCountDelta = change.lineCountDelta;
      } else {
        // Fallback calculation: count newlines in added text
        lineCountDelta = changeText.length > 0 ? (changeText.match(/\n/g) || []).length : 0;
      }
      
      totalLinesAdded += Math.max(0, lineCountDelta); // Count net additions
      fileActivity[filePath].linesChanged += Math.max(0, lineCountDelta);
      
      if (change.likelyAI) aiInsertions++;

      // Enhanced code capture with importance scoring
      if (changeText.length > 10 && codeChangesSample.length < 100) {
        // Build change context for importance scoring
        const changeContext = {
          isTestFile: /\.(test|spec)\.(ts|js|tsx|jsx)$/.test(filePath),
          isConfigFile: /\.(config|json|env|yaml|yml)$/.test(filePath),
          isFirstEditInSession: !processedFiles.has(filePath),
          editFrequency: fileActivity[filePath]?.editPattern?.length ? 
            fileActivity[filePath].edits / ((new Date(fileActivity[filePath].lastEdit).getTime() - 
            new Date(fileActivity[filePath].firstEdit).getTime()) / 1000 / 60) : 0,
          hasMultipleRevisions: (fileActivity[filePath]?.edits || 0) > 5,
          hasRevert: change.revertCount > 0,
          rapidEdits: fileActivity[filePath]?.editPattern?.filter((t: number) => t < 5).length || 0
        };
        
        processedFiles.add(filePath);
        
        // Calculate importance score
        const importance = calculateImportanceScore(change, changeText, changeContext);
        
        // Determine truncation length based on importance
        const truncationLength = importance.score > 60 ? 2000 : 
                               importance.score > 40 ? 1500 : 
                               importance.score > 20 ? 1000 : 
                               500;
        
        // Extract meaningful code
        const extractedCode = importance.score > 40 ? 
          extractMeaningfulCode(changeText, truncationLength) : 
          changeText.substring(0, truncationLength);
        
        // Extract semantic information
        const entities = extractSemanticEntities(changeText);
        const patterns = detectCodePatterns(changeText);
        const category = categorizeChange(changeText);
        
        // Update semantic summary
        semanticSummary.entitiesCreated.functions.push(...entities.functions);
        semanticSummary.entitiesCreated.classes.push(...entities.classes);
        semanticSummary.entitiesCreated.components.push(...entities.components);
        
        // Build enhanced change object
        codeChangesSample.push({
          file: filePath,
          language: entry.language || 'unknown',
          timestamp: entry.timestamp,
          change: extractedCode,
          size: change.textLength || changeText.length,
          type: (change.textLength || changeText.length) > change.rangeLength ? 'addition' : 'modification',
          aiCollaborationSignals: detectAICollaborationPatterns(changeText, change),
          
          // NEW: Semantic metadata
          semantic: {
            modifiedEntity: entities.functions[0] || entities.classes[0] || entities.components[0],
            changeCategory: category,
            fullContext: importance.score > 60 && changeText.length < 2000 ? changeText : undefined,
            entities: entities,
            patterns: patterns
          },
          
          // NEW: Importance data
          importance: {
            score: importance.score,
            factors: importance.factors,
            isImportant: importance.score > 40
          }
        });
        
        // Collect important complete code samples
        if (importance.score > 60 && (entities.functions.length > 0 || entities.classes.length > 0)) {
          const entityName = entities.functions[0] || entities.classes[0] || 'Unknown';
          const explanation = `${category} with importance score ${importance.score}`;
          
          importantCodeSamples.push({
            file: filePath,
            entity: entityName,
            category: category,
            fullCode: changeText.substring(0, 2000),
            explanation: explanation
          });
        }
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

  // Finalize semantic summary
  semanticSummary.entitiesCreated.functions = [...new Set(semanticSummary.entitiesCreated.functions)];
  semanticSummary.entitiesCreated.classes = [...new Set(semanticSummary.entitiesCreated.classes)];
  semanticSummary.entitiesCreated.components = [...new Set(semanticSummary.entitiesCreated.components)];
  semanticSummary.entitiesCreated.totalCount = 
    semanticSummary.entitiesCreated.functions.length +
    semanticSummary.entitiesCreated.classes.length +
    semanticSummary.entitiesCreated.components.length;

  // Determine session characteristics
  const languageCounts = Object.entries(langCounts).sort((a, b) => b[1] - a[1]);
  semanticSummary.codingPatterns.primaryLanguage = languageCounts[0]?.[0] || 'unknown';

  // Detect frameworks from imports
  const frameworkDetection: Record<string, string[]> = {
    'react': ['React', 'React.js'],
    'vue': ['Vue', 'Vue.js'],
    'angular': ['Angular'],
    'next': ['Next.js'],
    'express': ['Express'],
    'fastify': ['Fastify'],
    'nestjs': ['NestJS'],
    '@testing-library': ['React Testing Library'],
    'jest': ['Jest'],
    'vitest': ['Vitest']
  };

  for (const imp of importStatements) {
    for (const [pkg, frameworks] of Object.entries(frameworkDetection)) {
      if (imp.includes(pkg)) {
        semanticSummary.codingPatterns.frameworksUsed.push(...frameworks);
      }
    }
  }
  semanticSummary.codingPatterns.frameworksUsed = [...new Set(semanticSummary.codingPatterns.frameworksUsed)];

  // Determine focus area based on files and languages
  if (topFiles.some(f => f.file.match(/\.(tsx?|jsx?)$/)) && 
      topFiles.some(f => f.file.match(/(component|page|view)/i))) {
    semanticSummary.sessionInsights.focusArea = 'Frontend Development';
  } else if (topFiles.some(f => f.file.match(/(api|server|route|controller)/i))) {
    semanticSummary.sessionInsights.focusArea = 'Backend Development';
  } else if (topFiles.some(f => f.file.match(/\.(test|spec)\./))) {
    semanticSummary.sessionInsights.focusArea = 'Testing';
  } else {
    semanticSummary.sessionInsights.focusArea = 'General Development';
  }

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
      
      // Enhanced code samples with semantic data
      codeChangesSample: codeChangesSample,
      importStatements: Array.from(new Set(importStatements)).slice(0, 20),
      
      // NEW: Semantic analysis summary
      semanticSummary: semanticSummary,
      
      // NEW: Important code samples for LLM context
      importantCodeSamples: importantCodeSamples.slice(0, 10),
    
    // 🔄 PHASE 2.2: Learning Struggle Detection Data
    struggleIndicators: {
      rapidUndoRedoCount: logs.filter(l => l.eventType === 'struggle_indicator' && l.struggleType === 'rapid_undo_redo').length,
      longPauseCount: logs.filter(l => l.eventType === 'struggle_indicator' && l.struggleType === 'long_pause').length,
      frequentSwitchingCount: logs.filter(l => l.eventType === 'struggle_indicator' && l.struggleType === 'frequent_file_switching').length,
      errorHeavySessionCount: logs.filter(l => l.eventType === 'struggle_indicator' && l.struggleType === 'error_heavy_session').length,
      totalStruggleEvents: logs.filter(l => l.eventType === 'struggle_indicator').length,
      
      // Detailed struggle patterns
      struggleDetails: logs
        .filter(l => l.eventType === 'struggle_indicator')
        .map(l => ({
          type: l.struggleType,
          timestamp: l.timestamp,
          context: l.sessionContext,
          severity: l.struggleType === 'error_heavy_session' ? 'high' : 
                   l.struggleType === 'rapid_undo_redo' ? 'medium' : 'low'
        })),
        
      // Time-based struggle analysis
      avgPauseDuration: (() => {
        const pauses = logs.filter(l => l.eventType === 'struggle_indicator' && l.struggleType === 'long_pause');
        return pauses.length > 0 ? 
          pauses.reduce((sum, p) => sum + (p.duration || 0), 0) / pauses.length : 0;
      })(),
      
      maxConsecutiveFileSwitches: (() => {
        const switches = logs.filter(l => l.eventType === 'struggle_indicator' && l.struggleType === 'frequent_file_switching');
        return switches.length > 0 ? Math.max(...switches.map(s => s.switchCount || 0)) : 0;
      })()
    },
    
    // 🔄 PHASE 2.3: Error and Debugging Tracking Data
    errorTrackingData: {
      diagnosticChangeCount: logs.filter(l => l.eventType === 'diagnostic_change').length,
      totalErrorsEncountered: logs
        .filter(l => l.eventType === 'diagnostic_change')
        .reduce((sum, l) => sum + (l.errorCount || 0), 0),
      totalWarningsEncountered: logs
        .filter(l => l.eventType === 'diagnostic_change')
        .reduce((sum, l) => sum + (l.warningCount || 0), 0),
      
      // Debugging session analysis
      debuggingSessions: logs
        .filter(l => l.eventType === 'debugging_session_end')
        .map(l => ({
          file: l.file,
          duration: l.duration,
          durationMinutes: l.durationMinutes,
          maxErrorCount: l.maxErrorCount,
          errorTypes: l.errorTypes,
          resolution: l.resolution
        })),
      
      // Error pattern analysis
      errorPatternsByType: (() => {
        const errors = logs.filter(l => l.eventType === 'diagnostic_change' && l.diagnostics);
        const patterns: Record<string, number> = {};
        
        errors.forEach(l => {
          (l.diagnostics || []).forEach((d: any) => {
            if (d.category) {
              patterns[d.category] = (patterns[d.category] || 0) + 1;
            }
          });
        });
        
        return patterns;
      })(),
      
      // Error resolution efficiency
      avgDebuggingDuration: (() => {
        const sessions = logs.filter(l => l.eventType === 'debugging_session_end');
        return sessions.length > 0 ? 
          sessions.reduce((sum, s) => sum + (s.duration || 0), 0) / sessions.length : 0;
      })(),
      
      // Most problematic files
      errorProneFiles: (() => {
        const fileErrors: Record<string, number> = {};
        
        logs.filter(l => l.eventType === 'diagnostic_change').forEach(l => {
          if (l.file && l.errorCount > 0) {
            fileErrors[l.file] = (fileErrors[l.file] || 0) + l.errorCount;
          }
        });
        
        return Object.entries(fileErrors)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 5)
          .map(([file, count]) => ({ file, errorCount: count }));
      })(),
      
      // Error progression over time
      errorProgression: logs
        .filter(l => l.eventType === 'diagnostic_change')
        .map(l => ({
          timestamp: l.timestamp,
          file: l.file,
          errorCount: l.errorCount || 0,
          warningCount: l.warningCount || 0,
          changeType: l.changeType
        }))
        .slice(-50) // Keep last 50 for analysis
    },
      
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
        'personalized_recommendations',
        // 🔄 PHASE 2.1: AI collaboration analysis
        'ai_collaboration_patterns',
        'ai_learning_progression',
        'ai_dependency_assessment',
        'human_ai_balance_analysis',
        // 🔄 PHASE 2.2: Struggle detection analysis
        'struggle_pattern_identification',
        'learning_difficulty_assessment',
        'time_to_solution_analysis',
        'cognitive_load_evaluation',
        // 🔄 PHASE 2.3: Error tracking analysis
        'error_pattern_recognition',
        'debugging_efficiency_assessment',
        'error_progression_analysis',
        'problem_solving_methodology'
      ],
      
      // Provide context, not conclusions
      sessionCharacteristics: {
        isLongSession: sessionDuration > 60,
        isIntenseSession: logs.length > 100,
        isMultiFileSession: files.size > 5,
        hasLargeChanges: totalLinesAdded > 200,
        showsAIUsage: aiInsertions > 0,
        // 🔄 PHASE 2.2: Struggle indicators
        hasStrugglePatterns: logs.some(l => l.eventType === 'struggle_indicator'),
        hasFrequentPauses: logs.filter(l => l.eventType === 'struggle_indicator' && l.struggleType === 'long_pause').length > 2,
        hasRapidEditing: logs.filter(l => l.eventType === 'struggle_indicator' && l.struggleType === 'rapid_undo_redo').length > 0,
        hasFileSwitchingPattern: logs.filter(l => l.eventType === 'struggle_indicator' && l.struggleType === 'frequent_file_switching').length > 0,
        // 🔄 PHASE 2.3: Error indicators
        hasErrorsEncountered: logs.some(l => l.eventType === 'diagnostic_change' && (l.errorCount || 0) > 0),
        hasDebuggingSessions: logs.some(l => l.eventType === 'debugging_session_end'),
        hasErrorHeavySessions: logs.some(l => l.eventType === 'struggle_indicator' && l.struggleType === 'error_heavy_session'),
        hasComplexErrorPatterns: (() => {
          const errorTypes = new Set();
          logs.filter(l => l.eventType === 'diagnostic_change' && l.diagnostics).forEach(l => {
            (l.diagnostics || []).forEach((d: any) => {
              if (d.category) errorTypes.add(d.category);
            });
          });
          return errorTypes.size > 2; // Multiple error types indicate complexity
        })()
      },

      // 🔄 PHASE 2.1: Enhanced AI collaboration context
      aiCollaborationContext: {
        // AI usage statistics
        totalAIInsertions: aiInsertions,
        aiUsagePercentage: logs.length > 0 ? Math.round((aiInsertions / logs.filter(l => l.eventType === 'file_edit').length) * 100) : 0,
        
        // AI collaboration patterns from code samples
        aiPatternsSummary: codeChangesSample.reduce((acc: any, sample: any) => {
          if (sample.aiCollaborationSignals) {
            const signals = sample.aiCollaborationSignals;
            
            // Aggregate AI patterns
            signals.aiPatterns?.forEach((pattern: string) => {
              acc.aiPatterns[pattern] = (acc.aiPatterns[pattern] || 0) + 1;
            });
            
            // Aggregate learning signals
            signals.learningSignals?.forEach((signal: string) => {
              acc.learningSignals[signal] = (acc.learningSignals[signal] || 0) + 1;
            });
            
            // Aggregate complexity levels
            if (signals.complexityLevel && signals.complexityLevel !== 'unknown') {
              acc.complexityLevels[signals.complexityLevel] = (acc.complexityLevels[signals.complexityLevel] || 0) + 1;
            }
            
            // Aggregate code quality signals
            signals.codeQualitySignals?.forEach((signal: string) => {
              acc.codeQualitySignals[signal] = (acc.codeQualitySignals[signal] || 0) + 1;
            });
            
            // Aggregate problem-solving signals
            signals.problemSolvingSignals?.forEach((signal: string) => {
              acc.problemSolvingSignals[signal] = (acc.problemSolvingSignals[signal] || 0) + 1;
            });
            
            // Track AI confidence distribution
            if (signals.aiConfidence > 0) {
              const confidenceRange = signals.aiConfidence >= 80 ? 'high' : 
                                    signals.aiConfidence >= 50 ? 'medium' : 'low';
              acc.aiConfidenceDistribution[confidenceRange] = (acc.aiConfidenceDistribution[confidenceRange] || 0) + 1;
            }
          }
          return acc;
        }, {
          aiPatterns: {},
          learningSignals: {},
          complexityLevels: {},
          codeQualitySignals: {},
          problemSolvingSignals: {},
          aiConfidenceDistribution: {}
        }),
        
        // Session-level AI collaboration insights
        aiCollaborationInsights: {
          hasHighConfidenceAI: codeChangesSample.some((sample: any) => 
            sample.aiCollaborationSignals?.aiConfidence > 80
          ),
          hasLearningSignals: codeChangesSample.some((sample: any) => 
            sample.aiCollaborationSignals?.learningSignals?.length > 0
          ),
          hasComplexAICode: codeChangesSample.some((sample: any) => 
            sample.aiCollaborationSignals?.complexityLevel === 'complex' || 
            sample.aiCollaborationSignals?.complexityLevel === 'advanced'
          ),
          hasQualitySignals: codeChangesSample.some((sample: any) => 
            sample.aiCollaborationSignals?.codeQualitySignals?.length > 0
          ),
          hasProblemSolving: codeChangesSample.some((sample: any) => 
            sample.aiCollaborationSignals?.problemSolvingSignals?.length > 0
          ),
          
          // AI learning progression indicators
          aiLearningProgression: {
            isExploringNewConcepts: codeChangesSample.some((sample: any) => 
              sample.aiCollaborationSignals?.learningSignals?.includes('debugging_exploration') ||
              sample.aiCollaborationSignals?.learningSignals?.includes('planning_annotations')
            ),
            isApplyingBestPractices: codeChangesSample.some((sample: any) => 
              sample.aiCollaborationSignals?.codeQualitySignals?.includes('type_safety') ||
              sample.aiCollaborationSignals?.codeQualitySignals?.includes('error_handling')
            ),
            isRefactoringCode: codeChangesSample.some((sample: any) => 
              sample.aiCollaborationSignals?.problemSolvingSignals?.includes('code_refactoring')
            ),
            isWritingTests: codeChangesSample.some((sample: any) => 
              sample.aiCollaborationSignals?.learningSignals?.includes('testing_implementation')
            )
          }
        }
      }
    }
  };
}

// Removed all helper functions - analysis now done by backend

  export async function signInCommand(context: vscode.ExtensionContext) {
  // Show loading state
  updateStatusBar('initializing');
  
  try {
    // Generate PKCE parameters
    const state = crypto.randomUUID();
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    const apiBaseUrl = getApiBaseUrl();
    
    // Get token expiration preference
    const config = vscode.workspace.getConfiguration('frolic');
    const tokenExpiration = config.get<string>('tokenExpiration', 'long');
    
    // Store PKCE parameters securely
    await context.secrets.store('frolic.codeVerifier', codeVerifier);
    await context.secrets.store('frolic.state', state);
    
          // Build auth URL - always request API key for seamless experience
      const authUrl = `${apiBaseUrl}/api/auth/vscode/start?state=${state}&code_challenge=${codeChallenge}&token_type=${tokenExpiration}&source=vscode`;
      
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
      
      // Prompt for API key
      const code = await vscode.window.showInputBox({
        title: 'Frolic Authentication',
        prompt: 'Paste your API key from the browser',
        placeHolder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
        ignoreFocusOut: true,
        validateInput: (value) => {
          if (!value || value.trim().length === 0) {
            return 'Please enter your API key';
          }
          if (value.trim().length < 10) {
            return 'API key seems too short';
          }
          return null;
        }
      });
      
      if (!code) {
        throw new Error('No authentication code provided');
      }
      
      // Validate API key format
      const trimmedCode = code.trim();
      const isValidApiKey = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(trimmedCode);
      
      if (!isValidApiKey) {
        throw new Error('Invalid API key format. Please copy the complete API key from the browser.');
      }
      
      // Store API key directly
      progress.report({ message: "Storing API key..." });
      console.log('[FROLIC] Storing API key for seamless authentication');
      await context.secrets.store('frolic.apiKey', trimmedCode);
      
      // Clean up any old PKCE parameters
      await context.secrets.delete('frolic.codeVerifier');
      await context.secrets.delete('frolic.state');
      await context.secrets.delete('frolic.accessToken');
      await context.secrets.delete('frolic.refreshToken');
      
      return { apiKey: trimmedCode };
    });
    
    // If user cancelled or no result
    if (!progressResult) {
      updateStatusBar('unauthenticated');
      return;
    }
    
    // Success! API key is stored
    updateStatusBar('authenticated');
    vscode.window.showInformationMessage('✅ Frolic: Successfully signed in!');
    
    // Refresh activity panel to show updated auth status
    if (activityProvider) {
      activityProvider.refresh();
    }
    
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
        // Check for API key first (new auth method)
        const apiKey = await context.secrets.get('frolic.apiKey');
        if (apiKey) {
            console.log('[FROLIC] API key found, user is authenticated');
            updateStatusBar('authenticated');
            return; // No need for token refresh with API keys!
        }
        
        // Fall back to OAuth token check (legacy)
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
                setTimeout(async () => {
                    try {
                        await vscode.commands.executeCommand('workbench.action.openWalkthrough', 'frolic.frolic#frolic.welcome');
                    } catch (error) {
                        // Fallback for Cursor - show welcome message instead
                        console.log('[FROLIC] Walkthrough not available, showing welcome message');
                        vscode.commands.executeCommand('frolic.showWelcome');
                    }
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



export async function activate(context: vscode.ExtensionContext) {
    console.log('🚀 Frolic Logger is activating...');
    extensionContext = context;

    // Store context globally for activity-based digest sending
    extensionContext = context;

    // Create status bar item
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.command = 'frolic.flushLogs';
    context.subscriptions.push(statusBarItem);
    updateStatusBar('initializing');

    // 🔄 PHASE 1.1: Session Data Recovery System
    console.log('[FROLIC] 🔄 Starting session data recovery...');
    const recoveredEvents = await recoverSessionData(context);
    if (recoveredEvents > 0) {
        console.log(`[FROLIC] ✅ Successfully recovered ${recoveredEvents} events from previous session`);
    }

    // Load first digest sent state
    isFirstDigestSent = context.globalState.get('frolic.firstDigestSent', false);

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

            // Calculate line changes from contentChanges
            let totalLineChanges = 0;
            let totalTextAdded = 0;
            let isLikelyFileRewrite = false;
            
            // Detect if this is likely a file rewrite (e.g., save operation that replaces entire content)
            if (event.contentChanges.length === 1) {
                const change = event.contentChanges[0];
                // If the range covers the entire document and text is large, it's likely a rewrite
                if (change.range && 
                    change.range.start.line === 0 && 
                    change.range.start.character === 0 &&
                    change.rangeLength > 1000 && 
                    change.text.length > 1000) {
                    isLikelyFileRewrite = true;
                }
            }
            
            for (const change of event.contentChanges) {
                // Count lines in the new text
                const linesInNewText = change.text ? (change.text.match(/\n/g) || []).length : 0;
                
                // Count lines in the replaced range
                let linesInOldRange = 0;
                if (change.range && !change.range.isEmpty) {
                    // Calculate lines that were replaced
                    linesInOldRange = change.range.end.line - change.range.start.line;
                    // Only add 1 if we're not at the start of the end line
                    if (change.range.end.character > 0) {
                        linesInOldRange++;
                    }
                }
                
                // Calculate NET line change (can be negative)
                const netLineChange = linesInNewText - linesInOldRange;
                
                // For file rewrites, don't count as user-added lines
                if (!isLikelyFileRewrite) {
                    // Only count positive changes (lines added)
                    totalLineChanges += Math.max(0, netLineChange);
                }
                
                // Track total text length added
                totalTextAdded += change.text ? change.text.length : 0;
            }

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
                // Store both individual changes and calculated totals
                changes: event.contentChanges.map(change => {
                    // Calculate NET line change for this specific change
                    const linesInNewText = change.text ? (change.text.match(/\n/g) || []).length : 0;
                    let linesInOldRange = 0;
                    if (change.range && !change.range.isEmpty) {
                        linesInOldRange = change.range.end.line - change.range.start.line;
                        if (change.range.end.character > 0) {
                            linesInOldRange++;
                        }
                    }
                    const netLineChange = linesInNewText - linesInOldRange;
                    
                    return {
                        text: change.text,
                        textLength: change.text.length,
                        rangeLength: change.rangeLength,
                        // Store NET line change, not just lines in new text
                        lineCountDelta: isLikelyFileRewrite ? 0 : Math.max(0, netLineChange),
                        rangeStart: change.range ? change.range.start : null,
                        rangeEnd: change.range ? change.range.end : null
                    };
                }),
                // Add totals for easier processing in analyzeLogs
                totalLinesAdded: totalLineChanges,
                totalTextAdded: totalTextAdded,
                isFileRewrite: isLikelyFileRewrite
            });
        })
    );

    // Track file opens
    context.subscriptions.push(
        vscode.workspace.onDidOpenTextDocument((doc) => {
            const timestamp = Date.now();
            
            logEvent('file_open', {
                file: doc.fileName,
                language: doc.languageId,
                lineCount: doc.lineCount,
                isUntitled: doc.isUntitled,
                isDirty: doc.isDirty
            });
            
            // 🔄 PHASE 2.2: Track file opening for struggle detection
            if (doc.fileName && !doc.fileName.includes('.git')) {
                detectFrequentFileSwitching(doc.fileName, timestamp);
            }
            
            // Initialize baseline for opened files
            if (!doc.isUntitled && doc.fileName) {
                fileLineBaseline.set(doc.fileName, doc.lineCount);
            }
        })
    );

    // 📊 Track file saves to capture external edits (e.g., Claude)
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument((document) => {
            const filePath = document.fileName;
            const currentLines = document.lineCount;
            const previousLines = fileLineBaseline.get(filePath) || 0;
            
            // Calculate lines added (positive changes only)
            const linesAdded = Math.max(0, currentLines - previousLines);
            
            // Check if this was an external edit (document wasn't dirty before save)
            // External edits won't have the dirty flag set
            const isExternalEdit = linesAdded > 0 && !document.isDirty;
            
            if (linesAdded > 0) {
                logEvent('file_edit', {
                    file: filePath,
                    language: document.languageId,
                    lineCount: currentLines,
                    isUntitled: false,
                    isDirty: false,
                    cursorPosition: null,
                    selectionLength: 0,
                    changes: [{
                        text: '', // We don't have the actual text for external changes
                        textLength: 0,
                        rangeLength: 0,
                        lineCountDelta: linesAdded
                    }],
                    // Add tracking for external edits
                    totalLinesAdded: linesAdded,
                    totalTextAdded: 0,
                    externalEdit: isExternalEdit,
                    saveTriggered: true
                });
            }
            
            // Update baseline for next comparison
            fileLineBaseline.set(filePath, currentLines);
        })
    );

    // Show Frolic dropdown (similar to GitHub Copilot)
    const showDropdownCmd = vscode.commands.registerCommand('frolic.showDropdown', async () => {
        const accessToken = await getValidAccessToken(context);
        const isAuthenticated = !!accessToken;
        
        // Get current activity stats
        const totalEvents = LOG_BUFFER.length;
        const filesEdited = new Set(LOG_BUFFER.map(e => e.relativePath)).size;
        const bufferMemoryMB = (bufferMemoryUsage / 1024 / 1024).toFixed(1);
        const recentActivity = LOG_BUFFER.filter(e => 
            e.eventType === 'file_edit' && 
            Date.now() - e.timestamp < 5 * 60 * 1000
        ).length;
        
        const digestProgress = Math.min(100, (totalEvents / 1000) * 100);
        const digestReady = totalEvents >= 1000;
        
        // Create QuickPick items
        const items: vscode.QuickPickItem[] = [];
        
        // Header - Connection Status
        items.push({
            label: `${isAuthenticated ? 'Connected' : 'Disconnected'}`,
            description: isAuthenticated ? 'Frolic is tracking your activity' : 'Sign in to enable tracking',
            kind: vscode.QuickPickItemKind.Separator
        });
        
        // Activity metrics
        items.push({
            label: `${totalEvents} events logged`,
            description: `${filesEdited} files edited, ${recentActivity} recent edits`,
            kind: vscode.QuickPickItemKind.Default
        });
        
        items.push({
            label: `${bufferMemoryMB}MB buffer usage`,
            description: `Memory usage for event tracking`,
            kind: vscode.QuickPickItemKind.Default
        });
        
        // Digest status
        items.push({
            label: `Digest: ${totalEvents}/1000 events`,
            description: digestReady ? 'Ready to send!' : `${digestProgress.toFixed(0)}% complete`,
            kind: vscode.QuickPickItemKind.Default
        });
        
        // Separator for actions
        items.push({
            label: '',
            kind: vscode.QuickPickItemKind.Separator
        });
        
        // Actions
        if (isAuthenticated) {
            items.push({
                label: `Send Digest`,
                description: digestReady ? 'Send your activity digest now' : `Send digest with ${totalEvents} events`
            });
        }
        
        items.push({
            label: `Refresh`,
            description: 'Update activity stats'
        });
        
        if (isAuthenticated) {
            items.push({
                label: `Sign Out`,
                description: 'Sign out of Frolic'
            });
        } else {
            items.push({
                label: `Sign In`,
                description: 'Connect to Frolic'
            });
        }
        
        // Show QuickPick
        const quickPick = vscode.window.createQuickPick();
        quickPick.items = items;
        quickPick.placeholder = 'Frolic Status & Actions';
        quickPick.title = 'Frolic';
        quickPick.canSelectMany = false;
        
        // Handle selection
        quickPick.onDidAccept(async () => {
            const selection = quickPick.selectedItems[0];
            if (selection?.label) {
                if (selection.label.includes('Send Digest')) {
                    await vscode.commands.executeCommand('frolic.sendDigest');
                } else if (selection.label.includes('Sign Out')) {
                    await vscode.commands.executeCommand('frolic.signOut');
                } else if (selection.label.includes('Sign In')) {
                    await vscode.commands.executeCommand('frolic.signIn');
                } else if (selection.label.includes('Refresh')) {
                    // Close and reopen to refresh
                    quickPick.dispose();
                    await vscode.commands.executeCommand('frolic.showDropdown');
                    return;
                }
            }
            quickPick.dispose();
        });
        
        quickPick.onDidHide(() => quickPick.dispose());
        quickPick.show();
    });
    context.subscriptions.push(showDropdownCmd);

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
                    await sendDigestImmediately(context, 3, false); // Don't show notification (we show our own)
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
    const showWelcomeCmd = vscode.commands.registerCommand('frolic.showWelcome', async () => {
        try {
            // Try VS Code walkthrough command first
            await vscode.commands.executeCommand('workbench.action.openWalkthrough', 'frolic.frolic#frolic.welcome');
        } catch (error) {
            // Fallback for Cursor or other editors that don't support walkthroughs
            console.log('[FROLIC] Walkthrough command not available, showing welcome message instead');
            const selection = await vscode.window.showInformationMessage(
                '🌟 Welcome to Frolic!\n\nFrolic tracks your coding activity to provide personalized insights and learning recaps.',
                'Sign In to Get Started',
                'Learn More',
                'Got It'
            );
            
            if (selection === 'Sign In to Get Started') {
                vscode.commands.executeCommand('frolic.signIn');
            } else if (selection === 'Learn More') {
                                 vscode.env.openExternal(vscode.Uri.parse('https://getfrolic.dev'));
            }
        }
    });
    context.subscriptions.push(showWelcomeCmd);

    // Register dedicated digest send command for testing
    const sendDigestCmd = vscode.commands.registerCommand('frolic.sendDigest', async () => {
        if (LOG_BUFFER.length === 0) {
            vscode.window.showInformationMessage('📊 Frolic: No activity to send (buffer is empty). Try editing some files first.');
            return;
        }

        try {
            const eventCount = await sendDigestImmediately(context, 3, false); // Don't show notification (we show our own)
            if (eventCount > 0) {
                vscode.window.showInformationMessage(`✅ Frolic: Digest sent successfully! (${eventCount} events processed)`);
            } else {
                // Check authentication status to provide better error message
                const accessToken = await getValidAccessToken(context);
                if (!accessToken) {
                    vscode.window.showWarningMessage('🔐 Frolic: Please sign in first to send digests', 'Sign In')
                        .then(selection => {
                            if (selection === 'Sign In') {
                                vscode.commands.executeCommand('frolic.signIn');
                            }
                        });
                } else {
                    vscode.window.showErrorMessage('❌ Frolic: Failed to send digest. Please try again or check your connection.', 'Retry');
                }
            }
        } catch (err: any) {
            if (err.message === 'NO_AUTH_TOKEN') {
                vscode.window.showWarningMessage('🔐 Frolic: Please sign in first to send digests', 'Sign In')
                    .then(selection => {
                        if (selection === 'Sign In') {
                            vscode.commands.executeCommand('frolic.signIn');
                        }
                    });
            } else if (err.message === 'AUTH_TOKEN_EXPIRED') {
                vscode.window.showWarningMessage('🔐 Frolic: Authentication expired. Please sign in again to continue sending digests.', 'Sign In')
                    .then(selection => {
                        if (selection === 'Sign In') {
                            vscode.commands.executeCommand('frolic.signIn');
                        }
                    });
            } else {
                vscode.window.showErrorMessage(`❌ Frolic: Network error occurred: ${err.message}`, 'Retry');
            }
        }
    });
    context.subscriptions.push(sendDigestCmd);

    // Register writeLogsToFile command
    const writeLogsCmd = vscode.commands.registerCommand('frolic.writeLogsToFile', async () => {
        writeLogsToFile();
        vscode.window.showInformationMessage('✅ Frolic: Logs written to .frolic-log.json');
    });
    context.subscriptions.push(writeLogsCmd);

    // Register refresh activity panel command
    const refreshActivityPanelCmd = vscode.commands.registerCommand('frolic.refreshActivityPanel', () => {
        if (activityProvider) {
            activityProvider.refresh();
            vscode.window.showInformationMessage('🔄 Frolic: Activity panel refreshed');
        }
    });
    context.subscriptions.push(refreshActivityPanelCmd);

    // Register sign-out command
    const signOutCmd = vscode.commands.registerCommand('frolic.signOut', async () => {
        try {
            // Clear all auth tokens and reset state
            await clearAllAuthTokens(context);
            
            // Update status
            updateStatusBar('unauthenticated');
            
            // Refresh activity panel to show updated auth status
            if (activityProvider) {
                activityProvider.refresh();
            }
            
            vscode.window.showInformationMessage('👋 Signed out from Frolic. Your local activity tracking will continue.', 'Sign In Again')
                .then(selection => {
                    if (selection === 'Sign In Again') {
                        vscode.commands.executeCommand('frolic.signIn');
                    }
                });
        } catch (error) {
            console.error('[FROLIC] Sign-out error:', error);
            vscode.window.showErrorMessage('Failed to sign out. Please try again.');
        }
    });
    context.subscriptions.push(signOutCmd);

    // Register open skills webview command
    const openSkillsCmd = vscode.commands.registerCommand('frolic.openSkills', async () => {
        try {
            // Check if authenticated first (API key or OAuth token)
            const apiKey = await context.secrets.get('frolic.apiKey');
            const accessToken = apiKey ? 'api-key' : await getValidAccessToken(context);
            if (!accessToken && !apiKey) {
                // Show sign in options
                const quickPick = vscode.window.createQuickPick();
                quickPick.title = 'Frolic Skills';
                quickPick.placeholder = 'Sign in to view your skills progress';
                quickPick.items = [
                    {
                        label: 'Sign In Required',
                        kind: vscode.QuickPickItemKind.Separator
                    },
                    {
                        label: '$(sign-in) Sign In to Frolic',
                        description: 'Connect your VS Code to view skills progress'
                    },
                    {
                        label: '',
                        kind: vscode.QuickPickItemKind.Separator
                    },
                    {
                        label: '$(globe) Open Frolic Dashboard',
                        description: 'View full dashboard in browser'
                    }
                ];
                
                quickPick.onDidAccept(() => {
                    const selection = quickPick.selectedItems[0];
                    if (selection?.label.includes('Sign In')) {
                        quickPick.dispose();
                        vscode.commands.executeCommand('frolic.signIn');
                    } else if (selection?.label.includes('Open Frolic Dashboard')) {
                        vscode.env.openExternal(vscode.Uri.parse(`${getApiBaseUrl()}/skills`));
                        quickPick.dispose();
                    }
                });
                
                quickPick.show();
                return;
            }
            
            // Show loading quick pick
            const quickPick = vscode.window.createQuickPick();
            quickPick.title = 'Frolic Skills';
            quickPick.placeholder = 'Loading skills data...';
            quickPick.busy = true;
            quickPick.items = [];
            quickPick.show();
            
            let showAllSkills = false; // Track whether to show all skills or just top 3
            
            // Fetch skills data from API
            try {
                const skillsData = await fetchSkillsData(context);
                console.log('[FROLIC] Skills data received:', skillsData);
                
                const renderSkills = (skills: any[], showAll: boolean = false) => {
                console.log('[FROLIC] Rendering skills, showAll:', showAll);
                
                // Filter to only the correct 12 skills from the technical design
                const CORRECT_SKILLS = [
                    'Programming Fundamentals',
                    'Software Design & Architecture', 
                    'Frontend Development',
                    'Backend Development',
                    'DevOps & Infrastructure',
                    'Security & Auth',
                    'Testing & Quality Assurance',
                    'Developer Productivity & Collaboration',
                    'Mobile Development',
                    'Databases & Data Modeling',
                    'Data Engineering & Analytics',
                    'AI, Learning, & Prompting'
                ];
                
                // Transform skills into QuickPick items
                const items: vscode.QuickPickItem[] = [];
                
                // Add skills separator first
                items.push({
                    label: 'Your Skills Progress',
                    kind: vscode.QuickPickItemKind.Separator
                });
                
                // Create skills display using the same logic as the web app
                // Sort skills by total points to show top 3
                const skillsWithData = CORRECT_SKILLS.map(skillName => {
                    const skillData = skills.find(s => s.skill_name === skillName);
                    return {
                        name: skillName,
                        data: skillData,
                        totalPoints: skillData?.total_points || 0
                    };
                }).sort((a, b) => b.totalPoints - a.totalPoints);
                
                // Show either top 3 or all skills based on showAll flag
                const skillsToShow = showAll ? skillsWithData : skillsWithData.slice(0, 3);
                
                skillsToShow.forEach(({ name: skillName, data: skillData }) => {
                    if (skillData) {
                        // Use the same progress calculation as the web app
                        const totalPoints = skillData.total_points || 0;
                        const currentLevel = skillData.current_level || 1;
                        const pointsToNext = skillData.points_to_next_level || 10;
                        
                        // Calculate progress within current level (not overall)
                        // Level requirements: [10, 12, 15, 18, 20, 25, 30, 35, 40, 50]
                        const levelRequirements = [10, 12, 15, 18, 20, 25, 30, 35, 40, 50];
                        const currentLevelReq = levelRequirements[currentLevel - 1] || 10;
                        const pointsInCurrentLevel = currentLevelReq - pointsToNext;
                        const progress = currentLevelReq > 0 ? Math.round((pointsInCurrentLevel / currentLevelReq) * 100) : 0;
                        const progressBar = createProgressBar(progress);
                        
                        items.push({
                            label: `$(book) ${skillName}`,
                            description: `Level ${currentLevel} • ${progressBar} ${progress}%`,
                            detail: `Points: ${totalPoints} • Next level in ${pointsToNext} pts • Digest: ${skillData.points_breakdown?.digest || 0} • Quiz: ${skillData.points_breakdown?.skill_quiz || 0}`
                        });
                    } else {
                        // Show default for missing skills
                        items.push({
                            label: `$(book) ${skillName}`,
                            description: `Level 1 • ${'░'.repeat(10)} 0%`,
                            detail: `Points: 0 • Next level in 10 pts • Start earning points to level up!`
                        });
                    }
                });
                
                // Add "Show All Skills" option if not showing all and there are more than 3 skills
                if (!showAll && skillsWithData.length > 3) {
                    items.push({
                        label: '$(chevron-down) Show All Skills',
                        description: `View all ${skillsWithData.length} skills`
                    });
                }
                
                // Add actions separator and actions at the bottom (in requested order)
                items.push({
                    label: 'Actions',
                    kind: vscode.QuickPickItemKind.Separator
                });
                
                items.push({
                    label: '$(cloud-upload) Send Digest',
                    description: 'Send your coding activity digest now'
                });
                
                items.push({
                    label: '$(globe) Open Frolic Dashboard',
                    description: 'View full dashboard in browser'
                });
                
                items.push({
                    label: '$(refresh) Refresh Skills',
                    description: 'Update skills data'
                });
                
                items.push({
                    label: '$(sign-out) Sign Out',
                    description: 'Sign out of Frolic'
                });
                
                // Update quick pick
                quickPick.busy = false;
                quickPick.placeholder = showAll ? 'All skills • Select an action below' : 'Top 3 skills • Select an action below';
                quickPick.items = items;
            };
            
            // Initial render with top 3 skills
            renderSkills(skillsData, showAllSkills);
            
            // Handle selection
            quickPick.onDidAccept(() => {
                const selection = quickPick.selectedItems[0];
                if (selection?.label.includes('Show All Skills')) {
                    showAllSkills = true;
                    renderSkills(skillsData, showAllSkills);
                } else if (selection?.label.includes('Refresh')) {
                    quickPick.dispose();
                    vscode.commands.executeCommand('frolic.openSkills');
                } else if (selection?.label.includes('Send Digest')) {
                    quickPick.dispose();
                    vscode.commands.executeCommand('frolic.sendDigest');
                } else if (selection?.label.includes('Sign Out')) {
                    quickPick.dispose();
                    vscode.commands.executeCommand('frolic.signOut');
                } else if (selection?.label.includes('Open Frolic Dashboard')) {
                    vscode.env.openExternal(vscode.Uri.parse(`${getApiBaseUrl()}/skills`));
                    quickPick.dispose();
                }
            });
            
        } catch (error: any) {
            console.error('[FROLIC] Skills fetch error details:', {
                message: error.message,
                stack: error.stack
            });
            quickPick.busy = false;
            quickPick.items = [{
                label: '$(error) Failed to load skills',
                description: 'Please try again',
                detail: error.message
            }];
        }
    } catch (error) {
        console.error('[FROLIC] Error opening skills view:', error);
        vscode.window.showErrorMessage('Failed to open skills view. Please try again.');
    }
});
    context.subscriptions.push(openSkillsCmd);

    // Test command to debug API endpoint
    const testSkillsApiCmd = vscode.commands.registerCommand('frolic.testSkillsApi', async () => {
        const apiBaseUrl = getApiBaseUrl();
        const accessToken = await getValidAccessToken(context);
        
        console.log('[FROLIC TEST] Base URL:', apiBaseUrl);
        console.log('[FROLIC TEST] Has token:', !!accessToken);
        
        if (!accessToken) {
            vscode.window.showErrorMessage('No access token available');
            return;
        }
        
        // Test the exact endpoint
        try {
            console.log('[FROLIC TEST] Testing endpoint:', `${apiBaseUrl}/api/skills`);
            const response = await fetchWithTimeout(`${apiBaseUrl}/api/skills`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Content-Type': 'application/json',
                    'User-Agent': 'VSCode-Frolic-Extension/1.1.1'
                }
            }, 30000);
            
            console.log('[FROLIC TEST] Response status:', response.status);
            console.log('[FROLIC TEST] Response headers:', Object.fromEntries(response.headers.entries()));
            
            const text = await response.text();
            console.log('[FROLIC TEST] Response body:', text);
            
            if (response.ok) {
                try {
                    const data = JSON.parse(text);
                    vscode.window.showInformationMessage(`Skills API works! Found ${data.data?.length || 0} skills`);
                } catch (e) {
                    vscode.window.showErrorMessage('Skills API returned invalid JSON');
                }
            } else {
                vscode.window.showErrorMessage(`Skills API error: ${response.status} - ${text}`);
            }
        } catch (error: any) {
            console.error('[FROLIC TEST] Error:', error);
            vscode.window.showErrorMessage(`Test failed: ${error.message}`);
        }
    });
    context.subscriptions.push(testSkillsApiCmd);

    // Register debug command for troubleshooting (can be triggered from status bar)
    const debugCmd = vscode.commands.registerCommand('frolic.debug', async () => {
        const accessToken = await getValidAccessToken(context);
        const tokenInfo = accessToken ? 'Valid' : 'Missing/Invalid';
        
        vscode.window.showInformationMessage(
            `🔍 Frolic Debug Info:\n` +
            `• Buffer: ${LOG_BUFFER.length} events\n` +
            `• Memory: ${Math.round(bufferMemoryUsage / 1024)}KB\n` +
            `• Auth: ${tokenInfo}\n` +
            `• Session: ${sessionId.substring(0, 8)}...`,
            'View Buffer',
            'Test Send'
        ).then(selection => {
            if (selection === 'View Buffer') {
                writeLogsToFile();
                vscode.commands.executeCommand('vscode.open', vscode.Uri.file(
                    path.join(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '', '.frolic-log.json')
                ));
            } else if (selection === 'Test Send') {
                vscode.commands.executeCommand('frolic.sendDigest');
            }
        });
    });
    context.subscriptions.push(debugCmd);

    // 🔄 PHASE 1.3: Start smart backup system
    startPeriodicBackup();
    
    // 🔄 PHASE 1.4: Start inactivity backup monitoring
    resetInactivityBackupTimer();

    // 🔄 PHASE 1.3: Window focus loss backup trigger
    context.subscriptions.push(
        vscode.window.onDidChangeWindowState(state => {
            if (!state.focused) {
                // Window lost focus - create backup
                createSmartBackup('window-focus-loss').catch(err => {
                    console.log('[FROLIC] Focus loss backup failed');
                });
            }
        })
    );

    // 🔄 PHASE 2.2: Learning Struggle Detection Event Listeners
    console.log('[FROLIC] 🔄 Initializing Phase 2.2: Learning Struggle Detection...');
    
    // Track text editor selection changes for pause detection
    context.subscriptions.push(
        vscode.window.onDidChangeTextEditorSelection(event => {
            const now = Date.now();
            
            // Detect long pauses
            if (now - lastSignificantAction > LONG_PAUSE_THRESHOLD) {
                detectLongPause(now);
            }
            
            // Update last significant action
            lastSignificantAction = now;
        })
    );
    
    // Enhanced file opening tracking for frequent switching detection
    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor(editor => {
            if (editor && editor.document.fileName) {
                // Validate file path before processing
                if (!isValidPath(editor.document.fileName)) {
                    return;
                }
                
                const now = Date.now();
                const sanitizedPath = sanitizePath(editor.document.fileName);
                detectFrequentFileSwitching(sanitizedPath, now);
                
                // Log file switch action
                userActionHistory.push({
                    timestamp: now,
                    action: 'file_switch',
                    context: {
                        fileName: sanitizedPath,
                        language: editor.document.languageId
                    }
                });
            }
        })
    );
    
    // Track undo/redo commands
    context.subscriptions.push(
        vscode.commands.registerCommand('frolic.trackUndo', () => {
            detectRapidUndoRedo(Date.now(), 'undo');
        })
    );
    
    context.subscriptions.push(
        vscode.commands.registerCommand('frolic.trackRedo', () => {
            detectRapidUndoRedo(Date.now(), 'redo');
        })
    );

    // 🔄 PHASE 2.3: Error and Debugging Tracking Event Listeners
    console.log('[FROLIC] 🔄 Initializing Phase 2.3: Error and Debugging Tracking...');
    
    // Main diagnostic change listener
    context.subscriptions.push(
        vscode.languages.onDidChangeDiagnostics(event => {
            event.uris.forEach(uri => {
                const currentDiagnostics = vscode.languages.getDiagnostics(uri);
                const timestamp = Date.now();
                const rawFilePath = uri.fsPath;
                
                // Validate file path
                if (!isValidPath(rawFilePath)) {
                    return;
                }
                
                const filePath = sanitizePath(rawFilePath);
                
                // Skip if it's a git file or other excluded path
                if (filePath.includes('.git') || filePath.startsWith('git/')) {
                    return;
                }
                
                // 🔧 FIX: Throttle diagnostic logging to prevent LOG_BUFFER flooding
                const lastLogTime = lastDiagnosticLogTime.get(filePath) || 0;
                const now = Date.now();
                if (now - lastLogTime < DIAGNOSTIC_LOG_THROTTLE_MS) {
                    return; // Skip logging if we've logged this file recently
                }
                lastDiagnosticLogTime.set(filePath, now);
                
                // Determine change type
                const changeType = getDiagnosticChangeType(uri, currentDiagnostics);
                
                // Log the diagnostic change (now throttled)
                logEvent('diagnostic_change', {
                    file: filePath,
                    diagnosticCount: currentDiagnostics.length,
                    errorCount: currentDiagnostics.filter(d => d.severity === vscode.DiagnosticSeverity.Error).length,
                    warningCount: currentDiagnostics.filter(d => d.severity === vscode.DiagnosticSeverity.Warning).length,
                    changeType: changeType,
                    diagnostics: currentDiagnostics.slice(0, 10).map(d => ({ // Limit to first 10 to avoid memory issues
                        severity: d.severity,
                        code: d.code?.toString() || '',
                        message: d.message.substring(0, 200), // Truncate message
                        category: categorizeError(d),
                        range: {
                            start: { line: d.range.start.line, character: d.range.start.character },
                            end: { line: d.range.end.line, character: d.range.end.character }
                        }
                    }))
                });
                
                // Update error session tracking
                updateErrorSession(filePath, currentDiagnostics);
                
                // Store current diagnostics for next comparison
                previousDiagnostics.set(uri.toString(), [...currentDiagnostics]);
                
                // Add to diagnostic history
                diagnosticHistory.push({
                    timestamp,
                    uri: filePath,
                    diagnostics: currentDiagnostics,
                    eventType: changeType
                });
            });
        })
    );
    
    // Periodic cleanup for struggle and error data
    const cleanupInterval = setInterval(() => {
        cleanupOldStruggleData();
        cleanupOldErrorData();
    }, 60 * 60 * 1000); // Every hour
    context.subscriptions.push({ dispose: () => clearInterval(cleanupInterval) });

    // Start daily digest sending (with recovered data if any)
    startPeriodicDigestSending(context);

    // Enhanced activation with multiple sign-in triggers
    initializeAuthenticationFlow(context);

    // 🔄 ENHANCED: Start background token refresh if authenticated
    const hasTokens = await context.secrets.get('frolic.accessToken') && await context.secrets.get('frolic.refreshToken');
    if (hasTokens) {
        // Load stored token expiration time
        const storedExpiresAt = await context.globalState.get<number>('frolic.tokenExpiresAt');
        if (storedExpiresAt) {
            tokenExpiresAt = storedExpiresAt;
            console.log(`[FROLIC] Loaded token expiration: ${new Date(tokenExpiresAt * 1000).toISOString()}`);
        }
        
        startBackgroundTokenRefresh(context);
        
        // Proactively refresh token on activation to ensure fresh session
        const accessToken = await context.secrets.get('frolic.accessToken');
        if (accessToken && isTokenExpired(accessToken)) {
            console.log('[FROLIC] Token expired while VSCode was closed, will refresh on first use');
        } else if (accessToken && shouldProactivelyRefreshToken(accessToken)) {
            console.log('[FROLIC] Proactively refreshing token on activation');
            performBackgroundTokenRefresh(context).catch(err => {
                console.error('[FROLIC] Activation token refresh error:', err.message);
            });
        }
    }
    
    // Add window focus listener to refresh token when VS Code regains focus
    context.subscriptions.push(
        vscode.window.onDidChangeWindowState(async (state) => {
            if (state.focused && hasTokens) {
                const accessToken = await context.secrets.get('frolic.accessToken');
                if (accessToken && shouldProactivelyRefreshToken(accessToken)) {
                    console.log('[FROLIC] Window focused - checking token freshness');
                    performBackgroundTokenRefresh(context).catch(err => {
                        console.error('[FROLIC] Window focus token refresh error:', err.message);
                    });
                }
            }
        })
    );

    // Initialize baseline for already open files
    vscode.workspace.textDocuments.forEach(document => {
        if (!document.isUntitled && document.fileName) {
            fileLineBaseline.set(document.fileName, document.lineCount);
            console.log(`[FROLIC] Initialized baseline for ${document.fileName}: ${document.lineCount} lines`);
        }
    });

    console.log(`✅ Frolic Logger is now active! (${LOG_BUFFER.length} events in buffer)`);
}

export function deactivate() {
    console.log('🛑 Frolic Logger is deactivating...');
    
    // 🔄 PHASE 1.3: Stop smart backup system
    stopPeriodicBackup();
    
    // 🔄 PHASE 1.4: Stop inactivity backup monitoring
    stopInactivityBackupTimer();
    
    // Stop the daily digest timer
    stopPeriodicDigestSending();
    
    // 🔄 ENHANCED: Stop background token refresh
    stopBackgroundTokenRefresh();
    
    // 🔄 PHASE 1.3: Create final smart backup before shutdown
    if (LOG_BUFFER.length > 0) {
        console.log(`[FROLIC] Extension deactivating with ${LOG_BUFFER.length} unsent events.`);
        console.log('[FROLIC] 💾 Creating final smart backup layers...');
        
        try {
            const workspaceFolders = vscode.workspace.workspaceFolders;
            if (workspaceFolders && workspaceFolders.length > 0) {
                const workspacePath = workspaceFolders[0].uri.fsPath;
                
                // 1. Primary backup (new smart backup format)
                const primaryBackupPath = path.join(workspacePath, '.frolic-session.json');
                const backupData = {
                    timestamp: new Date().toISOString(),
                    sessionId: sessionId,
                    eventCount: LOG_BUFFER.length,
                    events: LOG_BUFFER,
                    metadata: {
                        version: '1.3.0',
                        trigger: 'deactivation',
                        memoryUsage: bufferMemoryUsage
                    }
                };
                fs.writeFileSync(primaryBackupPath, JSON.stringify(backupData, null, 2), 'utf8');
                console.log('[FROLIC] ✅ Primary backup: .frolic-session.json created');
                
                // 2. Emergency backup with timestamp
                const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
                const emergencyBackupPath = path.join(workspacePath, `.frolic-backup-${timestamp}.json`);
                fs.writeFileSync(emergencyBackupPath, JSON.stringify(backupData, null, 2), 'utf8');
                console.log(`[FROLIC] ✅ Emergency backup: ${emergencyBackupPath} created`);
                
                // 3. Temp directory backup as final fallback
                try {
                    const os = require('os');
                    const tempDir = os.tmpdir();
                    const tempBackupPath = path.join(tempDir, `frolic-emergency-${timestamp}.json`);
                    fs.writeFileSync(tempBackupPath, JSON.stringify(backupData, null, 2), 'utf8');
                    console.log(`[FROLIC] ✅ Temp backup: ${tempBackupPath} created`);
        } catch (err) {
                    console.warn('[FROLIC] Temp backup failed (non-critical):', err);
                }
            }
            
            // 4. Extension storage backup
            if (extensionContext) {
                const storageBackup = {
                    timestamp: new Date().toISOString(),
                    sessionId: sessionId,
                    eventCount: LOG_BUFFER.length,
                    events: LOG_BUFFER.slice(-1000), // Keep last 1000 events
                    metadata: {
                        version: '1.3.0',
                        trigger: 'deactivation-storage',
                        truncated: LOG_BUFFER.length > 1000
                    }
                };
                
                extensionContext.globalState.update('frolic.smartBackup', storageBackup);
                console.log('[FROLIC] ✅ Extension storage backup updated');
            }
            
            console.log('[FROLIC] 🔄 Smart backup system: Data recovery will restore these events on next startup');
            
        } catch (err) {
            console.error('[FROLIC] ❌ Final backup creation failed:', err);
        }
    } else {
        console.log('[FROLIC] No unsent events to backup');
    }
    
    // Clear the buffer to free memory
    LOG_BUFFER.length = 0;
    bufferMemoryUsage = 0;
    
    console.log('🛑 Frolic Logger deactivated with smart backup system protection.');
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
    const frequencyHours = config.get<number>('digestFrequencyHours', 0.75);
    const intervalMs = frequencyHours * 60 * 60 * 1000; // Convert hours to milliseconds
    
    // Send initial digest if there's already data in buffer (from previous session)
    if (LOG_BUFFER.length > 0) {
        console.log(`[FROLIC] Found ${LOG_BUFFER.length} events from previous session, sending initial digest`);
        // Don't block startup - send in background
        sendDigestImmediately(context, 3, true).catch(err => { // Show notification for recovered data
            console.log('[FROLIC] Initial digest send failed, will retry on next interval');
        });
    }
    
    digestTimer = setInterval(async () => {
        // Check if enough time has passed since last digest to prevent rapid-fire sends after system wake
        const timeSinceLastDigest = Date.now() - lastDigestSentTime;
        const minIntervalMs = intervalMs * 0.9; // Allow 10% early to account for timer drift
        
        if (timeSinceLastDigest < minIntervalMs) {
            console.log(`[FROLIC] Skipping digest - only ${Math.round(timeSinceLastDigest/1000/60)} minutes since last send (min: ${Math.round(minIntervalMs/1000/60)} minutes)`);
            return;
        }
        
        // Debounce check - if a digest is already pending, skip this one
        if (pendingDigestSend) {
            console.log('[FROLIC] Digest send already pending, skipping duplicate');
            return;
        }
        
        pendingDigestSend = true;
        
        // Check if this is a "catch-up" digest after system wake
        // If much more time has passed than expected, it's likely the system was asleep
        const isCatchUpDigest = timeSinceLastDigest > intervalMs * 1.5; // 50% over expected interval
        
        // Add some jitter to prevent thundering herd if many users have same interval
        const jitter = Math.random() * 60000; // 0-1 minute random delay
        setTimeout(async () => {
            try {
                // Never show notifications for periodic digests
                console.log('[FROLIC] Sending periodic digest (no notification)');
                await sendDigestImmediately(context, 3, false);
            } finally {
                pendingDigestSend = false;
            }
        }, jitter);
    }, intervalMs);

    console.log(`[FROLIC] Periodic digest timer started (every ${frequencyHours} hours)`);
}

async function sendDigestImmediately(context: vscode.ExtensionContext, maxRetries: number = 3, showNotification: boolean = true): Promise<number> {
    if (LOG_BUFFER.length > 0) {
        const eventCount = LOG_BUFFER.length; // Capture count before clearing
        console.log(`[FROLIC] Sending digest with ${eventCount} events`);
        updateStatusBar('sending');
        
        // 🔄 PHASE 1.3: Smart backup before digest sending
        await createSmartBackup('pre-digest-send', true);
        
        const digest = analyzeLogs(LOG_BUFFER);
        let lastError: Error | null = null;
        
        // Retry logic with exponential backoff
        for (let attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                await sendDigestToBackend(sessionId, digest, context);
                
                // Clear buffer and start new session after successful send
                LOG_BUFFER.length = 0;
                bufferMemoryUsage = 0; // Reset memory tracking
                sessionId = crypto.randomUUID();
                lastDigestSentTime = Date.now(); // Record when we sent this digest
                
                // Reset session timer after successful digest send
                if (activityProvider) {
                    activityProvider.resetSessionTimer();
                    activityProvider.updateLastDigestTime();
                }
                
                console.log(`[FROLIC] Digest sent successfully. New session: ${sessionId}`);
                updateStatusBar('authenticated');
                
                // Only show notification for first digest (onboarding) or if explicitly requested
                if (showNotification && !isFirstDigestSent) {
                    // First digest notification for onboarding
                    vscode.window.showInformationMessage(`✅ Frolic is now tracking your coding activity! Your first digest has been sent.`);
                    isFirstDigestSent = true;
                    // Store this state so we don't show it again
                    context.globalState.update('frolic.firstDigestSent', true);
                }
                
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

function updateStatusBar(status: 'initializing' | 'authenticated' | 'unauthenticated' | 'sending' | 'error' | 'offline' | 'needs-reauth') {
    if (!statusBarItem) return;
    
    switch (status) {
        case 'initializing':
            statusBarItem.text = '$(sync~spin) Frolic';
            statusBarItem.tooltip = 'Frolic is initializing...';
            statusBarItem.backgroundColor = undefined;
            statusBarItem.command = undefined;
            break;
        case 'authenticated':
            statusBarItem.text = '$(check) Frolic Connected';
            statusBarItem.tooltip = `Frolic: Connected and tracking activity (${LOG_BUFFER.length} events logged). Click to view skills.`;
            statusBarItem.backgroundColor = undefined;
            statusBarItem.command = 'frolic.openSkills';
            break;
        case 'unauthenticated':
            statusBarItem.text = '$(sign-in) Connect Frolic';
            statusBarItem.tooltip = 'Frolic: Click to sign in';
            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
            statusBarItem.command = 'frolic.signIn';
            break;
        case 'offline':
            statusBarItem.text = '$(cloud-offline) Frolic Offline';
            statusBarItem.tooltip = 'Frolic: Working offline, digests will sync when reconnected. Click to retry.';
            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
            statusBarItem.command = 'frolic.sendDigest';
            break;
        case 'needs-reauth':
            statusBarItem.text = '$(key) Frolic Re-auth Needed';
            statusBarItem.tooltip = 'Frolic: Authentication expired. Click to sign in again.';
            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
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
            statusBarItem.tooltip = 'Frolic: Connection error. Click to view status.';
            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
            statusBarItem.command = 'frolic.showDropdown';
            break;
    }
    statusBarItem.show();
}

// Tree view data provider for Frolic activity
class FrolicActivityProvider implements vscode.TreeDataProvider<FrolicTreeItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<FrolicTreeItem | undefined | null | void> = new vscode.EventEmitter<FrolicTreeItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<FrolicTreeItem | undefined | null | void> = this._onDidChangeTreeData.event;
    private sessionStartTime: Date = new Date();
    private lastDigestTime: number = 0;
    
    constructor(private context: vscode.ExtensionContext) {
        // Initialize with current time first
        this.sessionStartTime = new Date();
        
        // Try to restore session start time from storage
        const storedSessionTime = this.context.globalState.get<number>('frolic.sessionStartTime');
        if (storedSessionTime) {
            this.sessionStartTime = new Date(storedSessionTime);
        } else {
            // No stored time, save current time
            this.context.globalState.update('frolic.sessionStartTime', this.sessionStartTime.getTime());
        }
        
        // Try to restore last digest time from storage
        const storedDigestTime = this.context.globalState.get<number>('frolic.lastDigestTime');
        if (storedDigestTime) {
            this.lastDigestTime = storedDigestTime;
        }
    }

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    resetSessionTimer(): void {
        this.sessionStartTime = new Date();
        // Persist the new session start time
        this.context.globalState.update('frolic.sessionStartTime', this.sessionStartTime.getTime());
        this.refresh(); // Update the display
    }

    getTreeItem(element: FrolicTreeItem): vscode.TreeItem {
        return element;
    }

    async getChildren(element?: FrolicTreeItem): Promise<FrolicTreeItem[]> {
        if (!element) {
            // Streamlined root level items - show essentials only
            const items: FrolicTreeItem[] = [];
            
            // Session header with logo
            const logoPath = vscode.Uri.file(path.join(this.context.extensionPath, 'images', 'frolic_logo.png'));
            const sessionDuration = Math.round((Date.now() - this.sessionStartTime.getTime()) / 1000 / 60);
            items.push(new FrolicTreeItem(
                `Frolic Session • ${sessionDuration}m`,
                vscode.TreeItemCollapsibleState.None,
                'session-header',
                {
                    command: 'frolic.openSkills',
                    title: 'View Skills',
                    tooltip: 'Click to view your skills dashboard'
                },
                logoPath
            ));

            // Auth status (always visible) - get actual status
            const authItems = await this.getAuthStatusItems();
            if (authItems.length > 0) {
                items.push(authItems[0]); // Use the actual auth status item
            }

            // Last digest status (always visible)
            const lastDigestText = this.getLastDigestTimeText();
            items.push(new FrolicTreeItem(
                lastDigestText,
                vscode.TreeItemCollapsibleState.None,
                'digest-status',
                undefined,
                new vscode.ThemeIcon('mail')
            ));

            // Send digest action (always visible)
            const digestReady = LOG_BUFFER.length >= 1000;
            items.push(new FrolicTreeItem(
                digestReady ? 'Send Digest (Ready!)' : `Send Digest (${LOG_BUFFER.length}/1000)`,
                vscode.TreeItemCollapsibleState.None,
                'action-send-digest',
                {
                    command: 'frolic.sendDigest',
                    title: 'Send Digest Now'
                },
                new vscode.ThemeIcon(digestReady ? 'cloud-upload' : 'clock')
            ));

            // Recent activity summary (always visible)
            const recentActivity = this.getRecentActivity();
            items.push(new FrolicTreeItem(
                `Recent: ${recentActivity} edits/5m`,
                vscode.TreeItemCollapsibleState.None,
                'activity-summary',
                undefined,
                new vscode.ThemeIcon('flame')
            ));

            // Details section (collapsed by default - contains all the detailed metrics)
            items.push(new FrolicTreeItem(
                'Details',
                vscode.TreeItemCollapsibleState.Collapsed,
                'details-section'
            ));

            return items;
        } 
        
        else if (element.contextValue === 'details-section') {
            // All the detailed information goes here
            const items: FrolicTreeItem[] = [];
            
            // Session overview stats
            const totalEvents = LOG_BUFFER.length;
            const filesEdited = new Set(LOG_BUFFER.map(e => e.relativePath)).size;
            const totalLines = this.getTotalLinesChanged();
            const aiInsertions = this.getAIInsertions();
            const codingVelocity = this.getCodingVelocity();
            const bufferMemoryMB = (bufferMemoryUsage / 1024 / 1024).toFixed(1);
            
            items.push(new FrolicTreeItem(
                `Events: ${totalEvents}`,
                vscode.TreeItemCollapsibleState.None,
                'detail-stat',
                undefined,
                new vscode.ThemeIcon('symbol-event')
            ));
            
            items.push(new FrolicTreeItem(
                `Files: ${filesEdited}`,
                vscode.TreeItemCollapsibleState.None,
                'detail-stat',
                undefined,
                new vscode.ThemeIcon('file')
            ));
            
            items.push(new FrolicTreeItem(
                `Lines: +${totalLines}`,
                vscode.TreeItemCollapsibleState.None,
                'detail-stat',
                undefined,
                new vscode.ThemeIcon('add')
            ));
            
            items.push(new FrolicTreeItem(
                `AI Assists: ${aiInsertions}`,
                vscode.TreeItemCollapsibleState.None,
                'detail-stat',
                undefined,
                new vscode.ThemeIcon('robot')
            ));
            
            items.push(new FrolicTreeItem(
                `Velocity: ${codingVelocity}/min`,
                vscode.TreeItemCollapsibleState.None,
                'detail-stat',
                undefined,
                new vscode.ThemeIcon('pulse')
            ));
            
            items.push(new FrolicTreeItem(
                `Buffer: ${bufferMemoryMB}MB`,
                vscode.TreeItemCollapsibleState.None,
                'detail-stat',
                undefined,
                new vscode.ThemeIcon('database')
            ));

            // Add active files if any
            const activeFiles = this.getActiveFiles();
            if (activeFiles.length > 0) {
                items.push(new FrolicTreeItem(
                    `Top Files (${activeFiles.length})`,
                    vscode.TreeItemCollapsibleState.Collapsed,
                    'active-files'
                ));
            }

            // Add insights
            const insights = this.generateInsights();
            if (insights.length > 0) {
                items.push(new FrolicTreeItem(
                    `Insights (${insights.length})`,
                    vscode.TreeItemCollapsibleState.Collapsed,
                    'insights'
                ));
            }

            // Add additional actions
            items.push(new FrolicTreeItem(
                'Write Logs to File',
                vscode.TreeItemCollapsibleState.None,
                'action-write-logs',
                {
                    command: 'frolic.writeLogsToFile',
                    title: 'Write Logs'
                },
                new vscode.ThemeIcon('save')
            ));
            
            items.push(new FrolicTreeItem(
                'Refresh Panel',
                vscode.TreeItemCollapsibleState.None,
                'action-refresh',
                {
                    command: 'frolic.refreshActivityPanel',
                    title: 'Refresh Panel'
                },
                new vscode.ThemeIcon('refresh')
            ));

            return items;
        }
        
        else if (element.contextValue === 'auth-status') {
            return this.getAuthStatusItems();
        }
        
        else if (element.contextValue === 'active-files') {
            const activeFiles = this.getActiveFiles();
            return activeFiles.map(file => {
                const fileIcon = this.getFileIcon(file.fullPath);
                return new FrolicTreeItem(
                    `${fileIcon} ${file.name} (${file.count})`,
                    vscode.TreeItemCollapsibleState.None,
                    'file-item',
                    {
                        command: 'vscode.open',
                        title: 'Open File',
                        arguments: [vscode.Uri.file(path.resolve(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '', file.fullPath))]
                    }
                );
            });
        }
        
        else if (element.contextValue === 'insights') {
            const insights = this.generateInsights();
            return insights.map(insight => 
                new FrolicTreeItem(
                    insight,
                    vscode.TreeItemCollapsibleState.None,
                    'insight',
                    undefined,
                    new vscode.ThemeIcon('lightbulb')
                )
            );
        }

        return [];
    }

    private getActiveFiles(): {name: string, fullPath: string, count: number}[] { 
        const fileActivity: {[key: string]: number} = {};
        
        LOG_BUFFER.forEach(entry => {
            if (entry.eventType === 'file_edit' && entry.relativePath) {
                fileActivity[entry.relativePath] = (fileActivity[entry.relativePath] || 0) + 1;
            }
        });

        return Object.entries(fileActivity)
            .map(([fullPath, count]) => ({
                name: fullPath.split('/').pop() || fullPath,
                fullPath,
                count
            }))
            .sort((a, b) => b.count - a.count)
            .slice(0, 5); // Show top 5 most active files
    }

    private getRecentActivity(): number {
        const fiveMinutesAgo = Date.now() - (5 * 60 * 1000);
        return LOG_BUFFER.filter(event => 
            event.eventType === 'file_edit' && 
            new Date(event.timestamp).getTime() > fiveMinutesAgo
        ).length;
    }

    private getCodingVelocity(): string {
        const sessionDurationMinutes = (Date.now() - this.sessionStartTime.getTime()) / 1000 / 60;
        if (sessionDurationMinutes < 1) return '0 lines';
        
        const totalLines = this.getTotalLinesChanged();
        const velocity = Math.round((totalLines / sessionDurationMinutes) * 10) / 10;
        
        return `${velocity} lines`;
    }

    private getTotalLinesChanged(): number {
        return LOG_BUFFER
            .filter(e => e.eventType === 'file_edit')
            .reduce((sum, e) => sum + (e.changes?.reduce((s: number, c: any) => s + Math.abs(c.lineCountDelta || 0), 0) || 0), 0);
    }

    private getAIInsertions(): number {
        return LOG_BUFFER
            .filter(e => e.eventType === 'file_edit')
            .reduce((sum, e) => sum + (e.changes?.filter((c: any) => c.likelyAI).length || 0), 0);
    }

    private getLastDigestTimeText(): string {
        if (this.lastDigestTime === 0) {
            return 'Last digest: never';
        }
        
        const now = Date.now();
        const diffMs = now - this.lastDigestTime;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);
        
        if (diffDays > 0) {
            return `Last digest: ${diffDays}d ago`;
        } else if (diffHours > 0) {
            return `Last digest: ${diffHours}h ago`;
        } else if (diffMins > 0) {
            return `Last digest: ${diffMins}m ago`;
        } else {
            return 'Last digest: just now';
        }
    }

    updateLastDigestTime(): void {
        this.lastDigestTime = Date.now();
        // Persist to storage
        this.context.globalState.update('frolic.lastDigestTime', this.lastDigestTime);
        this.refresh();
    }

    private generateInsights(): string[] {
        const insights: string[] = [];
        const languages = this.getLanguageStats();
        const topLanguage = Object.entries(languages).sort((a, b) => b[1] - a[1])[0];
        
        if (topLanguage) {
            insights.push(`Focus: ${topLanguage[0]} (${topLanguage[1]} edits)`);
        }
        
        const sessionDuration = (Date.now() - this.sessionStartTime.getTime()) / 1000 / 60;
        if (sessionDuration > 30) {
            insights.push(`Deep focus: ${Math.round(sessionDuration)}m session`);
        }
        
        const aiAssists = this.getAIInsertions();
        if (aiAssists === 0 && LOG_BUFFER.length > 10) {
            insights.push('Independent coding streak!');
        } else if (aiAssists > 0) {
            insights.push(`AI-assisted development (${aiAssists})`);
        }
        
        const uniqueFiles = new Set(LOG_BUFFER.map(e => e.relativePath)).size;
        if (uniqueFiles > 5) {
            insights.push(`Multi-file project (${uniqueFiles} files)`);
        }
        
        const recentActivity = this.getRecentActivity();
        if (recentActivity > 10) {
            insights.push('High activity period!');
        }
        
        if (insights.length === 0) {
            insights.push('Keep coding to see insights!');
        }
        
        return insights.slice(0, 3); // Max 3 insights to avoid clutter
    }

    private getLanguageStats(): {[key: string]: number} {
        const languages: {[key: string]: number} = {};
        LOG_BUFFER.forEach(event => {
            if (event.eventType === 'file_edit' && event.language && event.language !== 'unknown') {
                const lang = this.formatLanguageName(event.language);
                languages[lang] = (languages[lang] || 0) + 1;
            }
        });
        return languages;
    }

    private formatLanguageName(language: string): string {
        const langMap: {[key: string]: string} = {
            'typescriptreact': 'TypeScript React',
            'javascriptreact': 'JavaScript React',
            'typescript': 'TypeScript',
            'javascript': 'JavaScript',
            'python': 'Python',
            'java': 'Java',
            'cpp': 'C++',
            'csharp': 'C#'
        };
        return langMap[language] || language;
    }

    private getFileIcon(filename: string): string {
        const ext = filename.split('.').pop()?.toLowerCase();
        const iconMap: {[key: string]: string} = {
            'ts': 'TS', 'tsx': 'TSX', 'js': 'JS', 'jsx': 'JSX',
            'py': 'PY', 'java': 'JAVA', 'cpp': 'CPP', 'c': 'C', 'cs': 'CS',
            'html': 'HTML', 'css': 'CSS', 'scss': 'SCSS', 'sass': 'SASS',
            'json': 'JSON', 'md': 'MD', 'txt': 'TXT', 'yml': 'YML', 'yaml': 'YAML',
            'go': 'GO', 'rs': 'RS', 'php': 'PHP', 'rb': 'RB'
        };
        return iconMap[ext || ''] || 'FILE';
    }

    private async getAuthStatusItems(): Promise<FrolicTreeItem[]> {
        // Check for API key first
        const apiKey = await this.context.secrets.get('frolic.apiKey');
        if (apiKey) {
            return [
                new FrolicTreeItem(
                    'Sign Out',
                    vscode.TreeItemCollapsibleState.None,
                    'auth-item',
                    {
                        command: 'frolic.signOut',
                        title: 'Sign Out'
                    },
                    new vscode.ThemeIcon('account')
                )
            ];
        }
        
        // Fall back to OAuth token check
        const accessToken = await getValidAccessToken(this.context);
        const status = accessToken ? 'authenticated' : 'unauthenticated';
        const label = status === 'authenticated' ? `Sign Out` : 'Sign In';
        
        return [
            new FrolicTreeItem(
                label,
                vscode.TreeItemCollapsibleState.None,
                'auth-item',
                {
                    command: status === 'authenticated' ? 'frolic.signOut' : 'frolic.signIn',
                    title: status === 'authenticated' ? 'Sign Out' : 'Sign In'
                },
                new vscode.ThemeIcon(status === 'authenticated' ? 'account' : 'sign-in')
            )
        ];
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
        if (command) {
            this.command = command;
        }
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
  
  // Check for API key first (new auth method)
  const apiKey = await context.secrets.get('frolic.apiKey');
  if (apiKey) {
    // Use new public endpoint with API key
    const apiUrl = `${apiBaseUrl}/api/digests/public`;
    console.log(`[FROLIC] Sending digest via API key to: ${apiUrl}`);
    
    try {
      const res = await fetchWithTimeout(apiUrl, {
        method: 'POST',
        headers: {
          'x-api-key': apiKey,
          'Content-Type': 'application/json',
          'User-Agent': 'VSCode-Frolic-Extension/1.2.6-rc2'
        },
        body: JSON.stringify({ sessionId, digest })
      }, 30000);
      
      if (res.ok) {
        return await res.json();
      }
      
      if (res.status === 401) {
        // Invalid API key
        await context.secrets.delete('frolic.apiKey');
        updateStatusBar('unauthenticated');
        vscode.window.showErrorMessage('Frolic: Invalid API key. Please set a new one.');
        throw new Error('INVALID_API_KEY');
      } else if (res.status === 429) {
        // Rate limited
        console.log('[FROLIC] Rate limited by server');
        throw new Error('RATE_LIMITED');
      } else {
        const errorText = await res.text();
        console.error('[FROLIC] API key digest failed:', res.status, errorText);
        throw new Error(`API_ERROR: ${res.status}`);
      }
    } catch (error) {
      console.error('[FROLIC] Digest send error:', error);
      throw error;
    }
  }
  
  // Fall back to OAuth token method (legacy)
  const apiUrl = `${apiBaseUrl}/api/digests`;
  console.log(`[FROLIC] Sending digest via OAuth to: ${apiUrl}`);
  
  // Try to get a valid access token (will refresh if needed)
  const accessToken = await getValidAccessToken(context);
  
  if (!accessToken) {
    console.log('[FROLIC] No valid access token available, skipping digest upload');
    throw new Error('NO_AUTH_TOKEN');
  }

  // Token validation successful (removed verbose logging)

  // 🔧 FIX: Add JSON serialization safety check to prevent circular reference errors
  let serializedBody: string;
  try {
    // Remove fields that backend doesn't expect
    const cleanDigest = { ...digest };
    if (cleanDigest.rawData) {
      delete cleanDigest.rawData.struggleIndicators;
      delete cleanDigest.rawData.errorTrackingData;
      delete cleanDigest.rawData.projectStructure;
    }
    // PERSISTENT AUTH: Include device ID in request
    const deviceId = await getDeviceId(context);
    serializedBody = JSON.stringify({ sessionId, digest: cleanDigest, deviceId });
  } catch (jsonError) {
    console.error('[FROLIC] JSON serialization failed - circular reference detected:', jsonError);
    throw new Error(`JSON_SERIALIZATION_ERROR: ${jsonError instanceof Error ? jsonError.message : 'Unknown error'}`);
  }

  try {
    const res = await fetchWithTimeout(apiUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
        'User-Agent': 'VSCode-Frolic-Extension/1.1.1'
      },
      body: serializedBody
    }, 30000); // 30 second timeout

    if (res.ok) {
      // Successfully sent digest - try to process any queued offline digests
      if (offlineDigestQueue.length > 0) {
        console.log('[FROLIC] Digest sent successfully, processing offline queue');
        processOfflineDigestQueue(context).catch(error => {
          console.log('[FROLIC] Error processing offline queue:', error.message);
        });
      }
      return await res.json();
    }

    if (!res.ok) {
      const errorText = await res.text();
      
      // Handle specific HTTP status codes
      if (res.status === 429) {
        // Rate limiting - don't treat as auth failure, just wait and retry
        console.log('[FROLIC] Rate limited by server:', {
          status: res.status,
          error: errorText,
          retryAfter: res.headers.get('Retry-After') || 'unknown'
        });
        
        // Extract retry-after header or default to 60 seconds
        const retryAfter = parseInt(res.headers.get('Retry-After') || '60', 10);
        const waitTime = Math.min(retryAfter * 1000, 120000); // Cap at 2 minutes
        
        console.log(`[FROLIC] Waiting ${waitTime}ms due to rate limiting`);
        
        // Queue digest for offline processing instead of blocking
        queueDigestForOfflineProcessing(sessionId, digest);
        
        // Show user-friendly message
        vscode.window.setStatusBarMessage(
          `$(clock) Frolic: Rate limited, queued for retry in ${Math.round(waitTime/1000)}s`,
          waitTime
        );
        
        // Process the queue after waiting
        setTimeout(() => {
          processOfflineDigestQueue(context).catch(error => {
            console.log('[FROLIC] Error processing rate limit queue:', error.message);
          });
        }, waitTime);
        
        return { queued: true, reason: 'rate_limited', retryAfter: waitTime };
      } else if (res.status === 401 || (res.status === 403 && errorText.includes('token is expired'))) {
        // Backend rejected token - implement smart retry logic before clearing
        console.log('[FROLIC] Backend rejected token with 401/403:', {
          status: res.status,
          error: errorText,
          tokenLength: accessToken.length,
          tokenExpiry: getTokenExpirationTime(accessToken),
          isLocallyExpired: isTokenExpired(accessToken)
        });
        
        // Implement retry logic with exponential backoff before clearing tokens
        const MAX_RETRY_ATTEMPTS = 3;
        const RETRY_DELAY_MS = 1000;
        
        for (let attempt = 1; attempt <= MAX_RETRY_ATTEMPTS; attempt++) {
          console.log(`[FROLIC] Auth retry attempt ${attempt}/${MAX_RETRY_ATTEMPTS}`);
          
          // Clear access token to force refresh on next attempt
          await context.secrets.delete('frolic.accessToken');
          
          // Wait with exponential backoff (except on first attempt)
          if (attempt > 1) {
            const delay = RETRY_DELAY_MS * Math.pow(2, attempt - 2);
            console.log(`[FROLIC] Waiting ${delay}ms before retry`);
            await new Promise(resolve => setTimeout(resolve, delay));
          }
          
          // Try to get a fresh token
          const newToken = await getValidAccessToken(context);
          if (newToken && newToken !== accessToken) {
            console.log('[FROLIC] Got fresh token, retrying digest upload...');
            
            // Retry the request with new token (reuse the already-serialized body)
            const retryRes = await fetchWithTimeout(apiUrl, {
              method: 'POST',
              headers: {
                'Authorization': `Bearer ${newToken}`,
                'Content-Type': 'application/json',
                'User-Agent': 'VSCode-Frolic-Extension/1.1.1'
              },
              body: serializedBody
            }, 30000);
            
            if (retryRes.ok) {
              console.log('[FROLIC] Digest uploaded successfully after token refresh (attempt ' + attempt + ')');
              return await retryRes.json();
            } else {
              const retryErrorText = await retryRes.text();
              console.log(`[FROLIC] Retry ${attempt} failed: ${retryRes.status} ${retryErrorText}`);
              
              // Continue to next attempt unless this was the last one
              if (attempt === MAX_RETRY_ATTEMPTS) {
                // Check network connectivity before giving up
                const hasNetwork = await checkNetworkConnectivity();
                
                if (!hasNetwork) {
                  console.log('[FROLIC] No network connectivity - queueing digest for later');
                  // Queue for offline processing instead of failing
                  queueDigestForOfflineProcessing(sessionId, digest);
                  // Show non-intrusive notification
                  vscode.window.setStatusBarMessage(
                    '$(cloud-offline) Frolic: Working offline, will sync when reconnected',
                    10000
                  );
                  return { queued: true };
                } else if (retryRes.status === 401) {
                  // PERSISTENT AUTH: Don't clear tokens immediately
                  console.log('[FROLIC] All retry attempts failed with 401 - entering degraded mode');
                  updateStatusBar('offline'); // Show offline mode instead of unauthenticated
                  
                  // Queue digest for later retry
                  queueDigestForOfflineProcessing(sessionId, digest);
                  
                  // Check if token is expired beyond grace period
                  const tokenExpired = await isTokenExpiredBeyondGracePeriod(context);
                  if (tokenExpired) {
                    console.log('[FROLIC] Token expired beyond grace period - user needs to re-authenticate');
                    updateStatusBar('needs-reauth');
                  }
                  
                  return { queued: true, authDegraded: true };
                }
                throw new Error('AUTH_DEGRADED');
              }
            }
          } else if (attempt === MAX_RETRY_ATTEMPTS) {
            console.log('[FROLIC] Could not refresh token after all attempts');
            // PERSISTENT AUTH: Don't clear tokens, enter degraded mode
            updateStatusBar('offline');
            queueDigestForOfflineProcessing(sessionId, digest);
            return { queued: true, authDegraded: true };
          }
        }
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

    // Success
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

/**
 * Create a text-based progress bar
 */
function createProgressBar(percentage: number): string {
    // Ensure percentage is between 0 and 100
    const safePercentage = Math.max(0, Math.min(100, percentage));
    const filled = Math.round(safePercentage / 10);
    const empty = 10 - filled;
    return '█'.repeat(filled) + '░'.repeat(empty);
}

/**
 * Fetch skills data from the API
 */
async function fetchSkillsData(context: vscode.ExtensionContext): Promise<any[]> {
  const apiBaseUrl = getApiBaseUrl();
  console.log('[FROLIC] Skills API base URL:', apiBaseUrl);
  
  // Check for API key first (new auth method)
  const apiKey = await context.secrets.get('frolic.apiKey');
  if (apiKey) {
    console.log('[FROLIC] Using API key for skills fetch');
    
    try {
      const response = await fetchWithTimeout(`${apiBaseUrl}/api/skills/public`, {
        method: 'GET',
        headers: {
          'x-api-key': apiKey,
          'Content-Type': 'application/json',
          'User-Agent': 'VSCode-Frolic-Extension/1.2.6-rc2'
        }
      }, 30000);
      
      if (response.ok) {
        const data = await response.json();
        console.log('[FROLIC] Skills data fetched via API key');
        return data.data || [];
      }
      
      if (response.status === 401) {
        // Invalid API key
        await context.secrets.delete('frolic.apiKey');
        updateStatusBar('unauthenticated');
        throw new Error('Invalid API key');
      }
      
      const errorText = await response.text();
      throw new Error(`Failed to fetch skills: ${response.status} - ${errorText}`);
    } catch (error: any) {
      console.error('[FROLIC] Error fetching skills with API key:', error);
      throw error;
    }
  }
  
  // Fall back to OAuth method
  const accessToken = await getValidAccessToken(context);
  
  if (!accessToken) {
    console.error('[FROLIC] No access token available for skills fetch');
    throw new Error('Not authenticated');
  }
  
  console.log('[FROLIC] Fetching from:', `${apiBaseUrl}/api/skills`);
  
  try {
    const response = await fetchWithTimeout(`${apiBaseUrl}/api/skills`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
        'User-Agent': 'VSCode-Frolic-Extension/1.2.6-rc2'
      }
    }, 30000);
    
    console.log('[FROLIC] Skills API response status:', response.status);
    
    if (!response.ok) {
      const errorText = await response.text();
      console.error('[FROLIC] Skills API error response:', response.status, errorText);
      
      if (response.status === 401 || response.status === 403) {
        // Try to refresh token
        console.log('[FROLIC] Auth error on skills endpoint, attempting token refresh...');
        const refreshToken = await context.secrets.get('frolic.refreshToken');
        if (refreshToken) {
          const newToken = await performTokenRefresh(context, refreshToken);
          if (newToken) {
            console.log('[FROLIC] Token refreshed successfully, retrying skills fetch...');
            // Retry with new token
            const retryResponse = await fetchWithTimeout(`${apiBaseUrl}/api/skills`, {
              method: 'GET',
              headers: {
                'Authorization': `Bearer ${newToken}`,
                'Content-Type': 'application/json',
                'User-Agent': 'VSCode-Frolic-Extension/1.1.1'
              }
            }, 30000);
            
            console.log('[FROLIC] Retry response status:', retryResponse.status);
            
            if (retryResponse.ok) {
              const data = await retryResponse.json();
              console.log('[FROLIC] Skills data after retry:', data);
              return data.data || [];
            } else {
              const retryError = await retryResponse.text();
              console.error('[FROLIC] Skills retry failed:', retryResponse.status, retryError);
              throw new Error(`Skills API error after retry: ${retryResponse.status} - ${retryError}`);
            }
          } else {
            console.error('[FROLIC] Token refresh returned null');
          }
        } else {
          console.error('[FROLIC] No refresh token available');
        }
        throw new Error(`Authentication failed: ${response.status} - ${errorText}`);
      }
      throw new Error(`Failed to fetch skills: ${response.status} - ${errorText}`);
    }
    
    const data = await response.json();
    console.log('[FROLIC] Skills API success, data structure:', {
      success: data.success,
      dataLength: data.data?.length,
      firstSkill: data.data?.[0]
    });
    return data.data || [];
  } catch (error: any) {
    console.error('[FROLIC] Error fetching skills:', error.message || error);
    console.error('[FROLIC] Full error:', error);
    throw error;
  }
}


