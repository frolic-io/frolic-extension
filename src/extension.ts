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
let bufferMemoryUsage = 0; // Track estimated memory usage in bytes
let statusBarItem: vscode.StatusBarItem;
let activityProvider: FrolicActivityProvider | undefined;
let extensionContext: vscode.ExtensionContext | undefined;

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

// 🔄 PHASE 2.1: Smart Notification Throttling - Global state
let lastNotificationTime = 0;
let digestsSentSinceLastNotification = 0;

// 🔄 ENHANCED: Background token refresh management
let backgroundTokenRefreshTimer: NodeJS.Timeout | null = null;
const TOKEN_REFRESH_CHECK_INTERVAL = 30 * 60 * 1000; // Check every 30 minutes

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

// Thresholds for struggle detection
const RAPID_UNDO_REDO_THRESHOLD = 5; // 5 undo/redo actions within 30 seconds
const RAPID_UNDO_REDO_TIME_WINDOW = 30 * 1000; // 30 seconds
const LONG_PAUSE_THRESHOLD = 2 * 60 * 1000; // 2 minutes
const FREQUENT_SWITCHING_THRESHOLD = 8; // 8 file switches within 2 minutes
const FREQUENT_SWITCHING_TIME_WINDOW = 2 * 60 * 1000; // 2 minutes
const ERROR_HEAVY_SESSION_THRESHOLD = 10; // 10+ errors in a file

function getNotificationThrottleMs(): number {
    const config = vscode.workspace.getConfiguration('frolic');
    const hours = config.get<number>('notificationFrequencyHours', 2);
    return hours * 60 * 60 * 1000; // Convert hours to milliseconds
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
        cursorPosition: activeEditor?.selection.active,
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
    if (LOG_BUFFER.length >= 50 && LOG_BUFFER.length % 25 === 0) {
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

    // Update status bar to reflect current event count
    // Only update if status bar is already in authenticated state
    if (statusBarItem && statusBarItem.text.includes('$(check) Frolic')) {
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
      const url = config.get<string>('apiBaseUrl') || 'https://www.getfrolic.io';
  
  // Log the URL for debugging
  console.log('[FROLIC] getApiBaseUrl() returning:', url);
  
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
  
  console.log('[FROLIC] getValidAccessToken called:', {
    hasAccessToken: !!accessToken,
    hasRefreshToken: !!refreshToken,
    accessTokenLength: accessToken?.length || 0
  });
  
  // If no access token, check if we have refresh token
  if (!accessToken) {
    if (refreshToken) {
      console.log('[FROLIC] No access token but refresh token exists, attempting refresh');
      return await performTokenRefresh(context, refreshToken);
    }
    console.log('[FROLIC] No access token and no refresh token available');
    return null;
  }
  
  // Check if access token is expired by trying to decode it
  if (isTokenExpired(accessToken)) {
    console.log('[FROLIC] Access token is expired, attempting refresh');
    if (refreshToken) {
      return await performTokenRefresh(context, refreshToken);
    } else {
      console.log('[FROLIC] No refresh token available, user needs to re-authenticate');
      await context.secrets.delete('frolic.accessToken');
      return null;
    }
  }
  
  console.log('[FROLIC] Access token is valid, returning it');
  return accessToken;
}

/**
 * Perform token refresh with race condition protection
 */
async function performTokenRefresh(context: vscode.ExtensionContext, refreshToken: string): Promise<string | null> {
  // If already refreshing, wait for the existing refresh to complete
  if (isRefreshing && refreshPromise) {
    console.log('[FROLIC] Token refresh already in progress, waiting...');
    return await refreshPromise;
  }
  
  // Start new refresh
  isRefreshing = true;
  refreshPromise = refreshAccessToken(context, refreshToken);
  
  try {
    const result = await refreshPromise;
    return result;
  } finally {
    isRefreshing = false;
    refreshPromise = null;
  }
}

/**
 * Clear all authentication tokens and reset auth state
 */
async function clearAllAuthTokens(context: vscode.ExtensionContext): Promise<void> {
  console.log('[FROLIC] Clearing all authentication tokens');
  await context.secrets.delete('frolic.accessToken');
  await context.secrets.delete('frolic.refreshToken');
  
  // Reset any ongoing refresh state
  isRefreshing = false;
  refreshPromise = null;
  
  // 🔄 ENHANCED: Stop background token refresh when clearing tokens
  stopBackgroundTokenRefresh();
}

/**
 * Check if a JWT token is expired (without verifying signature)
 */
function isTokenExpired(token: string): boolean {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      console.log('[FROLIC] Token validation failed: Invalid JWT format (not 3 parts)');
      return true;
    }
    
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    const now = Math.floor(Date.now() / 1000);
    
    if (!payload.exp) {
      console.log('[FROLIC] Token validation: No expiration claim found, treating as valid');
      return false; // No expiration claim means token doesn't expire
    }
    
    const timeUntilExpiry = payload.exp - now;
    // 🔄 FIXED: Only treat as expired if actually expired, not proactively
    const isExpired = payload.exp < now;
    
    console.log('[FROLIC] Token validation check:', {
      exp: payload.exp,
      expDate: new Date(payload.exp * 1000).toISOString(),
      now: now,
      nowDate: new Date(now * 1000).toISOString(),
      timeUntilExpiry: timeUntilExpiry,
      timeUntilExpiryMinutes: Math.round(timeUntilExpiry / 60),
      isExpired: isExpired
    });
    
    // Return true ONLY if actually expired
    return isExpired;
  } catch (err) {
    console.log('[FROLIC] Error checking token expiration:', err);
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
 * Check if token should be proactively refreshed (within 10 minutes of expiry)
 */
function shouldProactivelyRefreshToken(token: string): boolean {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    if (!payload.exp) return false;
    
    const now = Math.floor(Date.now() / 1000);
    const timeUntilExpiry = payload.exp - now;
    const PROACTIVE_REFRESH_BUFFER = 10 * 60; // 10 minutes in seconds
    
    // Only refresh if token expires within 10 minutes but is not yet expired
    const needsProactiveRefresh = timeUntilExpiry <= PROACTIVE_REFRESH_BUFFER && timeUntilExpiry > 0;
    
    if (needsProactiveRefresh) {
      console.log('[FROLIC] Token expires in', Math.round(timeUntilExpiry / 60), 'minutes - scheduling proactive refresh');
    }
    
    return needsProactiveRefresh;
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
    
    if (!accessToken || !refreshToken) {
      console.log('[FROLIC] Background refresh: No tokens available, skipping');
      return;
    }
    
    // Check if token needs proactive refresh (within 10 minutes of expiry)
    const shouldRefreshProactively = shouldProactivelyRefreshToken(accessToken);
    
    if (isTokenExpired(accessToken)) {
      console.log('[FROLIC] Background refresh: Token is expired, performing emergency refresh...');
      const newToken = await performTokenRefresh(context, refreshToken);
      if (newToken) {
        console.log('[FROLIC] Background refresh: Successfully refreshed expired token');
      } else {
        console.log('[FROLIC] Background refresh: Failed to refresh expired token');
      }
    } else if (shouldRefreshProactively) {
      console.log('[FROLIC] Background refresh: Token expires soon, performing proactive refresh...');
      const newToken = await performTokenRefresh(context, refreshToken);
      if (newToken) {
        console.log('[FROLIC] Background refresh: Successfully refreshed token proactively');
      } else {
        console.log('[FROLIC] Background refresh: Failed proactive refresh, will retry later');
      }
    } else {
      console.log('[FROLIC] Background refresh: Token still valid, no refresh needed');
    }
  } catch (err) {
    console.log('[FROLIC] Background refresh error:', err);
  }
}

/**
 * Start background token refresh timer
 */
function startBackgroundTokenRefresh(context: vscode.ExtensionContext): void {
  if (backgroundTokenRefreshTimer) {
    clearInterval(backgroundTokenRefreshTimer);
  }
  
  console.log('[FROLIC] Starting background token refresh (every 30 minutes)');
  backgroundTokenRefreshTimer = setInterval(() => {
    performBackgroundTokenRefresh(context).catch(err => {
      console.log('[FROLIC] Background token refresh failed:', err);
    });
  }, TOKEN_REFRESH_CHECK_INTERVAL);
  
  // Also perform initial check after 5 minutes
  setTimeout(() => {
    performBackgroundTokenRefresh(context).catch(err => {
      console.log('[FROLIC] Initial background token refresh failed:', err);
    });
  }, 5 * 60 * 1000);
}

/**
 * Stop background token refresh timer
 */
function stopBackgroundTokenRefresh(): void {
  if (backgroundTokenRefreshTimer) {
    clearInterval(backgroundTokenRefreshTimer);
    backgroundTokenRefreshTimer = null;
    console.log('[FROLIC] Stopped background token refresh');
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
    
    console.log('[FROLIC] Access token refreshed and validated successfully');
    updateStatusBar('authenticated');
    
    // 🔄 ENHANCED: Start background token refresh after successful refresh
    startBackgroundTokenRefresh(context);
    
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
          type: change.textLength > change.rangeLength ? 'addition' : 'modification',
          // 🔄 PHASE 2.1: Enhanced AI collaboration detection
          aiCollaborationSignals: detectAICollaborationPatterns(changeText, change)
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
  console.log('[FROLIC] Starting enhanced sign-in flow...');
  
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
    
    // Build auth URL
    const authUrl = `${apiBaseUrl}/api/auth/vscode/start?state=${state}&code_challenge=${codeChallenge}&token_type=${tokenExpiration}`;
    
    // Debug: Log the URL being used
    console.log(`[FROLIC] Auth URL constructed: ${authUrl}`);
    
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
      
      // Store tokens securely with detailed logging
      console.log('[FROLIC SIGNIN] About to store access token, length:', accessToken?.length);
      await context.secrets.store('frolic.accessToken', accessToken);
      
      // Immediately verify access token storage
      console.log('[FROLIC SIGNIN] Verifying access token storage...');
      const storedAccessToken = await context.secrets.get('frolic.accessToken');
      const accessTokenStored = storedAccessToken === accessToken;
      console.log('[FROLIC SIGNIN] Access token verification:', {
        stored: !!storedAccessToken,
        matches: accessTokenStored,
        originalLength: accessToken?.length || 0,
        storedLength: storedAccessToken?.length || 0
      });
      
      if (refreshToken) {
        console.log('[FROLIC SIGNIN] About to store refresh token, length:', refreshToken?.length);
        await context.secrets.store('frolic.refreshToken', refreshToken);
        
        // Immediately verify refresh token storage
        console.log('[FROLIC SIGNIN] Verifying refresh token storage...');
        const storedRefreshToken = await context.secrets.get('frolic.refreshToken');
        const refreshTokenStored = storedRefreshToken === refreshToken;
        console.log('[FROLIC SIGNIN] Refresh token verification:', {
          stored: !!storedRefreshToken,
          matches: refreshTokenStored,
          originalLength: refreshToken?.length || 0,
          storedLength: storedRefreshToken?.length || 0
        });
        
        if (accessTokenStored && refreshTokenStored) {
          console.log('[FROLIC SIGNIN] ✅ Both tokens stored and verified successfully');
      } else {
          console.error('[FROLIC SIGNIN] ❌ Token storage verification failed!', {
            accessTokenOK: accessTokenStored,
            refreshTokenOK: refreshTokenStored
          });
        }
      } else {
        console.log('[FROLIC SIGNIN] Only access token received (no refresh token)');
        if (!accessTokenStored) {
          console.error('[FROLIC SIGNIN] ❌ Access token storage verification failed!');
        }
      }
      
      // Clean up PKCE parameters
      await context.secrets.delete('frolic.codeVerifier');
      await context.secrets.delete('frolic.state');
      
      return { accessToken, refreshToken };
    });
    
    // Success! But let's verify tokens one more time
    console.log('[FROLIC SIGNIN] Sign-in flow completed, performing final token verification...');
    const finalAccessToken = await context.secrets.get('frolic.accessToken');
    const finalRefreshToken = await context.secrets.get('frolic.refreshToken');
    
    console.log('[FROLIC SIGNIN] Final verification results:', {
      accessToken: {
        exists: !!finalAccessToken,
        length: finalAccessToken?.length || 0,
        preview: finalAccessToken ? finalAccessToken.substring(0, 20) + '...' : 'null'
      },
      refreshToken: {
        exists: !!finalRefreshToken,
        length: finalRefreshToken?.length || 0,
        preview: finalRefreshToken ? finalRefreshToken.substring(0, 20) + '...' : 'null'
      }
    });
    
    if (!finalAccessToken) {
      console.error('[FROLIC SIGNIN] 🚨 CRITICAL: Access token is missing after sign-in!');
      vscode.window.showErrorMessage('🚨 Critical: Tokens were not saved! Please check Extension Host logs.');
      updateStatusBar('unauthenticated');
      return;
    }
    
    updateStatusBar('authenticated');
    
    // 🔄 ENHANCED: Start background token refresh after successful sign-in
    startBackgroundTokenRefresh(context);
    
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
                vscode.env.openExternal(vscode.Uri.parse('https://getfrolic.io'));
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
                const now = Date.now();
                detectFrequentFileSwitching(editor.document.fileName, now);
                
                // Log file switch action
                userActionHistory.push({
                    timestamp: now,
                    action: 'file_switch',
                    context: {
                        fileName: editor.document.fileName,
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
                const filePath = uri.fsPath;
                
                // Skip if it's a git file or other excluded path
                if (filePath.includes('.git') || filePath.startsWith('git/')) {
                    return;
                }
                
                // Determine change type
                const changeType = getDiagnosticChangeType(uri, currentDiagnostics);
                
                // Log the diagnostic change
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
        startBackgroundTokenRefresh(context);
    }

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
    const frequencyHours = config.get<number>('digestFrequencyHours', 24);
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
        // Add some jitter to prevent thundering herd if many users have same interval
        const jitter = Math.random() * 60000; // 0-1 minute random delay
        setTimeout(async () => {
            await sendDigestImmediately(context, 3, true); // Show notification for periodic digests
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
                console.log(`[FROLIC] Digest sent successfully. New session: ${sessionId}`);
                updateStatusBar('authenticated');
                
                // 🔄 PHASE 2.1: Smart notification throttling
                digestsSentSinceLastNotification++;
                const timeSinceLastNotification = Date.now() - lastNotificationTime;
                const notificationThrottleMs = getNotificationThrottleMs();
                const shouldShowNotification = showNotification && (
                    timeSinceLastNotification >= notificationThrottleMs || // Configurable hours since last
                    digestsSentSinceLastNotification >= 25 // Or 25+ digests sent (fallback)
                );
                
                if (shouldShowNotification) {
                    const message = digestsSentSinceLastNotification > 1 
                        ? `✅ Digest sent successfully! (${digestsSentSinceLastNotification} sessions processed)`
                        : `✅ Digest sent successfully! (${eventCount} events processed)`;
                    
                    vscode.window.showInformationMessage(message);
                    lastNotificationTime = Date.now();
                    digestsSentSinceLastNotification = 0; // Reset counter
                } else {
                    // Still log to console for debugging, but no popup
                    console.log(`[FROLIC] 🔇 Digest sent silently (${eventCount} events, ${digestsSentSinceLastNotification} total since last notification)`);
                }
                
                return eventCount; // Return the number of events processed
            } catch (err: any) {
                lastError = err;
                console.log(`[FROLIC] Digest send attempt ${attempt + 1}/${maxRetries + 1} failed: ${err.message}`);
                
                // Handle different error types
                if (err.message === 'NO_AUTH_TOKEN' || err.message === 'AUTH_TOKEN_EXPIRED') {
                    // Auth errors - don't retry, update status
                    console.log(`[FROLIC] Authentication error: ${err.message}. Buffer not cleared (${eventCount} events preserved).`);
                    updateStatusBar('unauthenticated');
                    return 0; // Exit without clearing buffer
                } else if (err.message === 'ACCESS_FORBIDDEN' || err.message === 'CLIENT_ERROR') {
                    // Client errors - don't retry
                    console.log(`[FROLIC] Client error: ${err.message}. Buffer not cleared (${eventCount} events preserved).`);
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
            statusBarItem.tooltip = 'Frolic: Click to sign in';
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
            statusBarItem.tooltip = 'Frolic: Connection error. Click to sign in.';
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
    private sessionStartTime: Date;
    
    constructor(private context: vscode.ExtensionContext) {
        this.sessionStartTime = new Date();
    }

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element: FrolicTreeItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: FrolicTreeItem): Thenable<FrolicTreeItem[]> {
        if (!element) {
            // Root level items with enhanced metrics
            const items: FrolicTreeItem[] = [];
            
            // Enhanced session header with logo
            const logoPath = vscode.Uri.file(path.join(this.context.extensionPath, 'images', 'frolic_logo.png'));
            const sessionDuration = Math.round((Date.now() - this.sessionStartTime.getTime()) / 1000 / 60);
            items.push(new FrolicTreeItem(
                `Frolic Session • ${sessionDuration}m`,
                vscode.TreeItemCollapsibleState.None,
                'session-header',
                undefined,
                logoPath
            ));

            // Authentication status section (NEW)
            items.push(new FrolicTreeItem(
                '🔐 Account Status',
                vscode.TreeItemCollapsibleState.Expanded,
                'auth-status'
            ));

            // Live stats section
            items.push(new FrolicTreeItem(
                '⚡ Live Stats',
                vscode.TreeItemCollapsibleState.Expanded,
                'live-stats'
            ));

            // Session overview
            items.push(new FrolicTreeItem(
                '📊 Session Overview',
                vscode.TreeItemCollapsibleState.Expanded,
                'session-overview'
            ));

            // Active files
            const activeFiles = this.getActiveFiles();
            if (activeFiles.length > 0) {
                items.push(new FrolicTreeItem(
                    `📁 Top Files (${activeFiles.length})`,
                    vscode.TreeItemCollapsibleState.Expanded,
                    'active-files'
                ));
            }

            // Insights
            items.push(new FrolicTreeItem(
                '💡 Insights',
                vscode.TreeItemCollapsibleState.Expanded,
                'insights'
            ));

            // Quick actions
            items.push(new FrolicTreeItem(
                '🚀 Quick Actions',
                vscode.TreeItemCollapsibleState.Expanded,
                'actions'
            ));

            return Promise.resolve(items);
        } 
        
        else if (element.contextValue === 'auth-status') {
            return this.getAuthStatusItems();
        }
        
        else if (element.contextValue === 'live-stats') {
            const recentActivity = this.getRecentActivity();
            const codingVelocity = this.getCodingVelocity();
            const bufferMemoryMB = (bufferMemoryUsage / 1024 / 1024).toFixed(1);
            
            return Promise.resolve([
                new FrolicTreeItem(
                    `🔥 Recent: ${recentActivity} edits/5m`,
                    vscode.TreeItemCollapsibleState.None,
                    'live-stat',
                    undefined,
                    new vscode.ThemeIcon('flame')
                ),
                new FrolicTreeItem(
                    `⚡ Velocity: ${codingVelocity}/min`,
                    vscode.TreeItemCollapsibleState.None,
                    'live-stat',
                    undefined,
                    new vscode.ThemeIcon('pulse')
                ),
                new FrolicTreeItem(
                    `💾 Buffer: ${bufferMemoryMB}MB`,
                    vscode.TreeItemCollapsibleState.None,
                    'live-stat',
                    undefined,
                    new vscode.ThemeIcon('database')
                )
            ]);
        }
        
        else if (element.contextValue === 'session-overview') {
            const totalEvents = LOG_BUFFER.length;
            const filesEdited = new Set(LOG_BUFFER.map(e => e.relativePath)).size;
            const totalLines = this.getTotalLinesChanged();
            const aiInsertions = this.getAIInsertions();

            return Promise.resolve([
                new FrolicTreeItem(
                    `📝 Events: ${totalEvents}`,
                    vscode.TreeItemCollapsibleState.None,
                    'overview-stat',
                    undefined,
                    new vscode.ThemeIcon('symbol-event')
                ),
                new FrolicTreeItem(
                    `📁 Files: ${filesEdited}`,
                    vscode.TreeItemCollapsibleState.None,
                    'overview-stat',
                    undefined,
                    new vscode.ThemeIcon('file')
                ),
                new FrolicTreeItem(
                    `📏 Lines: +${totalLines}`,
                    vscode.TreeItemCollapsibleState.None,
                    'overview-stat',
                    undefined,
                    new vscode.ThemeIcon('add')
                ),
                new FrolicTreeItem(
                    `🤖 AI Assists: ${aiInsertions}`,
                    vscode.TreeItemCollapsibleState.None,
                    'overview-stat',
                    undefined,
                    new vscode.ThemeIcon('robot')
                )
            ]);
        }
        
        else if (element.contextValue === 'active-files') {
            const activeFiles = this.getActiveFiles();
            return Promise.resolve(activeFiles.map(file => {
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
            }));
        }
        
        else if (element.contextValue === 'insights') {
            const insights = this.generateInsights();
            return Promise.resolve(insights.map(insight => 
                new FrolicTreeItem(
                    insight,
                    vscode.TreeItemCollapsibleState.None,
                    'insight',
                    undefined,
                    new vscode.ThemeIcon('lightbulb')
                )
            ));
        }
        
        else if (element.contextValue === 'actions') {
            const digestReady = LOG_BUFFER.length >= 10;
            return Promise.resolve([
                new FrolicTreeItem(
                    digestReady ? '📤 Send Digest (Ready!)' : `📤 Send Digest (${LOG_BUFFER.length}/10)`,
                    vscode.TreeItemCollapsibleState.None,
                    'action-send-digest',
                    {
                        command: 'frolic.sendDigest',
                        title: 'Send Digest Now'
                    },
                    new vscode.ThemeIcon(digestReady ? 'cloud-upload' : 'clock')
                ),
                new FrolicTreeItem(
                    '📝 Write Logs to File',
                    vscode.TreeItemCollapsibleState.None,
                    'action-write-logs',
                    {
                        command: 'frolic.writeLogsToFile',
                        title: 'Write Logs'
                    },
                    new vscode.ThemeIcon('save')
                ),
                new FrolicTreeItem(
                    '🔄 Refresh Panel',
                    vscode.TreeItemCollapsibleState.None,
                    'action-refresh',
                    {
                        command: 'frolic.refreshActivityPanel',
                        title: 'Refresh Panel'
                    },
                    new vscode.ThemeIcon('refresh')
                )
            ]);
        }

        return Promise.resolve([]);
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

    private generateInsights(): string[] {
        const insights: string[] = [];
        const languages = this.getLanguageStats();
        const topLanguage = Object.entries(languages).sort((a, b) => b[1] - a[1])[0];
        
        if (topLanguage) {
            insights.push(`🎯 Focus: ${topLanguage[0]} (${topLanguage[1]} edits)`);
        }
        
        const sessionDuration = (Date.now() - this.sessionStartTime.getTime()) / 1000 / 60;
        if (sessionDuration > 30) {
            insights.push(`🔥 Deep focus: ${Math.round(sessionDuration)}m session`);
        }
        
        const aiAssists = this.getAIInsertions();
        if (aiAssists === 0 && LOG_BUFFER.length > 10) {
            insights.push('💪 Independent coding streak!');
        } else if (aiAssists > 0) {
            insights.push(`🤖 AI-assisted development (${aiAssists})`);
        }
        
        const uniqueFiles = new Set(LOG_BUFFER.map(e => e.relativePath)).size;
        if (uniqueFiles > 5) {
            insights.push(`🌐 Multi-file project (${uniqueFiles} files)`);
        }
        
        const recentActivity = this.getRecentActivity();
        if (recentActivity > 10) {
            insights.push('🚀 High activity period!');
        }
        
        if (insights.length === 0) {
            insights.push('✨ Keep coding to see insights!');
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
            'ts': '🟦', 'tsx': '⚛️', 'js': '🟨', 'jsx': '⚛️',
            'py': '🐍', 'java': '☕', 'cpp': '⚙️', 'c': '⚙️', 'cs': '💜',
            'html': '🌐', 'css': '🎨', 'scss': '🎨', 'sass': '🎨',
            'json': '📋', 'md': '📝', 'txt': '📄', 'yml': '🔧', 'yaml': '🔧',
            'go': '🐹', 'rs': '🦀', 'php': '🐘', 'rb': '💎'
        };
        return iconMap[ext || ''] || '📄';
    }

    private async getAuthStatusItems(): Promise<FrolicTreeItem[]> {
        const accessToken = await getValidAccessToken(this.context);
        const status = accessToken ? 'authenticated' : 'unauthenticated';
        const label = status === 'authenticated' ? `✅ Signed in` : '❌ Not signed in';
        
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
  console.log(`[FROLIC] Sending digest to: ${apiUrl}`);
  
  // Try to get a valid access token (will refresh if needed)
  const accessToken = await getValidAccessToken(context);
  
  if (!accessToken) {
    console.log('[FROLIC] No valid access token available, skipping digest upload');
    throw new Error('NO_AUTH_TOKEN');
  }

  // Token validation successful (removed verbose logging)

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
        // Backend rejected token - but let's debug WHY before deleting it
        console.log('[FROLIC] Backend rejected token with 401/403:', {
          status: res.status,
          error: errorText,
          tokenLength: accessToken.length,
          tokenExpiry: getTokenExpirationTime(accessToken),
          isLocallyExpired: isTokenExpired(accessToken)
        });
        
        // Always clear the token when backend returns 401 - it's either expired or invalid
        console.log('[FROLIC] Backend returned 401 - clearing stored token to force refresh');
        await context.secrets.delete('frolic.accessToken');
        
        // Try to refresh token and retry the request once
        const newToken = await getValidAccessToken(context);
        if (newToken && newToken !== accessToken) { // Ensure we got a different token
          console.log('[FROLIC] Token refreshed, retrying digest upload...');
          
          // Retry the request with new token
          const retryRes = await fetchWithTimeout(apiUrl, {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${newToken}`,
              'Content-Type': 'application/json',
              'User-Agent': 'VSCode-Frolic-Extension/1.0.0'
            },
            body: JSON.stringify({ sessionId, digest })
          }, 30000);
          
          if (retryRes.ok) {
            console.log('[FROLIC] Digest uploaded successfully after token refresh');
            return await retryRes.json();
          } else {
            const retryErrorText = await retryRes.text();
            console.log(`[FROLIC] Retry after token refresh failed: ${retryRes.status} ${retryErrorText}`);
            
            // If the refreshed token also fails, clear everything and force re-authentication
            if (retryRes.status === 401) {
              console.log('[FROLIC] Refreshed token also rejected - clearing all auth state');
              await clearAllAuthTokens(context);
              updateStatusBar('unauthenticated');
              
              // Don't automatically prompt - this was causing the loop!
              // Just update status bar and let user manually sign in
              console.log('[FROLIC] Authentication expired. User will need to manually sign in.');
            }
            throw new Error('AUTH_TOKEN_EXPIRED');
          }
        } else {
          console.log('[FROLIC] Could not refresh token or got same token back');
          await clearAllAuthTokens(context);
          updateStatusBar('unauthenticated');
          throw new Error('AUTH_TOKEN_EXPIRED');
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

