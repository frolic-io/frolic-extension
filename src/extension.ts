// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

interface ActivityLog {
	timestamp: number;
	type: 'file_change' | 'cursor_move' | 'selection_change';
	file?: string;
	details: any;
}

class ActivityLogger {
	private logBuffer: ActivityLog[] = [];
	private readonly MAX_BUFFER_SIZE = 1000;
	private disposables: vscode.Disposable[] = [];
	private flushInterval: NodeJS.Timeout | undefined;
	private readonly FLUSH_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes
	private isEnabled: boolean = false;

	constructor() {
		this.loadConfig();
		this.setupConfigListener();
		this.setupEventListeners();
		this.loadExistingLogs();
		this.startFlushInterval();
	}

	private loadConfig() {
		const config = vscode.workspace.getConfiguration('frolic');
		this.isEnabled = config.get<boolean>('enableLogging', false);
		console.log(`[FROLIC] Logging ${this.isEnabled ? 'enabled' : 'disabled'} via config`);
	}

	private setupConfigListener() {
		const configDisposable = vscode.workspace.onDidChangeConfiguration((e) => {
			if (e.affectsConfiguration('frolic.enableLogging')) {
				const config = vscode.workspace.getConfiguration('frolic');
				this.isEnabled = config.get<boolean>('enableLogging', false);
				console.log(`[FROLIC] Logging ${this.isEnabled ? 'enabled' : 'disabled'} via config`);
			}
		});
		this.disposables.push(configDisposable);
	}

	private getLogFilePath(): string | undefined {
		const workspaceFolders = vscode.workspace.workspaceFolders;
		if (!workspaceFolders) return undefined;
		return path.join(workspaceFolders[0].uri.fsPath, '.frolic-log.json');
	}

	private loadExistingLogs() {
		const logFilePath = this.getLogFilePath();
		if (!logFilePath || !fs.existsSync(logFilePath)) return;

		try {
			const data = fs.readFileSync(logFilePath, 'utf8');
			this.logBuffer = JSON.parse(data);
			console.log(`[FROLIC] Loaded ${this.logBuffer.length} existing log entries`);
		} catch (error) {
			console.error('[FROLIC] Error loading existing logs:', error);
		}
	}

	private writeLogsToFile() {
		if (!this.isEnabled) return;
		
		const logFilePath = this.getLogFilePath();
		if (!logFilePath) return;

		try {
			fs.writeFileSync(logFilePath, JSON.stringify(this.logBuffer, null, 2), 'utf8');
			console.log(`[FROLIC] Logs written to ${logFilePath}`);
		} catch (error) {
			console.error('[FROLIC] Error writing logs:', error);
		}
	}

	private setupEventListeners() {
		// Track file changes
		const fileChangeDisposable = vscode.workspace.onDidChangeTextDocument(event => {
			if (!this.isEnabled) return;
			
			this.logActivity({
				timestamp: Date.now(),
				type: 'file_change',
				file: event.document.fileName,
				details: {
					changes: event.contentChanges.map(change => ({
						range: change.range,
						textLength: change.text.length
					}))
				}
			});
		});

		// Track cursor movements
		const cursorMoveDisposable = vscode.window.onDidChangeTextEditorSelection(event => {
			if (!this.isEnabled) return;
			
			this.logActivity({
				timestamp: Date.now(),
				type: 'cursor_move',
				file: event.textEditor.document.fileName,
				details: {
					selections: event.selections.map(selection => ({
						start: selection.start,
						end: selection.end
					}))
				}
			});
		});

		// Track selection changes
		const selectionChangeDisposable = vscode.window.onDidChangeTextEditorVisibleRanges(event => {
			if (!this.isEnabled) return;
			
			this.logActivity({
				timestamp: Date.now(),
				type: 'selection_change',
				file: event.textEditor.document.fileName,
				details: {
					visibleRanges: event.visibleRanges
				}
			});
		});

		this.disposables.push(fileChangeDisposable, cursorMoveDisposable, selectionChangeDisposable);
	}

	private logActivity(activity: ActivityLog) {
		if (!this.isEnabled) return;
		
		this.logBuffer.push(activity);
		
		// Maintain buffer size
		if (this.logBuffer.length > this.MAX_BUFFER_SIZE) {
			this.logBuffer = this.logBuffer.slice(-this.MAX_BUFFER_SIZE);
		}

		console.log('[FROLIC] Activity logged:', activity);
	}

	private startFlushInterval() {
		this.flushInterval = setInterval(() => {
			this.writeLogsToFile();
		}, this.FLUSH_INTERVAL_MS);
	}

	public dispose() {
		if (this.flushInterval) {
			clearInterval(this.flushInterval);
		}
		this.writeLogsToFile();
		this.disposables.forEach(d => d.dispose());
	}
}

let activityLogger: ActivityLogger;

// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed
export function activate(context: vscode.ExtensionContext) {
	console.log('✅ Frolic Logger is now active!');

	// Initialize the activity logger
	activityLogger = new ActivityLogger();

	// Register the toggle command
	const toggleCommand = vscode.commands.registerCommand('frolic.toggleLogging', async () => {
		const config = vscode.workspace.getConfiguration('frolic');
		const currentValue = config.get<boolean>('enableLogging', false);
		await config.update('enableLogging', !currentValue, true);
		vscode.window.showInformationMessage(
			`Frolic Logger ${!currentValue ? 'enabled' : 'disabled'}`
		);
	});

	// Register the logger's dispose method
	context.subscriptions.push(
		toggleCommand,
		{
			dispose: () => activityLogger.dispose()
		}
	);
}

// This method is called when your extension is deactivated
export function deactivate() {
	console.log('🛑 Frolic Logger is deactivated.');
	activityLogger?.dispose();
}
