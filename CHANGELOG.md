# Changelog

All notable changes to the Frolic extension will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.4] - 2025-07-17

### Fixed
- **Critical Fix**: Authentication tokens now properly track actual expiration times (~1 hour) instead of incorrectly assuming 365 days
- Fixed intermittent logout issues caused by expired tokens not being refreshed
- Users returning after lunch breaks or weekends will now have tokens automatically refreshed

### Added
- Background token refresh mechanism that checks every 5 minutes
- Proactive token refresh 5 minutes before expiry
- Health check integration to verify authentication status
- Token expiration tracking and storage
- Enhanced logging for authentication debugging

### Improved
- Better handling of expired tokens when VSCode starts up
- Automatic token refresh using long-lived refresh tokens
- More informative authentication status messages
- Seamless re-authentication without user intervention

### Technical Details
- Added `startBackgroundTokenRefresh` and `stopBackgroundTokenRefresh` functions
- Implemented token expiration storage in VSCode global state
- Added `/api/auth/vscode/health` endpoint for lightweight auth verification
- Fixed token expiration reporting in `/api/auth/vscode/token` and `/api/auth/vscode/refresh` endpoints

## [1.2.3] - 2025-07-16

### Fixed
- **Critical Fix**: Line counting now calculates NET changes (additions minus deletions) instead of counting all newlines
- Fixed inflated line counts that occurred when saving files or from file rewrites
- Added detection for file rewrites to prevent counting them as user-added lines
- `.frolic-session.json` backup file is now excluded from activity tracking
- External edits (e.g., from AI tools) are now properly tracked when saved in VS Code

### Improved
- More accurate "lines added" metrics in daily digests
- Better quality code samples in digests (no duplicate content from saves)
- Enhanced quiz generation based on actual code written, not file operations
- More relevant technology detection from real coding activity

### Technical Details
- Implemented proper line range calculation for multi-line edits
- Added file rewrite detection for operations that replace entire file contents
- Updated filtering to exclude internal extension files from tracking
- Line counting now properly handles: additions, deletions, replacements, and file rewrites

## [1.1.7] - 2025-01-14

### Fixed
- Activity panel now shows accurate "Last digest" time instead of always showing "just now"
- Session timer no longer resets to 0m after sending digests (maintains session duration)
- Fixed totalLinesAdded calculation to only count line additions, not deletions
- Session timer and last digest time now persist across VS Code restarts
- **Critical Fix**: Code changes were not being captured in digests (showing 0 lines added)
- Fixed missing `changeText` and `lineCountDelta` fields that prevented proper change tracking
- Now properly calculates line additions/deletions for each edit
- AI detection now works correctly for large code insertions

### Improved
- Better state management for activity panel display
- More accurate tracking of coding session metrics

### Technical Details
- Added proper mapping of VS Code's `contentChanges` to include all required fields for digest analysis
- Fixed field name mismatch (`text` vs `changeText`) that caused empty code samples
- Added line count delta calculation based on actual text changes

## [1.1.4] - 2025-01-12

### Added
- Skills dashboard quick pick view accessible from "Frolic Connected" status bar
- "Show more" feature displaying top 3 skills with option to expand all 10
- Skills command `frolic.openSkills` to view progress
- API integration with frolic-app skills endpoint using JWT authentication

### Changed
- Clicking "Frolic Connected" now opens skills view instead of dropdown
- Improved skills progress calculation to match web app logic
- Action buttons now appear at bottom of skills list

### Fixed
- Skills display now shows only the correct 10 skills from technical design
- Progress bar calculations now properly clamped between 0-100%
- Removed duplicate skills and incorrect skill names

## [1.1.2] - 2025-01-04

### Fixed
- Fixed critical bug where code changes were not being captured in digests
- Extension was recording empty contentChanges arrays for cursor movements and selections
- Added filter to only capture actual text changes, not cursor/selection events
- Digests now properly include code diffs in codeChangesSample array

### Improved
- Better code change tracking accuracy
- Reduced noise from non-content change events
- More reliable digest significance detection

## [1.0.15] - 2024-12-28

### Removed
- Removed all debug/test code for production release
- Removed automatic debug checks on startup
- Removed debug token command and toggle debug mode command
- Removed excessive debug notifications and modal dialogs
- Removed debug logging that was cluttering console output

### Fixed
- Status bar "Sign in to Frolic" now properly opens sign-in flow instead of debug dialog
- Cleaned up authentication flow to remove test infrastructure
- Simplified digest sending without debug notifications

## [1.0.14] - 2024-12-28

### Fixed
- Fixed authentication loop issue where status would revert to "Sign in to Frolic" after successful digest sends
- Enhanced token validation logging to debug authentication failures
- Improved activity panel authentication checks to prevent false failures
- Added comprehensive debugging for token expiration and refresh flows
- Better error handling for token refresh scenarios

### Added
- Debug mode with visual authentication status messages
- Enhanced console logging for authentication troubleshooting
- Improved token expiration time display in debug output
- Better backend token validation error handling

## [1.0.0] - 2024-03-19

### Added
- Initial release
- Basic passive logging functionality
- Configurable logging settings through VS Code settings
- Manual log flushing capability via command palette
- Automatic startup logging 