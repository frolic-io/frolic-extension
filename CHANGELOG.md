# Changelog

All notable changes to the Frolic extension will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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