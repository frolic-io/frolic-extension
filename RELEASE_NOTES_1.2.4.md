# Frolic v1.2.4 Release Notes

## 🔐 Authentication Improvements

This release fixes critical authentication issues that were causing intermittent logouts in the VSCode extension.

### What's Fixed

- **No more unexpected logouts**: The extension now properly tracks token expiration times (~1 hour) instead of incorrectly assuming they last 365 days
- **Seamless return from breaks**: Coming back after lunch or a weekend? Your session will automatically refresh without requiring a new sign-in
- **Better reliability**: Background token refresh runs every 5 minutes to ensure you stay authenticated

### Key Features

- ✅ Automatic token refresh when returning to VSCode after breaks
- ✅ Proactive refresh 5 minutes before token expiry
- ✅ Health check integration for better auth reliability
- ✅ Enhanced logging to help debug any auth issues

### Technical Details

- Fixed API endpoints to return actual token expiration times
- Added background refresh mechanism with proper error handling
- Implemented token expiration storage and tracking
- Added lightweight health check endpoint for auth verification

### Installation

**VS Code**: Update through the Extensions panel or install from [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=frolic-io.frolic)

**Cursor**: Download `frolic-1.2.4-cursor.vsix` and install:
1. Open Cursor → `Cmd+Shift+P`
2. Type: `Extensions: Install from VSIX...`
3. Select the downloaded file

### Next Steps

After updating, you should experience:
- Fewer authentication prompts
- Consistent sessions across VSCode restarts
- Automatic recovery after network interruptions

If you experience any issues, please report them on our [GitHub Issues](https://github.com/frolic-io/frolic-extension/issues) page.