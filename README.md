# Frolic: Weekly Coding Recaps

A vibe learning tool that passively logs your coding activity and helps you reflect, grow, and improve — without breaking flow.

## ✨ Features

- **Passive Activity Logging**: Tracks file edits, languages used, and coding patterns
- **Weekly Personalized Recaps**: Get insights about your coding journey delivered to your inbox  
- **Privacy-First Design**: All data stays local until you explicitly sign in and opt-in
- **Smart Development Detection**: Automatically switches between development and production modes
- **Activity Dashboard**: View your coding activity right in VS Code's sidebar
- **Configurable & Lightweight**: Fine-tune settings to match your preferences

## 📦 Installation

### VS Code
1. Open VS Code
2. Press `Ctrl+Shift+X` (Windows/Linux) or `Cmd+Shift+X` (Mac)
3. Search for **Frolic**
4. Click **Install**

### Cursor IDE
1. Open Cursor
2. Press `Ctrl+Shift+X` (Windows/Linux) or `Cmd+Shift+X` (Mac)
3. Search for **Frolic** in the extensions marketplace
4. Click **Install**

**Alternative for Cursor:** If the extension doesn't appear in Cursor's marketplace:
1. Download the latest `.vsix` file from our [GitHub Releases](https://github.com/frolic-io/frolic-extension/releases)
2. In Cursor, press `Ctrl+Shift+P` and select "Extensions: Install from VSIX..."
3. Select the downloaded `.vsix` file

## 🚀 Usage

### Getting Started
1. **Install the extension** - Frolic starts logging automatically (locally only)
2. **Sign in** (optional) - Use Command Palette → `Frolic: Sign In` to enable weekly recaps
3. **View activity** - Check the Frolic panel in VS Code's Explorer sidebar

### Commands
- `Frolic: Sign In` - Connect to get personalized weekly recaps
- `Frolic: Send Digest Now` - Manually send your coding activity (requires sign-in)
- `Frolic: Flush Logs` - Save activity data to local file

## ⚙️ Configuration

| Setting | Description | Default |
|---------|-------------|---------|
| `frolic.enableLogging` | Enable/disable activity logging | `true` |
| `frolic.apiBaseUrl` | API endpoint (auto-detects dev/prod) | `https://getfrolic.io` |
| `frolic.digestFrequencyHours` | How often to send activity digests | `24` hours |
| `frolic.maxBufferSize` | Maximum events to keep in memory | `10000` |
| `frolic.maxMemoryMB` | Memory limit for activity buffer | `50` MB |
| `frolic.tokenExpiration` | Authentication token preference | `long` |

## ✅ Requirements

- VS Code `v1.85.0` or higher

## 🐛 Known Issues

None at the moment! If you encounter any issues, please report them at our [GitHub Issues](https://github.com/frolic-io/frolic-extension/issues) page.

## 🗒️ Release Notes

### 1.0.0

- Initial release with comprehensive activity logging
- Weekly personalized coding recaps via email
- Privacy-first design with local-only logging by default
- Smart development/production environment detection
- Activity dashboard and status bar integration
- Configurable settings for buffer management and digest frequency

## 🔒 Privacy & Data Collection

**We take your privacy seriously.** Here's exactly what Frolic does:

### What We Collect (Only When You Sign In)
- **File activity**: Which files you edit, programming languages used, lines of code changed
- **Coding patterns**: When you code, how long you spend on different files, project structure
- **No personal code**: We never collect the actual content of your code, only metadata about your activity
- **Account info**: Name and email address (only if you sign up for weekly recaps)

### What We DON'T Collect
- ❌ **Actual code content** - Your code never leaves your machine
- ❌ **Keystrokes or cursor movements** - We don't track what you type or where you click
- ❌ **File contents** - Only file paths and metadata, never the actual code
- ❌ **Personal information** - Beyond name/email for signed-in users
- ❌ **Sensitive data** - No passwords, API keys, or confidential information

### Your Control
- **Logging is optional** - Disable anytime with `frolic.enableLogging: false`
- **Sign-in is optional** - Extension works locally without any account
- **Data deletion** - Contact us anytime to delete your data
- **Open source** - Extension code is public for full transparency

### Data Usage
- Generate personalized weekly coding insights and recaps
- Improve the extension based on anonymous usage patterns
- **Never sold or shared** with third parties

For complete details, see our [Privacy Policy](./PRIVACY.md).

---

**Questions?** Visit [getfrolic.io](https://getfrolic.io) or open an issue on [GitHub](https://github.com/frolic-io/frolic-extension).