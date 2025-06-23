# Frolic

Personalized vibe-learning newsletter powered by your coding sessions — learn from how you code, not just what you build.

## ✨ Features

### 📊 **Activity Insights (No Sign-in Required)**
- **Real-time Activity Panel**: View your coding session stats, file changes, and productivity metrics right in VS Code's sidebar
- **Session Tracking**: Monitor your current coding session duration and activity levels
- **File & Language Analytics**: See which files and programming languages you're working with most
- **Learning Pattern Detection**: Track coding behavior patterns including:
  - Struggle indicators (rapid undo/redo, long pauses)
  - Error and debugging patterns (via VS Code diagnostics)
  - AI collaboration patterns (detection of AI-assisted coding)
- **Event Buffering**: Track coding events with visual indicators for digest readiness
- **Local Data Export**: Export your coding activity to JSON files for personal analysis

### 🎯 **Enhanced Features (Sign-in Required)**
- **Personalized Coding Recaps**: Get AI-powered insights about your coding journey delivered to your inbox
- **Smart Digest Generation**: Automatically curated summaries of your coding patterns and achievements
- **Learning Analytics**: Advanced insights including:
  - Struggle pattern analysis and learning difficulty detection
  - Error resolution progression tracking
  - AI collaboration effectiveness measurements
  - Conceptual learning progression analysis
- **Cross-session Analytics**: Track progress across multiple coding sessions and projects
- **Newsletter Delivery**: Receive daily insights tailored to your unique coding style and learning patterns

### 🔒 **Privacy & Control**
- **Privacy-First Design**: All data stays local until you explicitly sign in and opt-in
- **Configurable & Lightweight**: Fine-tune settings to match your preferences
- **Always Useful**: The activity panel provides valuable insights even without an account

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
2. **View activity** - Check the Frolic panel in VS Code's Explorer sidebar for immediate insights
3. **Optional: Sign in** - Use Command Palette → `Frolic: Sign In` to unlock personalized recaps and newsletter features

### Without Sign-in
Frolic provides valuable insights right away:
- **Session metrics**: See your current coding session duration and activity
- **File analytics**: Track which files and languages you're working with
- **Event tracking**: Monitor your coding activity with visual indicators
- **Local export**: Export your data anytime for personal analysis

### With Sign-in
Unlock additional features:
- **Personalized newsletters**: AI-generated insights delivered to your inbox
- **Advanced analytics**: Cross-session tracking and pattern recognition
- **Smart digests**: Curated summaries of your coding achievements

### Commands
- `Frolic: Sign In` - Connect to get personalized coding recaps
- `Frolic: Send Digest Now` - Manually send your coding activity (requires sign-in)
- `Frolic: Flush Logs` - Export activity data to local `.frolic-log.json` file

## ⚙️ Configuration

| Setting | Description | Default |
|---------|-------------|---------|
| `frolic.enableLogging` | Enable/disable activity logging | `true` |
| `frolic.apiBaseUrl` | API endpoint for Frolic services | `https://getfrolic.dev` |
| `frolic.digestFrequencyHours` | How often to send activity digests | `0.75` hours (45 minutes) |
| `frolic.maxBufferSize` | Maximum events to keep in memory | `10000` |
| `frolic.maxMemoryMB` | Memory limit for activity buffer | `50` MB |
| `frolic.tokenExpiration` | Authentication token preference | `long` |

## ✅ Requirements

- VS Code `v1.85.0` or higher

## 🐛 Known Issues

None at the moment! If you encounter any issues, please report them at our [GitHub Issues](https://github.com/frolic-io/frolic-extension/issues) page.

## 🗒️ Release Notes

### 1.0.16 (December 2024) 🆕

- **Learning Struggle Detection**: Track rapid undo/redo patterns, long pauses, and frequent file switching
- **Error and Debugging Analytics**: Monitor VS Code diagnostic events and error resolution patterns
- **Enhanced AI Collaboration Tracking**: Improved detection of AI-assisted coding and refinement patterns
- **Advanced Session Intelligence**: Better session boundary detection and coding pattern analysis
- **Complete Educational Data Capture**: Comprehensive behavioral analysis for personalized learning insights

### 1.0.15

- Enhanced notification UX with reduced frequency
- Advanced token management with proactive refresh
- Beautiful email templates with dark theme design
- Automated daily digest processing

### 1.0.0

- Initial release with comprehensive activity logging
- Personalized coding recaps delivered to your inbox
- Privacy-first design with local-only logging by default
- Smart development/production environment detection
- Activity dashboard and status bar integration
- Configurable settings for buffer management and digest frequency

## 🔒 Privacy & Data Collection

**We take your privacy seriously.** Here's exactly what Frolic does:

### What We Collect (Only When You Sign In)
- **File activity**: Which files you edit, programming languages used, lines of code changed
- **Coding patterns**: When you code, how long you spend on different files, project structure
- **Learning behavior patterns**: 
  - Rapid undo/redo sequences (struggle detection)
  - Long pauses between coding actions (thinking time analysis)
  - Frequent file switching patterns (context switching behavior)
  - Error and debugging patterns (diagnostic events from VS Code)
- **AI collaboration patterns**: Detection of AI-assisted code generation and human refinement patterns
- **Session characteristics**: Coding session duration, intensity, and focus patterns
- **No personal code**: We never collect the actual content of your code, only metadata about your activity
- **Account info**: Name and email address (only if you sign up for coding recaps)

### Specific Events We Track
- **File operations**: Open, close, save, edit events
- **VS Code diagnostics**: Error/warning events (not the error content, just patterns)
- **Timing patterns**: Pauses between actions, session duration, editing intensity
- **Undo/redo actions**: Frequency and patterns (struggle detection)
- **File switching**: Context switching behavior between files
- **AI detection**: Patterns suggesting AI-assisted code generation
- **Window focus**: When VS Code gains/loses focus for session boundary detection

### What We DON'T Collect
- ❌ **Actual code content** - Your code never leaves your machine
- ❌ **Keystrokes or specific text** - We don't track what you type, only that you typed
- ❌ **File contents** - Only file paths and metadata, never the actual code
- ❌ **Error message content** - Only that errors occurred, not what they said
- ❌ **Personal information** - Beyond name/email for signed-in users
- ❌ **Sensitive data** - No passwords, API keys, or confidential information

### Your Control
- **Logging is optional** - Disable anytime with `frolic.enableLogging: false`
- **Local-first design** - All data stays on your machine until you sign in
- **Data deletion** - Contact us anytime to delete your cloud data
- **Open source** - Extension code is public for full transparency

### Data Usage
- Generate personalized coding insights and recaps
- Improve the extension based on anonymous usage patterns
- **Never sold or shared** with third parties

For complete details, see our [Privacy Policy](./PRIVACY.md).

---

**Questions?** Visit [getfrolic.dev](https://getfrolic.dev) or open an issue on [GitHub](https://github.com/frolic-io/frolic-extension).