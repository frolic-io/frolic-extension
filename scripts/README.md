# Frolic Extension Scripts

## Deployment Script

The `deploy.sh` script handles deployment to both VS Code marketplace and Cursor distribution.

### Usage

```bash
# Full deployment (recommended)
npm run deploy

# Or run directly
./scripts/deploy.sh
```

### What it does

1. **✅ Checks prerequisites** (vsce, node, npm)
2. **🔨 Compiles TypeScript** 
3. **📦 Publishes to VS Code Marketplace**
4. **📁 Creates VSIX for Cursor** (`frolic-{version}-cursor.vsix`)
5. **🚀 Optionally creates GitHub release** (if `gh` CLI is installed)

### Individual Commands

```bash
# VS Code only
npm run deploy:vscode

# Cursor VSIX only  
npm run deploy:cursor
```

### Prerequisites

- `vsce` installed globally: `npm install -g vsce`
- Logged into VS Code marketplace: `vsce login`
- Optional: GitHub CLI for releases: `brew install gh`

### Cursor Distribution

Since Cursor doesn't have a separate marketplace, users install via VSIX:

1. Download `frolic-{version}-cursor.vsix`
2. Open Cursor → `Cmd+Shift+P` → `Extensions: Install from VSIX...`
3. Select the VSIX file

Or via command line:
```bash
cursor --install-extension frolic-{version}-cursor.vsix
```

### GitHub Releases

If you have GitHub CLI installed, the script will offer to create a release with:
- 📝 Auto-generated release notes
- 📎 VSIX file attachment for Cursor users
- 🔗 Links to VS Code marketplace 