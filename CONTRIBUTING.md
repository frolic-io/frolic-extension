# Contributing to Frolic VS Code Extension

Thank you for your interest in contributing to Frolic! We welcome contributions from the community to help make our coding activity tracker even better.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:
- Be respectful and inclusive
- Welcome newcomers and help them get started
- Focus on constructive criticism
- Respect differing viewpoints and experiences

## How to Contribute

### Reporting Bugs

1. Check if the issue already exists in our [GitHub Issues](https://github.com/frolic-io/frolic-extension/issues)
2. If not, create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - VS Code version and OS
   - Frolic extension version

### Suggesting Features

1. Check existing issues for similar suggestions
2. Create a new issue with the `enhancement` label
3. Explain the use case and benefits
4. Be open to discussion and feedback

### Code Contributions

1. **Fork the Repository**
   ```bash
   git clone https://github.com/frolic-io/frolic-extension.git
   cd frolic-extension
   npm install
   ```

2. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

3. **Development Setup**
   - Open the project in VS Code
   - Press `F5` to launch a new VS Code window with the extension loaded
   - Make your changes and test thoroughly

4. **Code Style**
   - Use TypeScript for all new code
   - Follow existing code patterns
   - Keep functions small and focused
   - Add comments for complex logic
   - Use meaningful variable names

5. **Testing**
   - Test your changes manually
   - Ensure no existing functionality is broken
   - Test edge cases and error scenarios

6. **Commit Guidelines**
   - Use clear, descriptive commit messages
   - Format: `type: description`
   - Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`
   - Example: `feat: add privacy mode for file paths`

7. **Submit a Pull Request**
   - Push your branch to your fork
   - Create a PR against the `main` branch
   - Fill out the PR template
   - Link any related issues
   - Be responsive to review feedback

## Development Guidelines

### Architecture Overview

```
src/
├── extension.ts     # Main extension entry point (to be modularized)
├── auth/           # Authentication and token management (planned)
├── analytics/      # Event logging and digests (planned)
├── ui/            # Status bar and activity panel (planned)
└── storage/       # Backup and recovery (planned)
```

### Key Principles

1. **Privacy First**: Never collect actual code content
2. **Reliability**: Handle offline scenarios gracefully
3. **Performance**: Minimize impact on VS Code performance
4. **User Experience**: Keep notifications minimal and relevant

### Security Considerations

- Always validate and sanitize file paths
- Use VS Code's SecretStorage for sensitive data
- Never log sensitive information
- Follow OWASP guidelines for web requests

## Release Process

1. Update version in `package.json`
2. Update CHANGELOG.md
3. Create a git tag: `git tag v1.0.X`
4. Push tag: `git push origin v1.0.X`
5. GitHub Actions will build and create a release

## Getting Help

- Join our [Discord community](https://discord.gg/frolic) (coming soon)
- Check the [documentation](https://docs.frolic.io)
- Ask questions in GitHub Issues

## Recognition

Contributors will be recognized in:
- Release notes
- README.md contributors section
- Our website (with permission)

Thank you for helping make Frolic better for everyone! 🎉