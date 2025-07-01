# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of Frolic seriously. If you have discovered a security vulnerability, please follow these steps:

### 1. Do NOT Create a Public Issue

Security vulnerabilities should be reported privately to prevent malicious exploitation.

### 2. Email Us Directly

Send details to: security@frolic.io

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### 3. Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Based on severity
  - Critical: 1-7 days
  - High: 1-2 weeks
  - Medium: 2-4 weeks
  - Low: Next regular release

## Security Measures

### Data Collection

- We NEVER collect actual code content
- Only metadata about files and editing patterns
- All data transmission uses HTTPS
- OAuth 2.0 with PKCE for authentication

### Token Storage

- Tokens stored using VS Code's SecretStorage API
- Tokens expire after 90 days
- Automatic token rotation for active users
- Tokens invalidated after 30 days of inactivity

### Privacy Features

- Local-first approach - data stored locally by default
- Opt-in cloud synchronization
- Privacy mode available to hash file paths
- Clear data retention policies

### Third-Party Dependencies

- Regular dependency updates
- Security audit before major releases
- No dependencies with known vulnerabilities

## Security Best Practices for Contributors

1. **Never commit secrets** - Use environment variables
2. **Validate all inputs** - Especially file paths
3. **Use parameterized queries** - Prevent injection attacks
4. **Follow principle of least privilege**
5. **Log security events** - But never log sensitive data

## Vulnerability Disclosure

After a fix is released:
1. We'll publish a security advisory
2. Credit researchers (with permission)
3. Update this document with lessons learned

## Bug Bounty Program

Currently, we don't offer a formal bug bounty program, but we deeply appreciate security researchers who help us improve. We'll acknowledge your contribution in our release notes and README (with your permission).

## Contact

- Security: security@frolic.io
- General: support@frolic.io
- GitHub: https://github.com/frolic-io/frolic-extension

Thank you for helping keep Frolic secure! 🔒