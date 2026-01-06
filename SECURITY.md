# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please send an email to security@example.com with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You should receive a response within 48 hours. If the issue is confirmed, we will:

1. Work on a fix
2. Prepare a security advisory
3. Release a patched version
4. Credit you (unless you prefer to remain anonymous)

## Security Best Practices

When using RuntimeGuard:

1. **Keep Updated**: Always use the latest version
2. **Configure Appropriately**: Set `mode` to `block` in production for critical guards
3. **Monitor Logs**: Regularly review security event logs
4. **Test Guards**: Ensure guards don't create false positives in your use case
5. **Layer Security**: RuntimeGuard is one layer - use with other security measures

## Known Limitations

- RuntimeGuard is a **detection layer**, not a prevention guarantee
- False positives and negatives are possible
- Guards are pattern-based and may be bypassed by novel techniques
- Always validate and sanitize input at the application level
