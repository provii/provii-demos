# Security Policy

## Overview

This repository contains demo applications for the Provii zero knowledge proof age verification service. These demos are intended for educational and testing purposes. They are not intended for production use. We appreciate responsible disclosure of vulnerabilities.

Production deployments should use proper authentication and authorisation mechanisms, implement rate limiting and DoS protection, store private keys in secure key management systems (HSM, KMS), validate all inputs rigorously, implement logging and monitoring, and follow your organisation's security policies and compliance requirements. Never expose private keys in source code, logs, or environment variables.

## Scope

The following are in scope for vulnerability reports:

- All backend demo implementations (Cloudflare Workers, Node.js, Go, Python)
- The demo-web-provii-agegate Worker (over.provii.app, under.provii.app, playground.provii.app)
- Mobile demo applications (iOS, Android, Flutter, React Native)
- The provii-provenance
- Build and CI/CD pipeline configuration
- Documentation that could lead to insecure implementations

The following are out of scope:

- The sandbox environment and sandbox credentials (these are intentionally public)
- Third-party dependencies (report upstream)
- Social engineering attacks against maintainers
- Denial of service against demo deployments

## Supported Versions

Only the latest commit on the main branch is supported. This is a demo repository without versioned releases. Security patches are applied to main and deployed immediately.

## Reporting a Vulnerability

### For Critical or High Severity

Do not create a public GitHub issue. Email us at security@provii.app with a description of the vulnerability, steps to reproduce, potential impact, and any suggested fixes.

You can also create a [private security advisory](https://github.com/provii-id/provii-demos/security/advisories/new) on GitHub.

### For Medium or Low Severity

Create a [private security advisory](https://github.com/provii-id/provii-demos/security/advisories/new) on GitHub. Provide detailed reproduction steps and include any relevant code snippets or screenshots.

### Encrypted Communication

For sensitive vulnerability details, encrypt your email using our PGP public key. The key fingerprint and full public key are published at https://provii.app/.well-known/pgp-key.txt. You may also reach us via Signal at the number listed on that page.

### Response Timeline

| Stage | Timeline |
|-------|----------|
| Initial acknowledgement | Within 48 hours |
| Status update with triage | Within 5 business days |
| Critical severity fix | 24 to 72 hours |
| High severity fix | 7 days |
| Medium severity fix | 30 days |
| Low severity fix | 90 days |

### Coordinated Disclosure

We follow a 90-day coordinated disclosure window. If we have not resolved the issue within 90 days of your initial report, you may publicly disclose the vulnerability. We ask that you give us reasonable notice before public disclosure so we can coordinate the release of a fix.

## Safe Harbour

Maelstrom AI Pty Ltd will not pursue legal action against security researchers who act in good faith and within the scope defined above. Good faith means making a reasonable effort to avoid privacy violations, data destruction, and service disruption during your research. If you accidentally cause disruption, stop immediately and report it.

We consider security research conducted in accordance with this policy to be authorised under applicable computer fraud laws, and we will not initiate legal claims against researchers who comply with this policy.

## Security Best Practices for Demo Usage

### Backend Demos (Node.js, Cloudflare Workers, Go, Python)

Never use sandbox credentials in production. The sandbox Ed25519 keys are publicly known. Generate your own keys through the Provii Admin Portal.

Use environment variables or secret management services for private keys. Never commit keys to version control. Rotate keys regularly. The demos include basic input validation. Add thorough input validation for production deployments.

Always use TLS in production. The demos run on HTTP for local development only.

### Mobile App Demos (Android, iOS, React Native, Flutter)

Do not ship with hardcoded backend URLs. Configure them through proper configuration management and use different URLs for development, staging, and production.

Use platform-specific secure storage (Keychain on iOS, Keystore on Android) rather than storing sensitive data in plain text. Enable code obfuscation (ProGuard/R8 for Android) and consider additional app hardening measures.

### Web Demo (provii-agegate)

The demo includes basic CSP headers. Customise CSP for your production environment. Ensure requests come from expected origins and implement proper CORS policies.

## Known Security Considerations

### Sandbox Environment

The sandbox environment uses publicly documented credentials. Sandbox issuer IDs and keys are for testing only and must never be used in production. Sandbox data may be periodically reset.

### Deep Links

The demos use deep links (https://provii.app/) for app-to-app communication. Deep links should be validated before processing. Use Universal Links (iOS) or App Links (Android) and implement proper intent/URL validation in production.

## Security Scanning

This repository uses automated security scanning:

| Tool | Purpose |
|-------|---------|
| Semgrep | Static analysis for security vulnerabilities |
| Gitleaks | Secret detection in code and git history |
| Trivy | Dependency vulnerability scanning |
| CodeQL | GitHub semantic code analysis |
| npm audit / pip-audit / govulncheck | Language-specific dependency audits |

## Contact

For security-related inquiries:

- Email: security@provii.app
- Security advisories: [GitHub Security Advisories](https://github.com/provii-id/provii-demos/security/advisories)

For general support:

- Documentation: https://docs.provii.app
- Support: support@provii.app

## Acknowledgements

We thank all security researchers who responsibly disclose vulnerabilities. Contributors who report valid security issues will be acknowledged (with their permission) in our security hall of fame.
