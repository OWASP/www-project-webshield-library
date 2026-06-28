# Security Policy

## Supported Versions

OWL is in `1.x` stable release mode.

Supported security update policy:

- Latest `1.x` release: full security fixes
- Previous `1.x` release line: best-effort critical fixes
- `0.x` releases: no longer supported

## Reporting a Vulnerability

Please do not open public issues for security vulnerabilities.

Report privately with:

- Affected module (A01-A10)
- Description and impact
- Reproduction steps or PoC
- Suggested mitigation (if known)

Use one of these channels:

- Security email: cybersreejith@gmail.com
- GitHub Security Advisories: https://github.com/OWASP/www-project-webshield-library/security/advisories

## Response Process

- Initial acknowledgment target: within 72 hours
- Triage and severity assessment
- Fix development and validation
- Coordinated disclosure with release notes

## Disclosure Policy

We follow responsible disclosure and will credit reporters unless anonymity is requested.

## Security Expectations for Contributions

- New features must include tests for abuse/failure paths.
- Secure defaults are required.
- Avoid introducing silent security bypasses.
