# Security Policy

<p align="center">
  <img src="https://img.shields.io/badge/security-responsible%20disclosure-informational" alt="Responsible Disclosure" />
  &nbsp;
  <img src="https://img.shields.io/badge/response%20target-72%20hours-brightgreen" alt="Response target" />
</p>

OWL takes security seriously. This document describes supported versions, how to report a vulnerability, and what to expect during the response process.

---

## Supported Versions

| Version | Status | Security Support |
|---|---|---|
| `1.x` — latest | ✅ Stable | Full security fixes |
| `1.x` — previous minor | ⚠️ Maintenance | Critical fixes only, best-effort |
| `0.x` | ❌ End of life | No support |

---

## Reporting a Vulnerability

> ⚠️ **Do not open a public GitHub issue for a security vulnerability.**

Use one of the following private channels:

| Channel | Details |
|---|---|
| 📧 Email | [cybersreejith@gmail.com](mailto:cybersreejith@gmail.com) |
| 🔒 GitHub Security Advisories | [Report privately →](https://github.com/OWASP/www-project-webshield-library/security/advisories/new) |

### What to include in your report

```
- Affected module (e.g. A07 TokenManager, A08 HTTPClient)
- Description and assessed impact
- Reproduction steps or minimal proof-of-concept
- Suggested mitigation if known
```

---

## Response Process

```
Report received
     │
     ▼
⏱  Acknowledgment within 72 hours
     │
     ▼
🔍  Triage & severity assessment (CVSS scoring)
     │
     ▼
🔧  Fix developed with tests covering the vulnerability path
     │
     ▼
🚀  Patch release with coordinated disclosure notes
     │
     ▼
📋  CVE filed where applicable — reporter credited
```

---

## Disclosure Policy

- Researchers acting in good faith will not face legal action.
- Reporters are credited in release notes unless anonymity is requested.
- Embargoed details remain confidential until the fix ships.
- Disclosure timing is coordinated with the reporter.

---

## Security Expectations for Contributors

All contributions must satisfy these security requirements:

- [ ] New features include tests for abuse paths and failure conditions
- [ ] Secure defaults are always enforced — no opt-in required for baseline safety
- [ ] Silent security bypasses are not permitted
- [ ] Sensitive fields are never logged without redaction
- [ ] Outbound requests use SSRF-aware paths where applicable

---

## Security Defaults Reference

| Module | Default Behavior |
|---|---|
| A01 | ACL deny overrides RBAC allow deterministically |
| A02 | PBKDF2 with 210,000 iterations and 32-byte keys |
| A07 | In-memory token storage; expired tokens return `null` |
| A08 | `X-Content-Type-Options` and `X-Frame-Options` on every request |
| A09 | `password`, `token`, `secret`, `authorization`, `cookie` redacted by default |
| A10 | Loopback, RFC-1918, and `.local` hosts blocked; protocol allowlist enforced |

---

*For general help, see [SUPPORT.md](SUPPORT.md).*
