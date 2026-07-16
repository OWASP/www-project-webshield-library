---
title: Overview
layout: null
tab: true
order: 1
tags: owasp javascript react security-library top10
---

<p align="center">
  <img src="https://owasp.org/assets/images/logo.png" width="160" alt="OWASP Logo" />
</p>

<h2 align="center">OWASP Web Shield Library (OWL)</h2>

<p align="center">
  <strong>Practical, reusable OWASP Top 10 security controls for modern JavaScript applications.</strong>
</p>

<p align="center">
  <a href="https://github.com/OWASP/www-project-webshield-library/blob/main/LICENSE.md"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License" /></a>
  &nbsp;
  <a href="https://owasp.org/projects/"><img src="https://img.shields.io/badge/owasp-lab%20project-blue" alt="OWASP Lab Project" /></a>
  &nbsp;
  <img src="https://img.shields.io/badge/node-%3E%3D20-brightgreen" alt="Node 20+" />
  &nbsp;
  <img src="https://img.shields.io/badge/coverage-A01--A10-success" alt="OWASP A01-A10" />
</p>

---

## What OWL Delivers

OWL maps reusable security controls directly to OWASP categories so teams speak the same security language as their threat models.

| Capability | Approach |
|---|---|
| 🛡️ Full A01–A10 coverage | One module per OWASP category, consistent naming |
| 🧩 Framework-agnostic core | Pure JavaScript, no runtime framework dependency |
| ⚛️ React adapter | Category-aligned providers, hooks, and guard components |
| ✅ Secure defaults | Deny-overrides, token expiry, redaction — all on by default |
| 🧪 Test-first delivery | Positive, negative, and abuse-path test coverage |
| 🔄 CI-ready | Lint + test + build gate in a single `npm run check` |

---

## Core Module Map (A01–A10)

| OWASP # | Category | Key Exports |
|---|---|---|
| A01 | Broken Access Control | `RBACManager`, `ACLManager`, `PermissionChecker` |
| A02 | Cryptographic Failures | `CryptoManager`, `PBKDF2Adapter`, `Argon2Adapter`, `SecretPolicy` |
| A03 | Injection | `InputSanitizer`, `InputValidator` |
| A04 | Insecure Design | `ThreatModelGuard`, `DesignChecklist` |
| A05 | Security Misconfiguration | `SecurityConfigManager`, `HardeningReporter` |
| A06 | Vulnerable & Outdated Components | `DependencyRiskScanner`, `ComponentPolicy` |
| A07 | Identification & Auth Failures | `AuthManager`, `TokenManager` |
| A08 | Software & Data Integrity Failures | `CSRFTokenManager`, `HTTPClient` |
| A09 | Security Logging & Monitoring Failures | `SecurityLogger`, `EventEmitter` |
| A10 | SSRF | `SSRFGuard`, `SafeFetcher` |

---

## React Adapter Highlights

```
@owl/react-adapter
 ├── A01  ACLProvider, RBACProvider, useACL, usePermission, PermissionGate
 ├── A02  useCryptoManager
 ├── A03  useInputSanitizer, SanitizedText
 ├── A04  useThreatModelGuard
 ├── A05  useHardeningReport
 ├── A06  useDependencyRiskScanner
 ├── A07  AuthProvider, useAuth, useAuthToken, AuthGate
 ├── A08  useSecureHttpClient, withSecurityHeaders
 ├── A09  SecurityProvider, useSecurityMonitoring, SecurityAlert
 └── A10  useSafeFetcher
```

---

## Project Links

| Resource | Link |
|---|---|
| 📚 API Reference | [docs/api-reference.md](https://github.com/OWASP/www-project-webshield-library/blob/main/docs/api-reference.md) |
| 📁 Source | [github.com/OWASP/www-project-webshield-library](https://github.com/OWASP/www-project-webshield-library) |
| 🚀 Examples | [examples/](https://github.com/OWASP/www-project-webshield-library/tree/main/examples) |
| 🐛 Issues | [GitHub Issues](https://github.com/OWASP/www-project-webshield-library/issues) |
