# Changelog

<p align="center">
  <a href="https://github.com/OWASP/www-project-webshield-library/releases"><img src="https://img.shields.io/github/v/release/OWASP/www-project-webshield-library?sort=semver" alt="Latest Release" /></a>
  &nbsp;
  <img src="https://img.shields.io/badge/versioning-semver-blue" alt="Semver" />
</p>

All notable changes to this project are documented in this file.
This project follows [Semantic Versioning](https://semver.org/).

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [1.0.0] - 2026-07-16

### Added

- **Core A01–A10 modules** — Full public API for all 10 OWASP categories:
  - A01: `RBACManager`, `ACLManager`, `PermissionChecker` with deny-overrides conflict resolution
  - A02: `CryptoManager` (AES-256-GCM), `PBKDF2Adapter`, `Argon2Adapter` plugin pattern, `SecretPolicy`, `generateSalt`
  - A03: `InputSanitizer` (strict/moderate profiles), `InputValidator` (schema, email, URL, length)
  - A04: `ThreatModelGuard` (state transitions + abuse rules), `DesignChecklist`
  - A05: `SecurityConfigManager`, `HardeningReporter`
  - A06: `DependencyRiskScanner`, `ComponentPolicy`
  - A07: `AuthManager`, `TokenManager` (refresh hook, expiry scheduling, event emission)
  - A08: `CSRFTokenManager`, `HTTPClient` (async `tokenProvider`, SSRF policy wiring, interceptors)
  - A09: `SecurityLogger` (redaction-first, sink-configurable), `EventEmitter`
  - A10: `SSRFGuard` (private-IP + protocol allowlist), `SafeFetcher`
  - `SecurityError` / `SecurityErrorCode` — typed error surface across all modules
- **React adapter (`@owl/react-adapter`)** — Category-aligned providers, hooks, and guards for A01–A10:
  - `AuthProvider`, `useAuth`, `useAuthToken`, `AuthGate` — token expiry scheduling, token-cleared reactivity
  - `ACLProvider`, `RBACProvider`, `useACL`, `usePermission`, `PermissionGate`
  - `useCryptoManager`, `useInputSanitizer`, `SanitizedText`
  - `useThreatModelGuard`, `useHardeningReport`, `useDependencyRiskScanner` (stable `runScan` callback)
  - `useSecureHttpClient` (per-instance `CSRFTokenManager`, async token provider), `withSecurityHeaders`
  - `SecurityProvider`, `useSecurityMonitoring` (safe without provider), `SecurityAlert`
  - `useSafeFetcher`
- **Runnable examples** — `examples/core-node-demo/` (Node, no build) and `examples/react-adapter-demo/` (Vite)
- **API reference** — `docs/api-reference.md` with copyable examples for every exported symbol
- **GitHub Actions workflows** — CI (Node 20 + 22 matrix), release (tag-triggered npm publish with provenance), security (CodeQL + dependency review + npm audit)
- **Quality gate** — `npm run check` (lint + 63 tests across 13 suites)

### Changed

- `AuthProvider` now tracks token lifecycle events (`token:changed`, `token:cleared`, `token:rotated`) and schedules a recheck timer at `expiresAt`, so `AuthGate` and `isAuthenticated` stay accurate after token expiry without manual refresh.
- `useAuthToken` subscribes to both `token:changed` and `token:cleared` so the hook returns `null` immediately after logout.
- `useDependencyRiskScanner` returns a stable `runScan` callback that always uses the latest scanner instance via ref, preventing unnecessary re-renders.
- Package promoted from `0.x` foundation to `1.0.0` stable release.
- npm publish metadata hardened: explicit `files` array, `prepublishOnly` gate, provenance enabled.

### Security

- Deny-overrides ACL conflict strategy enforced as the non-configurable default.
- `SecurityLogger` redacts `password`, `token`, `secret`, `authorization`, and `cookie` fields at all nesting levels.
- `HTTPClient` always awaits `tokenProvider` (sync and async) before attaching `Authorization` header.
- `SSRFGuard` blocks loopback, RFC-1918, and `.local` hosts; enforces protocol allowlist and redirect-hop limit.
- All `SecurityError` throws carry a typed `code` from `SecurityErrorCode` and a structured `details` payload.

---

## [0.1.0] - 2026-06-28

### Added

- Core OWASP modules A01-A10 with JavaScript APIs.
- React adapter modules grouped by A01-A10.
- Access control, auth/session, CSRF/data integrity, logging, SSRF, crypto, misconfiguration, design guard, and vulnerable component helpers.
- Jest unit tests for core and key adapter hooks.
- ESLint quality gate and `check` script.

### Changed

- React adapter organization consolidated into A01-A10 folders.
- A08 HTTPClient now supports outbound SSRF policy integration.
- A02 crypto now supports pluggable KDF adapters (PBKDF2 default + Argon2 plugin pattern).

### Security

- Deny-overrides conflict strategy for ACL checks.
- Sensitive field redaction in security logging.

## [0.1.0] - 2026-06-28

### Added

- Core OWASP modules A01-A10 with JavaScript APIs.
- React adapter modules grouped by A01-A10.
- Access control, auth/session, CSRF/data integrity, logging, SSRF, crypto, misconfiguration, design guard, and vulnerable component helpers.
- Jest unit tests for core and key adapter hooks.
- ESLint quality gate and `check` script.

### Changed

- React adapter organization consolidated into A01-A10 folders.
- A08 HTTPClient now supports outbound SSRF policy integration.
- A02 crypto now supports pluggable KDF adapters (PBKDF2 default + Argon2 plugin pattern).

### Security

- Deny-overrides conflict strategy for ACL checks.
- Sensitive field redaction in security logging.
