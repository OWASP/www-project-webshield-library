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

## [2.0.0] - 2026-09-19

### Security

- **A10 `SSRFGuard`/`SafeFetcher`** — Fixed fail-open behavior for IPv4-mapped/expanded IPv6 loopback and `0.0.0.0` literals, and closed a DNS-rebinding gap: hostnames are now resolved and every returned address is validated via the new `assertResolvedSafe()` method (configurable `resolveHost` option). `SafeFetcher` now follows redirects manually and re-validates every hop instead of letting `fetch` auto-follow them unchecked.
- **A03 `InputSanitizer`** — Replaced the regex-based blocklist sanitizer with a tokenizer-based allowlist sanitizer, closing bypasses via unclosed `<script>` tags, `/`-separated event handlers (e.g. `<svg/onload=...>`), and case/whitespace/HTML-entity-obfuscated `javascript:` URLs (including named references like `&colon;`). **Behavior change:** the `moderate` profile now only allows a fixed set of formatting tags instead of passing through arbitrary markup.
- **A08 `HTTPClient`** — Fixed a cross-origin credential leak: `Authorization`/`X-CSRF-Token` headers were previously attached to any absolute URL regardless of origin. Requests to an absolute URL now require the target to match `baseUrl`'s origin or an explicit new `allowedOrigins` option, otherwise a `CREDENTIAL_LEAK_BLOCKED` `SecurityError` is thrown. **Breaking:** cross-origin credentialed requests that previously worked implicitly now require `allowedOrigins` to be configured.
- **A02 `SecretPolicy`** — Fixed `minimumEntropyBits()`/`isEntropySufficient()` overestimating the strength of long, repetitive secrets (e.g. `"ab".repeat(32)`). Entropy is now estimated from the number of distinct characters used times the bits-per-symbol implied by the character classes present, instead of raw length times unique-character count.
- **A09 `SecurityLogger`** — Fixed a denial-of-service where logging an object containing a circular reference threw a stack-overflow error; `redact()` now detects cycles and enforces a maximum recursion depth. Also added value-pattern-based redaction (JWT-shaped strings) so secrets logged under a non-sensitive field name are still redacted.

### Fixed

- Renamed the published npm scope from `@owl/*` to `@owsl/*` and back to `@owl/*` (see `docs/release-process.md`) — `package.json`/`src/adapters/react/package.json`, all documentation, and example code samples now consistently used the `@owl/*` scope.
- Renamed the npm scope again, from `@owl/*` to `@owasp-core/*` (`@owl/core` → `@owasp-core/owl`, `@owl/react-adapter` → `@owasp-core/owl-react`), because the `owl` npm organization name was unavailable at publish time. All `package.json` files, documentation, and example code samples now consistently use the `@owasp-core/*` scope.

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
- **React adapter (`@owasp-core/owl-react`)** — Category-aligned providers, hooks, and guards for A01–A10:
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
