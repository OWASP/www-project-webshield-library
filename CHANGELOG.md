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

## [1.0.0] — 2026-09-21 (first release as `@owasp-webshield/core` / `@owasp-webshield/react`)

This is the first published version under the current package names. The project was
previously developed and published as `@owasp-core/owl`/`@owasp-core/owl-react`
(versions `0.1.0`–`1.0.4`) under a different package identity. Starting at `1.0.0` rather
than `0.1.0` reflects that the code itself is already mature (full A01–A10 coverage, real
security fixes, 87 tests) — this is a fresh package identity, not an immature first cut.


### What this release includes

**Core (`@owasp-webshield/core`)** — full A01–A10 API:
- A01: `RBACManager`, `ACLManager`, `PermissionChecker` with deny-overrides conflict resolution.
- A02: `CryptoManager` (AES-256-GCM), `PBKDF2Adapter`, `Argon2Adapter` plugin pattern, `SecretPolicy`, `generateSalt`. `CryptoManager`/`KDFAdapters` are genuinely Node-only (no synchronous, browser-portable AES-GCM/PBKDF2 exists) — see the browser bundling note below.
- A03: `InputSanitizer` (tokenizer-based allowlist, strict/moderate profiles — closes bypasses via unclosed `<script>` tags, `/`-separated event handlers, and obfuscated `javascript:` URLs), `InputValidator` (schema, email, URL, length).
- A04: `ThreatModelGuard` (state transitions + abuse rules), `DesignChecklist`.
- A05: `SecurityConfigManager`, `HardeningReporter`.
- A06: `DependencyRiskScanner`, `ComponentPolicy`.
- A07: `AuthManager`, `TokenManager` (refresh hook, expiry scheduling, event emission).
- A08: `CSRFTokenManager` (Web Crypto-based — `globalThis.crypto.getRandomValues` + a hand-written constant-time comparison, no `node:crypto` dependency, works identically in Node and browsers), `HTTPClient` (async `tokenProvider`, SSRF policy wiring, interceptors, cross-origin credential-leak protection via `allowedOrigins`).
- A09: `SecurityLogger` (redaction-first, sink-configurable, cycle-safe with a max recursion depth, JWT-shaped value-pattern redaction regardless of field name), `EventEmitter`.
- A10: `SSRFGuard` (private-IP + protocol allowlist, IPv4-mapped/expanded-IPv6 and DNS-rebinding protection via `assertResolvedSafe()`), `SafeFetcher` (manually re-validates every redirect hop instead of trusting `fetch`'s auto-follow).
- `SecurityError`/`SecurityErrorCode` — typed error surface across all modules.
- **`createOwlClient(config)`** — builds and wires `TokenManager`, `AuthManager`, `RBACManager`, `ACLManager`, `EventEmitter`, and `SecurityLogger` from one declarative config object instead of constructing and threading each manager by hand.

**React adapter (`@owasp-webshield/react`)** — category-aligned providers, hooks, and guards for A01–A10 (`AuthProvider`/`AuthGate`/`useAuth`/`useAuthToken`, `ACLProvider`/`RBACProvider`/`useACL`/`usePermission`/`PermissionGate`, `useCryptoManager`, `useInputSanitizer`/`SanitizedText`, `useThreatModelGuard`, `useHardeningReport`, `useDependencyRiskScanner`, `useSecureHttpClient`/`withSecurityHeaders`, `SecurityProvider`/`useSecurityMonitoring`/`SecurityAlert`, `useSafeFetcher`), plus:
- **`<OwlProvider>`** — composes `SecurityProvider`/`AuthProvider`/`ACLProvider`/`RBACProvider` into one component, paired with `createOwlClient()`. Validated by collapsing 4 nested providers to 1 and a dozen manual manager constructions to one call in both `owl-enabled-react-todo-app` (React) and `owl-enabled-node-secrets-app` (plain Node, proving `createOwlClient` isn't React-specific) — re-verified end to end in a real browser afterward.

**Browser bundling** — the package root works for every export, including `CryptoManager`:
- `CSRFTokenManager` (A08) has no Node-specific import at all, so it's fully real in a browser build.
- `CryptoManager`/`KDFAdapters` (A02) remain Node-only for actual encryption, but both packages ship a `"browser"`-conditioned build (respected by Vite/webpack 5+/Rollup-with-node-resolve) where they're a same-shaped stub: construction works, `.encrypt()`/`.decrypt()`/`.deriveKey()` throw a clear `SecurityError` instead of the whole bundle failing to build. `Argon2Adapter`/`generateSalt` (no `pbkdf2Sync` dependency) are fully real in the browser build.
- A `./modules/*` subpath export (mapped to unbundled `src/core/*` source) is available as an additional way to import individual files directly.
- Verified against real published tarballs (not monorepo-relative paths) for both packages: installed fresh into a scratch project, built with a real `vite build`, and executed in a real headless browser.

**Known limitation:** `CryptoManager` cannot perform real, synchronous encryption/key-derivation in a browser build — Web Crypto's encryption/derivation APIs are async-only everywhere, including in Node, so this isn't something the browser-bundling fix works around. A genuinely functional browser-side `CryptoManager` would need an async API and would be a breaking change whenever it ships.

**Examples** — `examples/owl-enabled-react-todo-app` (React, every category in one product) and `examples/owl-enabled-node-secrets-app` (plain Node, CLI + HTTP API, includes a real `npm audit`-backed `DependencyRiskScanner` provider).

**Quality gates** — `npm run check` (lint + 87 tests across 15 suites), CI matrix on Node 20/22, CodeQL + dependency review + npm audit workflows, provenance-signed npm publishes for both packages.

---
