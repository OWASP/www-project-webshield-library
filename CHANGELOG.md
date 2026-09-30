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

## [Unreleased]

### Security

- A10: `SSRFGuard.createSafeLookup()` validates resolved addresses at socket-connect time, and `SafeFetcher` accepts a `dispatcher` to pin connections to them. This closes the DNS-rebinding race between `assertResolvedSafe()` and `fetch`'s own lookup.
- A08: `HTTPClient` with an `outboundRequestPolicy` no longer lets `fetch` auto-follow redirects. Every hop is DNS-validated, the policy's hop limit applies, and `Authorization`/`X-CSRF-Token`/`Cookie` are stripped on cross-origin redirects.
- A03: `InputSanitizer` (moderate profile) no longer allows `javascript:` URLs preceded by control characters (e.g. `&#1;javascript:`), which browsers ignore when reading the scheme. Out-of-range numeric entities no longer throw a `RangeError`; they decode to U+FFFD as in browsers.
- A08: `HTTPClient` resolves request URLs the way `fetch` does before attaching credentials. URLs such as `" https://evil"`, `//evil` or `/\evil` previously passed as "relative" when `baseUrl` was empty (the `useSecureHttpClient` default) and received the Bearer and CSRF tokens.
- A10: `SafeFetcher` strips `Authorization`/`Proxy-Authorization`/`Cookie`/`X-CSRF-Token` when a redirect leaves the current origin, and turns a 303 (or a 301/302 after POST) into a bodiless GET, as native `fetch` does.
- A01: `ACLManager` now enforces deny-overrides across rules: a wildcard `deny` beats a direct `allow`. Rule keys can no longer collide through `:` in action or resource names, and `RBACManager.can()` rejects actions containing `:`.
- A06: `DependencyRiskScanner.passesPolicy()` normalizes severities (case-insensitive, npm's `moderate`/`info`) and blocks findings whose severity is still unrecognized. `ComponentPolicy` compares versions by semver precedence and blocks missing or unparsable versions (`v1.0.0`, `2.0.0-beta.1` and `undefined` previously passed a `2.0.0` minimum).
- A10: `SSRFGuard.assertResolvedSafe()` fails closed when a resolver returns no addresses. `validateUrl()` also blocks `localhost.`, `*.localhost`, IPv4-compatible `::a.b.c.d`, IPv6 multicast (`ff00::/8`), site-local (`fec0::/10`), local-use NAT64 (`64:ff9b:1::/48`) and 6to4 addresses that embed a blocked IPv4 address.

### Changed

- A08/A10: under Node, `HTTPClient` with an `SSRFGuard` policy resolves DNS before each request, so hostnames that don't resolve (such as fake domains in tests) now fail with `SSRF_BLOCKED: Host could not be resolved`. Pass a `resolveHost` option in tests. Browsers are unaffected.
- A10: a custom `resolveHost` that returns `[]`, `null` or a non-array now blocks the request instead of allowing it.
- A06: `passesPolicy()` throws `INVALID_INPUT` for an unknown threshold (previously every finding was blocked). `ComponentPolicy` throws `MISCONFIGURATION` for a `minVersions` entry that isn't a valid version, and returns `reason: "unparsable_version"` for a package version it can't parse.
- A01: `ACLManager.setPolicy()` throws `INVALID_INPUT` for an effect other than `"allow"` or `"deny"`. It still replaces the rule for the exact same resource/action pair, so toggling a rule (freeze/unfreeze) keeps working.

### Fixed

- A08: `HTTPClient` and `withSecurityHeaders()` no longer send `X-Frame-Options`/`X-Content-Type-Options` as *request* headers (they only apply to responses). `withSecurityHeaders()` now sets `credentials: "same-origin"` and `referrerPolicy: "strict-origin-when-cross-origin"`.
- A08/A10: the default `fetch` is now called unbound, avoiding "Illegal invocation" errors in browsers.
- Docs: removed links to non-existent deployment, CI-gate, and docs-site pages.

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
