# FAQ

## Can I use OWL in a browser bundle?

Partially, today. `CryptoManager`/`PBKDF2Adapter` ([A02](/reference/a02-crypto-integrity)) and `SSRFGuard`/`SafeFetcher` ([A10](/reference/a10-ssrf-defense)) import Node's built-in `node:crypto` and `node:dns/promises` directly. The published `dist/index.js` is bundled with esbuild's `--platform=node`, so a browser bundler (Vite, webpack, etc.) that tries to include those specific exports will fail unless you polyfill those Node built-ins.

Modules that don't touch those two built-ins — access control, input sanitization, auth/session state, logging, hardening reports, dependency scanning — bundle for the browser without any special configuration. If your app only needs those, you're unaffected.

A browser-safe split (or dynamic-import guard) for the crypto/SSRF modules is tracked as follow-up work, not yet shipped.

## Why is the package called `@owasp-core/owl` and not `@owl/core`?

The library's own acronym has always been **OWL** (OWASP Web Shield Library) — that hasn't changed. The npm *scope* changed twice for availability reasons, not naming preference: `@owl/*` → `@owsl/*` → `@owl/*` → `@owasp-core/*`. The `owl` npm organization name was unavailable at publish time, so the package settled on `@owasp-core/owl` (core) and `@owasp-core/owl-react` (React adapter). See [CHANGELOG](/changelog) for the full history.

## Does OWL require React?

No. `@owasp-core/owl` is framework-agnostic and has zero required dependencies. `@owasp-core/owl-react` is a separate, optional package — install it only if you're building a React app. See [Getting Started](/guide/getting-started).

## What Node.js version does OWL require?

Node.js 20 or later (`engines.node: ">=20"` in `package.json`).

## How does OWL handle secrets in logs?

`SecurityLogger` ([A09](/reference/a09-logging-monitoring)) redacts by field name (e.g. `password`, `token`, `authorization`, `cookie`) and by value pattern (JWT-shaped strings), even when a secret is logged under a non-sensitive-looking field name. It also detects circular references and enforces a recursion depth limit, so logging a circular object can't crash your process.

## How do I report a security vulnerability in OWL itself?

Do not open a public GitHub issue. Follow the private disclosure process described in [SECURITY.md](https://github.com/OWASP/www-project-webshield-library/blob/main/SECURITY.md).

## Where do I find the full list of exports?

Every OWASP category's [reference page](/reference/a01-access-control) lists its exports with runnable examples for both the core API and the React adapter. The sidebar under **Reference** covers A01 through A10 plus [Typed Errors](/reference/errors).

## How is OWL versioned?

Semantic Versioning. Breaking changes (including behavior changes to a security default) are called out explicitly in the [CHANGELOG](/changelog) and bump the major version.
