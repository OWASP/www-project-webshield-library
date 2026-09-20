# FAQ

## Can I use OWL in a browser bundle?

Yes, including the package root now — with one deliberate, clearly-signposted exception (`CryptoManager`'s actual encryption/derivation methods).

**Background:** `@owasp-core/owl`'s single entry point (`dist/index.js`) is one esbuild bundle containing every core module. Importing *anything* from it used to pull all of them in together, so a production browser bundler (Rollup, webpack) failed on **any** import from the package root — even an unrelated export like `SecretPolicy` — because two files had a top-level `import ... from "node:crypto"`: `CryptoManager`/`KDFAdapters` ([A02](/reference/a02-crypto-integrity)) and `CSRFTokenManager` ([A08](/reference/a08-data-integrity)). The same applied to `@owasp-core/owl-react`'s root, since it re-exports those categories too.

**`CSRFTokenManager` (A08) is fully fixed, everywhere** — rewritten to use the Web Crypto API (`globalThis.crypto.getRandomValues`) and a hand-written constant-time comparison instead of `node:crypto`'s `randomBytes`/`timingSafeEqual`. It has no Node-specific import left and works identically in Node 20+, every modern browser, and any other Web Crypto runtime. `useSecureHttpClient` benefits from this too — no swap needed for it at all.

**`CryptoManager`/`KDFAdapters` (A02) remain genuinely Node-only for real encryption** — AES-256-GCM and PBKDF2 have no synchronous, browser-portable equivalent (Web Crypto's `subtle.encrypt`/`deriveBits` are async-only by spec everywhere, including in Node), and making them async would be a breaking change to the existing sync API. Instead, both packages now ship a **browser build** (selected automatically via the `"browser"` `exports` condition that Vite, webpack 5+, and Rollup-with-node-resolve all respect) where `CryptoManager`/`KDFAdapters`/`useCryptoManager` are replaced with a same-shaped stub: `new CryptoManager()` still works, but `.encrypt()`/`.decrypt()`/`.deriveKey()` throw a clear `SecurityError` explaining the limitation instead of crashing the whole bundle at import time. `Argon2Adapter` and `generateSalt` (which don't need `pbkdf2Sync`) are fully real in the browser build too.

```js
// This now works in a browser build, package root included:
import { SecretPolicy, CSRFTokenManager, CryptoManager } from "@owasp-core/owl";

new CryptoManager().encrypt(...); // throws a clear SecurityError in a browser build,
                                   // works for real in Node — same code, either environment
```

If you'd rather avoid even constructing the stub, or want the smallest possible bundle, `@owasp-core/owl`'s `./core/*` subpath still lets you import individual source files directly (e.g. `@owasp-core/owl/core/a02-crypto-integrity/SecretPolicy.js`) without touching A02 at all.

This is verified against real published tarballs (not monorepo-relative paths) for **both** `@owasp-core/owl` and `@owasp-core/owl-react` — installed fresh, built with a real `vite build`, and executed in a real headless browser. See the [`owl-enabled-react-todo-app` example](https://github.com/OWASP/www-project-webshield-library/tree/main/examples/owl-enabled-react-todo-app).

`SSRFGuard`/`SafeFetcher` ([A10](/reference/a10-ssrf-defense)) were never actually affected despite also referencing `node:dns/promises`: that import is a *dynamic* `import()` gated behind a `typeof process !== "undefined" && process.versions?.node` check, so it's never evaluated in a browser — only a build-time warning, not a failure.

Node apps (see the [`owl-enabled-node-secrets-app` example](https://github.com/OWASP/www-project-webshield-library/tree/main/examples/owl-enabled-node-secrets-app)) are fully unaffected either way — Node has `node:crypto` natively, so they always get the real `CryptoManager`.

A browser-safe `.` entry point (so the package root itself works without the `./core/*` subpath) is tracked as follow-up work — it would need either a breaking async `CryptoManager` API or a separate throwing-stub browser build.

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
