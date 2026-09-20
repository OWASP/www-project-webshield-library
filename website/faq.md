# FAQ

## Can I use OWL in a browser bundle?

Partially, and the failure mode is at the *package* level, not the module level — importing anything from `@owasp-core/owl`'s single entry point pulls in every core module together, not just the one you named.

`CryptoManager`/`KDFAdapters` ([A02](/reference/a02-crypto-integrity)) and `CSRFTokenManager` ([A08](/reference/a08-data-integrity)) each have a top-level `import ... from "node:crypto"` (for `createCipheriv`, `pbkdf2Sync`, `randomBytes`, `timingSafeEqual`). The published `dist/index.js` is one esbuild bundle containing every category, so a production bundler (Rollup, webpack) targeting the browser fails to resolve those named imports the moment **anything** is imported from `@owasp-core/owl` or `@owasp-core/owl-react` — even an unrelated export like `SecretPolicy`, and even if your code never calls the crypto functions. The same applies to the React adapter's `useCryptoManager` and `useSecureHttpClient` (which wraps `CSRFTokenManager`), since importing from the adapter's package root re-exports those categories too.

`SSRFGuard`/`SafeFetcher` ([A10](/reference/a10-ssrf-defense)) are the exception despite also referencing `node:dns/promises`: that import is a *dynamic* `import()` gated behind a `typeof process !== "undefined" && process.versions?.node` check, so it's never evaluated in a browser. It only produces a build-time warning, not a failure — `useSafeFetcher` works in a browser bundle today.

**Workaround today:** import each class or hook from its individual source file instead of the package root (e.g. `@owasp-core/owl-react/a01-access-control/index.js` instead of `@owasp-core/owl-react`), which avoids ever evaluating `CryptoManager.js`/`KDFAdapters.js`/`CSRFTokenManager.js`. The [`owl-enabled-react-todo-app` example](https://github.com/OWASP/www-project-webshield-library/tree/main/examples/owl-enabled-react-todo-app) does exactly this — see its README "Notes" section — and its `npm run build` succeeds as a result, unlike a build that imports from the package root.

Node apps (see the [`owl-enabled-node-secrets-app` example](https://github.com/OWASP/www-project-webshield-library/tree/main/examples/owl-enabled-node-secrets-app)) are unaffected — Node has `node:crypto` natively, so `CryptoManager` and `CSRFTokenManager` work as published.

A proper fix (per-category `exports` conditions or a browser-safe subpath so bundlers can resolve just what's used) is tracked as follow-up work, not yet shipped.

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
