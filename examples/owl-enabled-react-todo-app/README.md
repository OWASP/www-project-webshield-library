# OWL Enabled React Todo App

A single, full-featured Todo product built on `@owasp-core/owl-react`, showing every
OWASP Top 10 category (A01–A10) doing real work inside one realistic app instead of
across ten disconnected tutorial pages. This example replaces the previous
`react-adapter-demo` and `owl-enabled-app` examples.

## Run locally

From this folder:

```bash
npm install
npm run dev
```

Open the Vite URL shown in the terminal, then sign in as either demo identity from the
login screen.

## What it demonstrates

| Category | Where |
|---|---|
| A01 Broken Access Control | `RBACManager` + `ACLManager` + `PermissionChecker` via `usePermission`/`useACL`/`PermissionGate` — task deletion is denied for every role by an explicit ACL policy that overrides RBAC (deny-override) |
| A02 Crypto Failures | `SecretPolicy` entropy/rotation checks (Security Dashboard + token entropy in the Workspace) — see **Notes** below for why `CryptoManager` itself can't run here |
| A03 Injection | `useInputSanitizer` + `SanitizedText` for sanitized previews, `InputValidator.validateSchema` on the new-task form |
| A04 Insecure Design | `useThreatModelGuard` for status-transition rules + abuse-case checks, `DesignChecklist` in the Security Dashboard |
| A05 Security Misconfiguration | `useHardeningReport` |
| A06 Vulnerable Components | `useDependencyRiskScanner` cross-checked against `ComponentPolicy` |
| A07 Auth & Session | `AuthProvider`/`AuthGate`/`useAuth`/`useAuthToken` — a real sign-in/sign-out flow, not a pre-set session |
| A08 Data Integrity | Core `HTTPClient` wired with a CSRF manager, bearer token provider, and `SSRFGuard` as its `outboundRequestPolicy`; requests built with a `withSecurityHeaders`-equivalent helper (see **Notes**) |
| A09 Logging & Monitoring | `SecurityProvider`/`useSecurityMonitoring`/`SecurityAlert` — every write, blocked action, login, and logout is logged and shown on the admin Activity Timeline |
| A10 SSRF | `useSafeFetcher` validates each task's attachment URL before "fetching" it, blocking loopback/private targets |

The **Security Dashboard** tab is gated by `PermissionGate action="manage" resource="security"` and is only reachable by the `admin` demo identity.

## Notes

- **Why this app imports OWL by direct file path instead of `@owasp-core/owl` / `@owasp-core/owl-react`'s package root.** `CryptoManager`, its `KDFAdapters`, and `CSRFTokenManager` each have a top-level `import ... from "node:crypto"`. The published `@owasp-core/owl` entry point resolves to a single prebuilt `dist/index.js` that bundles *every* core module together, so importing anything from it — even just `SecretPolicy` — evaluates that `node:crypto` import too. In a browser, Vite/Rollup externalizes `node:crypto` to a stub that throws the instant *any* property is read off it, which happens unconditionally at module-evaluation time (not only when the crypto function is actually called). The same problem applies to `@owasp-core/owl-react`'s root export, since it re-exports the A02 (`useCryptoManager`) and A08 (`useSecureHttpClient`) categories, whose files import `CryptoManager.js`/`CSRFTokenManager.js`. Net effect: **importing from either package's root entry point crashes on load in a browser**, regardless of which named export you actually use. This app instead imports each core class from its source file directly (`src/security.js`'s imports) and each adapter hook from its per-category path (e.g. `@owasp-core/owl-react/a01-access-control/index.js`) — the exact technique the adapter's own source already uses internally — which avoids ever evaluating the three Node-crypto files. `CryptoManager` is skipped entirely (no browser-safe equivalent exists yet); `CSRFTokenManager` is replaced with a tiny mock satisfying the same `attach(headers)` interface, seeded via the browser-native Web Crypto API instead of Node's `randomBytes`.
- As a result, unlike the two examples this one replaces, **`npm run build` (production) actually works here** — verified with a real `vite build`. The previous `react-adapter-demo` and `owl-enabled-app` examples both fail `vite build` today for the reason above; this app's import style is also the fix for that, and might be worth carrying back into those patterns (or fixing upstream with per-category `exports` conditions on `@owasp-core/owl`) if that's ever revisited.
- Uses deterministic mocks for the HTTP and dependency-scan providers so it runs fully offline.
