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

## Deploying a live demo (Netlify)

This folder has its own `netlify.toml`, so it can be deployed as a second Netlify site
alongside the docs site (`netlify.toml` at the repo root), pointed at the same GitHub repo:

1. Go to [netlify.com](https://www.netlify.com) → **Add new site → Import an existing project** → choose this repo (`OWASP/www-project-webshield-library`).
2. Set **Base directory** to `examples/owl-enabled-react-todo-app`. Netlify will then read *this* folder's `netlify.toml` instead of the repo root's — build command and publish directory are already set (`npm run build`, `dist`), no manual entry needed.
3. Click **Deploy site**. The build also compiles the root `@owasp-core/owl`/`@owasp-core/owl-react` packages first (see the `command` in `netlify.toml`), since this app depends on their `dist/` output, which isn't committed to git.
4. Once live, add a "Try it live" badge to the main repo README pointing at the deploy URL.

No environment variables are required — every provider (HTTP, dependency scan) is mocked deterministically. See `docs/docs-site-deployment.md` for the equivalent walkthrough for the docs site, including the same base-directory gotcha (`publish` resolves relative to `base`, not the repo root).

## What it demonstrates

| Category | Where |
|---|---|
| A01 Broken Access Control | `RBACManager` + `ACLManager` + `PermissionChecker` via `usePermission`/`useACL`/`PermissionGate` — task deletion is denied for every role by an explicit ACL policy that overrides RBAC (deny-override) |
| A02 Crypto Failures | `SecretPolicy` entropy/rotation checks (Security Dashboard + token entropy in the Workspace) — `CryptoManager` itself is skipped, see **Notes** |
| A03 Injection | `useInputSanitizer` + `SanitizedText` for sanitized previews, `InputValidator.validateSchema` on the new-task form |
| A04 Insecure Design | `useThreatModelGuard` for status-transition rules + abuse-case checks, `DesignChecklist` in the Security Dashboard |
| A05 Security Misconfiguration | `useHardeningReport` |
| A06 Vulnerable Components | `useDependencyRiskScanner` cross-checked against `ComponentPolicy` |
| A07 Auth & Session | `AuthProvider`/`AuthGate`/`useAuth`/`useAuthToken` — a real sign-in/sign-out flow, not a pre-set session |
| A08 Data Integrity | Real core `CSRFTokenManager` + `HTTPClient` (not a mock — see **Notes**), wired with a bearer token provider and `SSRFGuard` as its `outboundRequestPolicy`; requests built with a `withSecurityHeaders`-equivalent helper |
| A09 Logging & Monitoring | `SecurityProvider`/`useSecurityMonitoring`/`SecurityAlert` — every write, blocked action, login, and logout is logged and shown on the admin Activity Timeline |
| A10 SSRF | `useSafeFetcher` validates each task's attachment URL before "fetching" it, blocking loopback/private targets |

The **Security Dashboard** tab is gated by `PermissionGate action="manage" resource="security"` and is only reachable by the `admin` demo identity.

## Notes

- **Uses `createOwlClient()` + `<OwlProvider>`** for the RBAC/ACL/Auth/logging setup (`security.js` and `App.jsx`) instead of constructing `TokenManager`/`AuthManager`/`RBACManager`/`ACLManager`/`EventEmitter`/`SecurityLogger` by hand and nesting four separate providers. `CSRFTokenManager`/`HTTPClient`/`SSRFGuard` are still constructed directly (their config is too app-specific to generalize). See `docs/react-adapter-usage.md`'s "Quick start" section.
- **All imports use the package root** (`@owasp-core/owl`, `@owasp-core/owl-react`) — see the [FAQ](https://owasp.org/www-project-webshield-library/faq#can-i-use-owl-in-a-browser-bundle) for why that's now safe in a browser build.
- **`CSRFTokenManager` (A08) is the real class here, not a mock** — it's been rewritten upstream to use the Web Crypto API (`globalThis.crypto.getRandomValues`) and a constant-time comparison instead of `node:crypto`, so it has no Node-specific dependency left and works identically in this browser app.
- `CryptoManager` (A02) isn't used by this app: AES-GCM/PBKDF2 have no synchronous browser-portable equivalent, so it remains genuinely Node-only for real encryption — the package's browser build provides a same-shaped stub that throws clearly if called, rather than crashing the build.
- `npm run build` (production) works here — verified with a real `vite build`.
- Uses deterministic mocks for the HTTP and dependency-scan providers so it runs fully offline.
