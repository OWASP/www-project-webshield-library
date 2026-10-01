# OWL Enabled Banking Dashboard

A full-featured fintech dashboard built on `@owasp-webshield/react`, showing every OWASP Top 10
category (A01–A10) doing real work inside one realistic banking product: masked/vault-protected
account numbers, a 2FA-guarded transfer workflow, maker-checker dual-control approvals, and a live
security audit log.

## Run locally

From this folder:

```bash
npm install
npm run dev
```

Open the Vite URL shown in the terminal, then sign in as one of the three demo identities from the
login screen.

## Deploying a live demo (Netlify)

This folder has its own `netlify.toml`, so it can be deployed as its own Netlify site alongside the
docs site and the Todo app, pointed at the same GitHub repo. The setup mechanism is identical to
the [Todo app's](../owl-enabled-react-todo-app/README.md#deploying-a-live-demo-netlify) — just swap
the base directory to `examples/owl-enabled-react-banking-dashboard`.

## What it demonstrates

| Category | Where |
|---|---|
| A01 Broken Access Control | `RBACManager` + `ACLManager` + `PermissionChecker` via `usePermission`/`PermissionGate` across three roles (customer/teller/admin). Approving a transfer above the $10,000 policy ceiling is denied for **every** role, admin included, by an explicit ACL deny-override — a maker-checker dual-control demo |
| A02 Crypto Failures | Accounts panel calls the real, Node-only `CryptoManager.encrypt()` directly in the browser and shows it correctly refuse rather than fake weaker crypto; real account numbers are only ever fetched on demand from a CSRF-protected "vault" endpoint. `SecretPolicy` entropy/rotation checks vet the webhook signing secret in Admin Settings |
| A03 Injection | `useInputSanitizer` + `SanitizedText` sanitize transfer memos (one seed transfer ships with a raw `<script>` payload), `InputValidator.validateSchema` on the new-transfer form |
| A04 Insecure Design | `useThreatModelGuard` enforces a strict `draft → otp_requested → otp_verified → (pending_approval →) completed` state machine — a "try to skip 2FA" button proves the guard rejects the jump instead of just hiding it in the UI. `DesignChecklist` in Admin Settings |
| A05 Security Misconfiguration | `useHardeningReport` wired to live toggles (debug flag, CORS origin, cookie flags) in Admin Settings — flip a setting and watch findings update |
| A06 Vulnerable Components | `useDependencyRiskScanner` over three mock vendor SDKs, cross-checked against `ComponentPolicy`, on the Integrations page |
| A07 Auth & Session | `AuthProvider`/`AuthGate`/`useAuth`/`useAuthToken`, plus a real, observable token-refresh flow — the top bar shows a live session countdown (90s demo TTL) and a "Refresh Session" button that calls `TokenManager.refreshIfNeeded()` |
| A08 Data Integrity | Real core `CSRFTokenManager` + `HTTPClient`, wired with a bearer token provider and `SSRFGuard` as its `outboundRequestPolicy`; every transfer execution/approval and vault reveal goes through it with `withSecurityHeaders` |
| A09 Logging & Monitoring | `SecurityProvider`/`useSecurityMonitoring` — every login, transfer state change, vault reveal, webhook validation, and config change is logged and shown on a filterable Audit Log page |
| A10 SSRF | `useSafeFetcher` validates a merchant bill-pay webhook URL before it's ever fetched or saved — try the built-in "probe localhost" / "probe cloud metadata" buttons on the Integrations page |

The **Integrations** and **Audit Log** tabs are gated by `PermissionGate` to teller/admin; **Admin
Settings** is gated to admin only.

## Notes

- **Uses `createOwlClient()` + `<OwlProvider>`** for the RBAC/ACL/Auth/logging setup instead of
  constructing each manager by hand and nesting four separate providers. `CSRFTokenManager`/
  `HTTPClient`/`SSRFGuard` are still constructed directly (their config is app-specific).
- **All imports use the package root** (`@owasp-webshield/core`, `@owasp-webshield/react`) — see the
  [FAQ](https://owasp.org/www-project-webshield-library/faq#can-i-use-owl-in-a-browser-bundle) for
  why that's safe in a browser build.
- **`CryptoManager` (A02) is deliberately called directly in this app** (unlike the Todo app example)
  specifically to demonstrate its browser-safety behavior: it throws a clear, actionable error rather
  than crashing the build or silently using weaker crypto. Real account-number encryption/decryption
  is modeled as a server-side "vault" call instead, which is also how a real bank would architect it —
  PANs should never be decrypted client-side.
- Uses deterministic mocks for the HTTP and dependency-scan providers so it runs fully offline.
- `npm run build` (production) works here — verified with a real `vite build`.
