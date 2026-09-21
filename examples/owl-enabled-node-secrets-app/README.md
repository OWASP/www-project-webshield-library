# OWL Enabled Node Secrets App

A small team credential vault — built directly on `@owasp-webshield/core`, no framework —
showing every OWASP Top 10 category (A01–A10) doing real work. This example replaces
`core-node-demo`.

Unlike the browser-based `owl-enabled-react-todo-app` example, this one runs in real
Node, so it can use the two modules that need Node's native `crypto` module and can't
run in a browser bundle: **`CryptoManager`** (real AES-256-GCM encryption at rest) and
**`CSRFTokenManager`** (real, not mocked). It also runs a **real `npm audit`**, not a
fixture.

## Run locally

From this folder:

```bash
npm install
npm start          # scripted CLI walkthrough — every category, one run, no server
npm run serve       # a small REST API on :8787 — see "Try the API" below
```

## What `npm start` demonstrates

| Category | Where |
|---|---|
| A01 Broken Access Control | `RBACManager` + `ACLManager` + `PermissionChecker` — RBAC denies a `viewer` reveal outright; a per-secret ACL freeze denies reveal even for `admin` (deny-override, scoped to one secret instead of a whole resource type) |
| A02 Crypto Failures | `CryptoManager` (AES-256-GCM) encrypts every secret at rest with a vault master key; `SecretPolicy` flags weak stored values and overdue rotations |
| A03 Injection | `InputValidator.validateSchema` + `InputSanitizer` on secret name/description |
| A04 Insecure Design | A lifecycle guard (active → rotating → active, active → revoked) plus abuse-case checks on metadata length, self-audited against a `DesignChecklist` |
| A05 Security Misconfiguration | `SecurityConfigManager` + `HardeningReporter`, run once at boot |
| A06 Vulnerable Components | `DependencyRiskScanner` backed by a **real** `NpmAuditProvider` (shells out to `npm audit --json` against the repo root) |
| A07 Auth & Session | `AuthManager` + `TokenManager` |
| A08 Data Integrity | A real `CSRFTokenManager` + `HTTPClient` |
| A09 Logging & Monitoring | `SecurityLogger` — a reveal is logged with the plaintext under the key `secretValue`, which auto-redacts to `[REDACTED]` because it matches the default redact-key list; `EventEmitter` builds the full audit trail printed at the end |
| A10 SSRF | `SafeFetcher`/`SSRFGuard` guards the "notify on reveal" webhook call; a literal cloud-metadata IP (`169.254.169.254`) is blocked |

## Try the API (`npm run serve`)

The server keeps one global session at a time (same simplification the CLI makes) —
log in again to switch roles. Every mutating request needs both the bearer token from
`/login` and the CSRF token in `X-CSRF-Token`; omitting either is rejected.

```bash
# Log in — returns { accessToken, csrfToken }
curl -s -X POST localhost:8787/login -H 'Content-Type: application/json' -d '{"role":"contributor"}'

TOKEN=<accessToken from above>
CSRF=<csrfToken from above>

# Rejected — no CSRF header (403 CSRF_INVALID)
curl -s -X POST localhost:8787/secrets \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"STRIPE_KEY","value":"sk_live_...","description":"Stripe secret key"}'

# Accepted
curl -s -X POST localhost:8787/secrets \
  -H "Authorization: Bearer $TOKEN" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
  -d '{"name":"STRIPE_KEY","value":"sk_live_...","description":"Stripe secret key"}'

# Log in as admin, reveal it
curl -s -X POST localhost:8787/login -H 'Content-Type: application/json' -d '{"role":"admin"}'
curl -s -X POST localhost:8787/secrets/STRIPE_KEY/reveal -H "Authorization: Bearer $TOKEN" -H "X-CSRF-Token: $CSRF"

# Freeze it (per-secret ACL deny) — reveal now fails even for admin
curl -s -X POST localhost:8787/secrets/STRIPE_KEY/freeze \
  -H "Authorization: Bearer $TOKEN" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' -d '{"frozen":true}'
```

Other routes: `GET /secrets`, `POST /secrets/:name/rotate` (`{"newValue": "..."}`), `DELETE /secrets/:name`.

## Notes

- The RBAC/ACL roles and the token/session managers are built with `createOwlClient()` (one config object) instead of constructing `RBACManager`/`ACLManager`/`TokenManager`/`AuthManager` separately — see `vault.js`. `EventEmitter`/`SecurityLogger` are still constructed directly since this vault wires the logger's sink into its own audit-trail event channel, which is more specific than `createOwlClient`'s config covers.
- Vault state (secrets, roles, audit log) is in-memory only — restarting either entry point resets everything.
- `SSRFGuard.assertResolvedSafe()` does a real DNS lookup for non-literal hostnames in Node (unlike the browser build, which skips DNS entirely). The demo's outbound webhook target, `hooks.example.com`, doesn't have a real DNS record, so `vault.js` injects a fixed `resolveHost` returning a deterministic, non-private address for it — keeping the whole example runnable offline instead of depending on real network access.
- `npm audit --json` is run against the repo root (`../..`), since this example's own `package.json` has no dependencies to meaningfully audit. Point `NpmAuditProvider`'s `cwd` option at any project with a `package-lock.json` to scan it instead.
