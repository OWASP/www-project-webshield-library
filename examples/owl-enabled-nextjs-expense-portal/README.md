# OWL Enabled Next.js Expense Portal

An expense-claims portal built on the Next.js App Router with
[`@owasp-webshield/next`](../../src/adapters/next/README.md). Employees submit claims, managers
approve their team's claims, and finance pays approved claims to an encrypted bank account.

The vulnerabilities that this kind of app usually ships with are covered by tests. Each one is a
real request against the production build:
- reading a colleague's claim by changing the id in the URL,
- approving your own expenses,
- sneaking `"status": "approved"` into a new claim,
- a Server Action that forgets to check who is calling,
- signing a victim in to an attacker's account,
- making the server fetch `http://169.254.169.254/` as a "receipt".

## Run locally

From this folder:

```bash
npm install
npm run dev        # http://localhost:3000
npm test           # unit tests, then a production build and HTTP tests against `next start`
npm run test:unit  # just the service tests (no build)

npm run build && npm start   # production build on http://localhost:3000
```

Use `localhost`, not `127.0.0.1`, in the browser: the session cookie is a `__Host-` cookie
(`Secure`), which browsers accept over plain HTTP only on `localhost`. Safari doesn't make that
exception, so use Chrome or Firefox locally, or serve over HTTPS.

Demo accounts (also listed on the sign-in page):

| User | Password | Role · team | Can |
|---|---|---|---|
| `emma` | `owl-demo-employee` | employee · platform | submit and follow her own claims |
| `omar` | `owl-demo-employee` | employee · sales | the same, in another team |
| `max` | `owl-demo-manager` | manager · platform | also see and approve the platform team's claims, up to $1,000 |
| `fiona` | `owl-demo-finance` | finance | see every claim, approve any amount, pay, see payout accounts, audit log |

> ⚠️ **Demo only.** The accounts are hard-coded in `lib/users.js` so this README can list them, and
> all data is in memory. A restart resets everything.

## Real-world problems and how the app handles them

| Problem | What could go wrong | What the portal does | Category |
|---|---|---|---|
| **Insecure direct object reference** | `/claims/7` shows whoever's claim #7 is | Every read goes through `claims.get(session, id)`, which checks the RBAC scope (own ⊂ team ⊂ any). A claim you can't read is a **404**, the same as one that doesn't exist, so ids can't be probed. The attempt is logged. | A01 |
| **Approving your own expenses** | A manager files and approves their own claim | Segregation of duties is a `ThreatModelGuard` rule: nobody approves, rejects or pays their own claim, finance included | A04 |
| **Approval limits** | A manager approves a $40,000 "laptop" | Over $1,000 needs `approve:large-claims`, which only finance has | A01/A04 |
| **Lifecycle abuse** | A paid claim is reopened and paid twice | `submitted → approved/rejected → paid`; rejected and paid are final. Paying needs a payout account on file | A04 |
| **Double claiming** | The same receipt is claimed twice | Same merchant, amount and date as one of your claims that wasn't rejected is refused; at most 5 pending claims per employee | A04 |
| **Mass assignment** | `{"status":"approved","ownerId":"u-fiona"}` in the create request | Schemas with `allowUnknownFields: false`; amounts are strings parsed to cents, never floats; dates must be real, not in the future, not older than 90 days | A03 |
| **Stored XSS in comments** | `<img src=x onerror=…>` steals the next reader's session | Comments are sanitized when stored (`InputSanitizer` moderate profile) and rendered through `SanitizedText`. The session cookie is HttpOnly anyway | A03 |
| **Unprotected Server Actions** | An action is a public endpoint; anyone can call it with any arguments | Every action gets the session from the cookie and goes through the same service as the API. The tests replay a manager's decision form as an employee: refused | A01 |
| **Login CSRF** | Another site signs the victim in to the attacker's account | The proxy issues an `XSRF-TOKEN` cookie on the sign-in page and requires it as `X-CSRF-Token` on every `/api` write, sign-in included | A08 |
| **CSRF on authenticated requests** | A sibling subdomain plants a cookie and double-submit passes | After sign-in, routes check the token against **the session's own** token (synchronizer pattern), not just against the cookie. A planted cookie fails | A08 |
| **Session handling** | Session fixation, stolen tokens that never expire, logout that only clears the browser | A fresh random session id at every sign-in, `__Host-` HttpOnly Secure SameSite=Lax cookie, server-side expiry, logout deletes the session on the server | A07 |
| **Credential stuffing** | Unlimited password guesses | PBKDF2 (600,000 iterations), one generic error for unknown users and wrong passwords (with a dummy hash, so timing doesn't tell them apart), a 1-minute lockout after 5 failures per account, and 10 failed sign-ins per minute per client IP | A07 |
| **Bank details at rest** | A database dump leaks every employee's IBAN | AES-256-GCM (`CryptoManager`) with a key from `BANK_DETAILS_KEY`. The IBAN is checked with mod-97, shown masked, decrypted only for finance on an approved claim, sent with `no-store`, and every reveal is audited | A02/A09 |
| **SSRF through "import receipt from URL"** | The server fetches cloud metadata or an internal admin page | `withOwl({ outboundUrl })` refuses private, loopback, link-local and non-HTTP targets. `SafeFetcher` with a pinned-DNS dispatcher re-checks every redirect and connects only to the checked address | A10 |
| **Malicious uploads** | A "receipt" is an HTML page that runs script on your origin | The file is kept only if its first bytes are a real PDF, PNG or JPEG (the remote Content-Type is ignored), reading stops at 2 MB, and downloads are `attachment` with `nosniff` and `CSP: sandbox` | A03/A10 |
| **Missing headers and leaky errors** | Clickjacking, framework fingerprinting, stack traces in responses | `securityHeadersConfig()` for pages, the strict JSON policy on API routes, `poweredByHeader: false`, and error responses that never include a 500's message | A05 |
| **Unsafe deploy** | Debug mode left on in production | `instrumentation-node.js` builds the portal at startup, which runs `assertHardened()`. With `OWL_DEBUG=true` the process exits with code 1 instead of serving 500s | A05 |
| **Vulnerable dependencies** | A known-vulnerable package ships unnoticed | Finance → Security: "Run scan" runs `npm audit` through `DependencyRiskScanner`; high or critical findings fail the policy | A06 |
| **No audit trail** | Nobody notices the attack | `SecurityLogger` records sign-ins, failures, denials, decisions and payout-account reveals, with secrets redacted. Finance sees the log | A09 |

## Try it

- **IDOR:** sign in as `omar`, open `/claims/1` (one of Emma's): "This page could not be found".
  `GET /api/claims/1` is a 404 too, and the attempt shows up in the audit log (as `fiona`, under Finance & security).
- **Segregation of duties:** as `max`, submit a claim. No Approve button is offered on it, and
  `POST /api/claims/<id>/status` with `{"status":"approved"}` is refused with 403.
- **Approval limit:** as `emma`, submit $1,500.00. `max` can reject it but not approve it;
  `fiona` can approve it.
- **Paying:** as `emma`, add `DE89 3704 0044 0532 0130 00` under Payout account. As `fiona`, open
  an approved claim, reveal the IBAN (check the audit log), then mark it paid.
- **XSS:** comment `<b>ok</b><img src=x onerror=alert(1)>`. The bold stays, the script doesn't.
- **SSRF:** import a receipt from `http://169.254.169.254/latest/meta-data/` or
  `http://127.0.0.1:22/`. Both are refused with `SSRF_BLOCKED`.
- **Brute force:** five wrong passwords lock the account for a minute.

## How it fits together

```text
proxy.js                     A08 first gate: CSRF cookie on pages, double-submit check on /api writes
instrumentation(-node).js    A05 startup hardening check; exits on a high-severity finding
next.config.mjs              A05 page security headers (API routes get withOwl's)
lib/policy.js                roles and scopes, limits, lifecycle, validation schemas
lib/claims.js                the claims service: every access and business rule, used by routes, actions and pages
lib/auth.js                  session cookie, createServerAuth(), apiRoute() (withOwl defaults), runAction()
lib/portal.js                builds the stores once per process; A09 audit log, A10 SafeFetcher, A06 scanner
lib/users.js, sessions.js    A07 password hashing, lockout, server-side sessions with per-session CSRF tokens
lib/bank-details.js          A02 encrypted IBANs
lib/receipts.js              A10 receipt download: size limit, file type by magic bytes
lib/rate-limit.js            per-IP sign-in throttle
app/api/**/route.js          JSON API, each route wrapped in withOwl()
app/actions.js               Server Actions (submit, decide, bank details, dependency scan, sign out)
app/**/page.js               Server Components; client components use @owasp-webshield/next/client
test/claims.test.js          service tests for every rule
test/http.test.js            HTTP tests against the production build, including Server Actions posted without JavaScript
```

Route handlers, Server Actions and pages never apply rules themselves. They call
`lib/claims.js` with the session, and that service decides. A rule added there applies to the
API, the forms and the pages at once.

## Production notes

- **Data:** move sessions, claims and bank details to a database or Redis. Load
  `BANK_DETAILS_KEY` (32 bytes, base64) from a KMS or secret store. Without it, a random key is
  used per process.
- **Client IP:** route handlers can't see the socket. Next.js only fills in `X-Forwarded-For` when
  the request doesn't have one, so a client talking to `next start` directly can choose it. Run
  behind a proxy that appends the real address, and set `OWL_TRUSTED_PROXY_HOPS` to the number of
  proxies (default 1). The per-account lockout doesn't depend on the IP.
- **Several instances:** the rate limiter and lockout are in memory, per instance. Use a shared
  store.
- **CSP:** the page policy allows inline scripts, which Next.js needs without nonces. For a
  stricter policy, generate a nonce in `proxy.js` and pass your own `Content-Security-Policy`.
- **Tests:** they start the app with `OWL_KDF_ITERATIONS=1000` for speed and send a distinct
  `X-Forwarded-For` per simulated browser, as a proxy would.
