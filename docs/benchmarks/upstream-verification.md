# OWL Runtime Security Benchmark — OWASP Juice Shop & NodeGoat (actual applications)

This is the benchmark reviewers asked for in [issue #54](https://github.com/OWASP/www-project-webshield-library/issues/54): the same 16 attack scenarios documented in [runtime-verification.md](./runtime-verification.md) run against **the real, pinned upstream applications** — not replicas — twice each: once as shipped (baseline) and once started through OWL's wiring preloads. It records which attacks OWL stops on the actual apps, which still succeed, and how to reproduce every number.

| | |
|---|---|
| **Issue** | [#54](https://github.com/OWASP/www-project-webshield-library/issues/54) |
| **Targets** | OWASP Juice Shop v20.2.0 (`1618a61`) and OWASP NodeGoat (`c5cb68a`), the commits of the static reviews in [juice-shop.md](./juice-shop.md) and [nodegoat.md](./nodegoat.md) |
| **Method** | 16 attack scenarios × (baseline, OWL) + a legitimate-traffic check per scenario, against the pinned deployments on loopback ports |
| **Run** | `npm run benchmark:apps:setup` (once), then `npm run benchmark:apps` |
| **Result** | 2026-10-04 · 32 checks · **13 blocked under OWL** · **3 documented gaps** · 0 expectation mismatches · 0 errors |
| **Code** | [`scripts/benchmark-apps/`](../../scripts/benchmark-apps/) |
| **Companion** | [runtime-verification.md](./runtime-verification.md) (CI-runnable replicas), [traceability-matrix.md](./traceability-matrix.md), [juice-shop.md](./juice-shop.md), [nodegoat.md](./nodegoat.md) |

## Targets

The setup script downloads both applications as source tarballs from GitHub at the reviewed commits, installs and builds them under `~/.cache/owl-issue54-apps` (override with `OWL_BENCH_APPS_DIR`), and starts MongoDB `4.4` in a local Docker container (`owl-bench-mongo`) for NodeGoat — its driver (`mongodb ^2.1.18`) cannot talk to `mongo:8+`.

Both applications run on loopback only, on fixed ports (`3100` Juice Shop, `5100` NodeGoat; override with `OWL_BENCH_JUICE_PORT` / `OWL_BENCH_NODE_PORT`), and every scenario is executed in two modes:

- **baseline** — the application exactly as shipped: `node build/app` (Juice Shop) or `node server.js` (NodeGoat). Every baseline probe must succeed, i.e. the documented weakness is live before OWL is measured.
- **owl** — the same entry point started through the OWL wiring preload: `node --import scripts/benchmark-apps/wiring/<app>.mjs <entry>`. The wiring intercepts the application's module loading to apply the documented OWL control to the existing route (for example `assertValidInput()`, `assertPermission()`, `assertSafeOutboundUrl()`, `CryptoManager`); everything else about the application is unchanged.

No scenario contacts anything outside this machine: SSRF probes target an internal metadata service the runner starts on loopback, coupons and passwords are minted by the probe itself, and the only network downloads happen once during setup.

## What a run does

1. Starts the application in baseline mode, waits until it answers its ready path, and runs its six or ten probes with the legitimate-traffic check for each.
2. Stops it, reseeds NodeGoat's database (`artifacts/db-reset.js`) so each suite starts from the shipped state, and starts the same application in OWL mode through the wiring preload.
3. Compares every observed outcome with the documented expectation, prints the results table with the evidence line for every probe, and writes each mode's full application log to `$TMPDIR/owl-bench-<app>-<mode>.log`.
4. Exits non-zero on any expectation mismatch, failed legitimate check, probe error, missing application, or missing MongoDB container.

## Results

| ID | App | OWASP | Attack | Baseline | OWL-protected | Expected (OWL) |
|---|---|---|---|---|---|---|
| JS-01 | juice-shop | A08 | Mass assignment: register with role=admin | success | blocked | blocked |
| JS-02 | juice-shop | A03 | SQL injection login: `' OR 1=1--` | success | success | success |
| JS-03 | juice-shop | A10 | SSRF: fetch an internal URL as the profile image | success | blocked | blocked |
| JS-04 | juice-shop | A07 | Weak password accepted at registration | success | blocked | blocked |
| JS-05 | juice-shop | A02 | Forge or tamper a coupon token | success | blocked | blocked |
| JS-06 | juice-shop | A05 | Stack trace / internal detail disclosure on a failed request | success | blocked | blocked |
| NG-01 | nodegoat | A01 | Function-level access control: user reads /benefits | success | blocked | blocked |
| NG-02 | nodegoat | A01 | CSRF: cross-site POST /profile without a token | success | blocked | blocked |
| NG-03 | nodegoat | A01 | Insecure direct object reference: read another user's allocations | success | success | success |
| NG-04 | nodegoat | A03 | Server-side code injection through the contribution amount | success | blocked | blocked |
| NG-05 | nodegoat | A03 | NoSQL injection: attacker JavaScript inside the `$where` threshold | success | blocked | blocked |
| NG-06 | nodegoat | A03 | Stored XSS in a memo | unexploitable | blocked | blocked |
| NG-07 | nodegoat | A04 | Credential brute force: no attempt limit or lockout | success | success | success |
| NG-08 | nodegoat | A06 | Vulnerable component (marked@0.3.5) loaded at startup | success | blocked | blocked |
| NG-09 | nodegoat | A09 | Log injection: forge a log line through the username | success | blocked | blocked |
| NG-10 | nodegoat | A05 | Missing security response headers (clickjacking, MIME sniffing) | success | blocked | blocked |

**Total: 16 probes × 2 modes = 32 checks · blocked under OWL: 13 · succeeded under OWL: 3 · errors: 0 · expectation mismatches: 0.** Every baseline probe except NG-06 (see [Notes](#notes-on-the-pinned-applications)) succeeded, so each weakness was demonstrated on the real application before the OWL control was measured against it. All 22 runnable legitimate-flow checks passed; the other 10 are skipped for documented reasons (see [Legitimate traffic](#legitimate-traffic)).

## OWASP Top 10 (2021) coverage

Every category A01–A10 has at least one running probe against the actual applications.

| Category | Scenarios | Blocked under OWL | Gap |
|---|---|---|---|
| A01 Broken Access Control | NG-01, NG-02, NG-03 | 2 | 1 (IDOR) |
| A02 Cryptographic Failures | JS-05 | 1 | — |
| A03 Injection | JS-02, NG-04, NG-05, NG-06 | 3 | 1 (SQL injection) |
| A04 Insecure Design | NG-07 | 0 | 1 (brute force) |
| A05 Security Misconfiguration | JS-06, NG-10 | 2 | — |
| A06 Vulnerable Components | NG-08 | 1 | — |
| A07 Identification & Authentication | JS-04 | 1 | — |
| A08 Software & Data Integrity | JS-01 | 1 | — |
| A09 Logging & Monitoring | NG-09 | 1 | — |
| A10 Server-Side Request Forgery | JS-03 | 1 | — |

## Verified blocked attacks (13)

Evidence lines are taken verbatim from the runner's output (abridged with `…`).

| ID | Weakness (upstream) | OWL control | Evidence |
|---|---|---|---|
| JS-01 | Mass assignment on `POST /api/Users` (J10) | `assertValidInput(..., { allowUnknownFields: false })` | `400 {"error":"INVALID_INPUT" … "field":"role" … "role is not allowed"}` |
| JS-03 | SSRF via profile image URL (J14) | `assertSafeOutboundUrl()` guarding the fetch | `302; internal service not contacted` (baseline: `1 internal request(s), response 302`) |
| JS-04 | Weak password at registration (J19) | `SecretPolicy.isEntropySufficient()` | `400 … "code":"weak_secret" … "password is too predictable"` |
| JS-05 | Unsigned, forgeable coupon token (J24) | `CryptoManager.encrypt()` / `decrypt()` (AES-256-GCM) | tampered ciphertext cannot decrypt → `404 Invalid coupon.` (baseline: `redeemed for discount=100 (response 200)`) |
| JS-06 | Stack trace disclosed on a 500 (J27) | `toErrorResponse()` | `500 {"error":"internal_error"}` (baseline: `500 body exposes "… Error: Unexpected path …"`) |
| NG-01 | Missing function-level authorization (#14) | `assertPermission()` over `RBACManager` | `403 {"error":"ACCESS_DENIED","message":"Not allowed to read benefits"}` |
| NG-02 | CSRF disabled on `POST /profile` (#17) | `verifyCsrf()` + `CSRFTokenManager` | `POST 403 {"error":"CSRF_INVALID", …}; marker absent from profile` |
| NG-04 | `eval("1+" + preTax)` (#1) | `assertValidInput()` with a numeric `pattern` | `400 … "field":"preTax" … "preTax format is invalid"`; the attacker's marker file was never created |
| NG-05 | `$where` string built from input (#2) | `assertValidInput()` with a numeric `pattern` | `400 … "field":"threshold" … "threshold format is invalid"`; no attacker JS executed |
| NG-06 | Stored XSS, autoescape off (#4) | `sanitizeFields()` with `InputSanitizer("moderate")` | `payload removed at input; marker present=true` |
| NG-08 | `marked@0.3.5` in `package.json` (#18) | `ComponentPolicy` minimum-version gate | `ComponentPolicy rejected marked@0.3.5: below_minimum_version (requires 4.0.1)` |
| NG-09 | User input written raw to the log (#3) | `SecurityLogger` JSON sink | no forged entry; the injected CR/LF stays inside the JSON `message` string of one line |
| NG-10 | helmet commented out (#8) | `securityHeaders()` / `DEFAULT_SECURITY_HEADERS` | `present: content-security-policy, x-frame-options, x-content-type-options` (baseline: `missing` all three) |

## Coverage gaps (3)

These probes succeed on the real applications under OWL **by design** — the run pins each gap so a future fix has a failing expectation to turn around. The static matrices already record the same gaps, with the roadmap items that would close them.

| ID | Weakness | Why it is not blocked | Roadmap |
|---|---|---|---|
| JS-02 | SQL injection login, `' OR 1=1--` (J01) | OWL has no bound-parameter API, and `validateEmail`/`validateSchema` are not injection defenses. The upstream query stays string-built in both modes, so OWL mode signs the attacker in as `admin` exactly as baseline: `signed in as admin@juice-sh.op (role admin) with no credentials`. | [R11](./juice-shop.md#roadmap) |
| NG-03 | IDOR: user1 reads user2's allocations (#13) | The OWL-wired route checks the caller's role (`read:allocations`) but never compares owner and subject — OWL has no ownership primitive, so a valid session still reads another user's rows: `user1 (Doe) received Will Smith's allocations page`. | [R7](./nodegoat.md#roadmap) |
| NG-07 | Credential brute force: 15 failed logins, no lockout (#12) | The OWL-wired login validates input and hashes the password but counts no attempts: `15 failed attempts -> 200, no lockout; correct password -> 302`. | [R6](./nodegoat.md#roadmap) |

## Legitimate traffic

A control that blocks everything would "pass" every probe, so each scenario also sends the legitimate version of the same request — a normal registration, a real login, an `admin` reading benefits, a same-origin profile update with the issued CSRF token, a numeric contribution, a normal memo, a correct password. **All 22 runnable checks passed in both modes**, i.e. the OWL wiring behaves like the baseline for honest users on the real applications.

Five scenarios skip the legitimate check on the actual apps (×2 modes = 10 checks), with the reason recorded in the probe itself:

| ID | Skipped legitimate check | Reason |
|---|---|---|
| JS-03 | outbound fetch of an allowed URL | The benchmark isolates the app (no external fetches), and the upstream route answers `302` whether the fetch succeeds or is blocked |
| JS-05 | redeeming an issued coupon | No HTTP-reachable issuance endpoint: upstream only mints coupons through the LLM chat tool, which needs a local model the isolated benchmark does not run |
| JS-06 | valid request | No legitimate counterpart for an invalid-path request |
| NG-09 | normal log line | The control is the shape of the log sink itself |
| NG-10 | normal response headers | The control is the response header set; the probe never relies on browsers enforcing it |

## Notes on the pinned applications

- **NG-06 baseline is `unexploitable` on NodeGoat `c5cb68a`.** The static matrix ([nodegoat.md](./nodegoat.md) #4) records stored XSS as exploitable, but on the real application the payload is stored and then rendered HTML-escaped by `marked@0.3.5` with `sanitize: true`: `payload stored but rendered HTML-escaped by marked@0.3.5 (sanitize:true); marker=true`. OWL's `sanitizeFields()` still strips the payload at input, so the OWL mode is `blocked`.
- **JS-03 is submitted form-encoded.** On the pinned Juice Shop, the `/profile/image/url` route is registered before the JSON body parser (`server.ts` registers the upload routes, then `bodyParser.text` plus the JSON workaround), so a JSON body would leave `req.body.imageUrl` undefined and never reach the fetch. The upstream Angular client posts the field as `application/x-www-form-urlencoded`; the probe does the same, and the baseline confirms the fetch reaches the internal service.

## Reproduce

Prerequisites: Node 20+, npm, Docker (for MongoDB), `curl` and `tar`, and network access for the one-time source download.

```bash
npm ci
npm run benchmark:apps:setup   # pinned sources, installs, builds, mongo:4.4 container (idempotent)
npm run benchmark:apps         # baseline + OWL for both applications
```

Useful variants:

```bash
npm run benchmark:apps -- --app=juice           # one application only
npm run benchmark:apps -- --mode=owl            # one mode only
OWL_BENCH_APPS_DIR=/path/to/apps npm run benchmark:apps   # relocate the checkouts
```

A healthy run ends with:

```
owl: 13 blocked, 3 documented gap(s) (JS-02, NG-03, NG-07); OWASP categories exercised: A01, A02, A03, A04, A05, A06, A07, A08, A09, A10
All expectations and legitimate-flow checks passed.
```

exit code `0`. The full application log of every mode is written to `$TMPDIR/owl-bench-<app>-<mode>.log`.

Cleanup:

```bash
lsof -ti :3100 :5100 | xargs kill   # stop any running benchmark servers
docker stop owl-bench-mongo         # stop MongoDB
rm -rf ~/.cache/owl-issue54-apps    # optional: remove the pinned applications
```

## Layout

| File | Role |
|---|---|
| [`scripts/benchmark-apps/setup.mjs`](../../scripts/benchmark-apps/setup.mjs) | One-time environment: pinned downloads, installs, builds, MongoDB container, OWL dist build |
| [`scripts/benchmark-apps/run.mjs`](../../scripts/benchmark-apps/run.mjs) | Runner: spawns both modes, readiness checks, reseeding, internal metadata service, report, exit code |
| [`scripts/benchmark-apps/probes.mjs`](../../scripts/benchmark-apps/probes.mjs) | The 16 scenarios: expected outcomes, probes, legitimate checks and skip reasons |
| [`scripts/benchmark-apps/wiring/hook.mjs`](../../scripts/benchmark-apps/wiring/hook.mjs) | Module-load interception: `onModuleLoad`, the Express factory hook, route-guard preloading |
| [`scripts/benchmark-apps/wiring/juice-shop.mjs`](../../scripts/benchmark-apps/wiring/juice-shop.mjs) | Juice Shop OWL wiring: input validation, secret policy, fetch guard, coupon encryption, error responses |
| [`scripts/benchmark-apps/wiring/nodegoat.mjs`](../../scripts/benchmark-apps/wiring/nodegoat.mjs) | NodeGoat OWL wiring: RBAC, CSRF, permissions, validation, sanitization, security log, headers, component gate |

## Scope and limitations

- **The wiring is ours.** Each OWL mode shows how a *documented* OWL API addresses the weakness on the upstream route; it is not a claim that Juice Shop or NodeGoat ship patched. The static matrices remain the authoritative per-challenge and per-weakness review, and their roadmap items ([R6](./nodegoat.md#roadmap), [R7](./nodegoat.md#roadmap), [R11](./juice-shop.md#roadmap)) are the gaps this run reproduces.
- **Pinned versions.** Results are specific to Juice Shop v20.2.0 (`1618a61`) and NodeGoat (`c5cb68a`); a future pin needs a rerun.
- **NG-08 is a startup gate**, not a per-request check: `ComponentPolicy.evaluate()` runs before the server answers traffic, as it would at boot.
- **State lives in the apps directory.** Probes register throwaway accounts in Juice Shop's local SQLite and log in as the seeded NodeGoat users; the NodeGoat database is reseeded before each suite.
- **No performance, fuzzing or browser-side testing** — this benchmark measures security outcomes only.
- For a hermetic, CI-run variant of the same scenarios see [runtime-verification.md](./runtime-verification.md).
