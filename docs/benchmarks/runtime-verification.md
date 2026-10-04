# OWL Runtime Security Benchmark — Juice Shop & NodeGoat weakness replicas

This is the runtime counterpart of the static benchmark reviews. It runs 16 representative attacks against local, isolated targets twice — once with the upstream wiring (baseline, no OWL) and once with OWL's documented control applied — and records which attacks OWL stops, which still succeed, and how to reproduce every number.

| | |
|---|---|
| **Issue** | [#54](https://github.com/OWASP/www-project-webshield-library/issues/54) |
| **Targets** | Local replicas of the weaknesses documented in [juice-shop.md](./juice-shop.md) (`J01`–`J35`) and [nodegoat.md](./nodegoat.md) (`#1`–`#22`) |
| **Method** | 16 attack scenarios × (baseline, OWL) + a legitimate-traffic check for each, against loopback servers on OS-assigned ports |
| **Run** | `npm test -- src/__tests__/benchmark` (part of `npm test`, so CI runs it) |
| **Result** | 2026-10-04 · 16 probes · **13 blocked under OWL** · **3 documented gaps** · 0 errors · 0 expectation mismatches |
| **Code** | [`src/__tests__/benchmark/`](../../src/__tests__/benchmark/) |
| **Companion** | [upstream-verification.md](./upstream-verification.md) (the same scenarios against the actual pinned apps), [traceability-matrix.md](./traceability-matrix.md), [juice-shop.md](./juice-shop.md), [nodegoat.md](./nodegoat.md) |

## Targets

Each scenario runs against **two isolated servers** bound to `127.0.0.1` on an OS-assigned port:

- **baseline** — the upstream wiring of that route: the weakness is exploitable, exactly as the static matrices describe it.
- **owl** — the same route with OWL's control applied (for example `assertValidInput()`, `assertPermission()`, `SafeFetcher`, `ComponentPolicy`). Everything else is identical.

These are **replicas of the documented routes, not the full upstream applications.** Running Juice Shop or NodeGoat in CI would mean installing their dependency trees and databases on every run, which this repository's benchmark constraints rule out; a replica of one route keeps the run hermetic, reproducible in CI, and directly comparable to the static review of that same route. The same 16 scenarios additionally run against the real, pinned applications through the opt-in `npm run benchmark:apps` — see [upstream-verification.md](./upstream-verification.md) for that run's results and reproduction steps. The static matrices remain the authoritative per-challenge and per-weakness review.

## What a run does

1. Starts five loopback servers: one internal "metadata" service (the only address an SSRF probe may reach) plus the two targets in both modes.
2. Runs every scenario's **probe** against both targets: `outcome: "success"` means the weakness manifested, `outcome: "blocked"` means a control stopped it.
3. Runs every scenario's **legitimate request** against both targets: a control that blocks normal use is a failure, not a pass.
4. Prints a results table plus per-probe evidence, and the test suite asserts the outcome of all 16 scenarios and that OWASP A01–A10 are all represented.

No scenario touches the network beyond this machine: the internal service is loopback-only, the legitimate SSRF URL uses TEST-NET-3 (`203.0.113.10`, RFC 5737) with the outbound fetch stubbed, and no external host is ever contacted.

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
| NG-06 | nodegoat | A03 | Stored XSS in a memo | success | blocked | blocked |
| NG-07 | nodegoat | A04 | Credential brute force: no attempt limit or lockout | success | success | success |
| NG-08 | nodegoat | A06 | Vulnerable component (marked@0.3.5) loaded at startup | success | blocked | blocked |
| NG-09 | nodegoat | A09 | Log injection: forge a log line through the username | success | blocked | blocked |
| NG-10 | nodegoat | A05 | Missing security response headers (clickjacking, MIME sniffing) | success | blocked | blocked |

**Total: 16 probes · blocked under OWL: 13 · succeeded under OWL: 3 · errors: 0 · expectation mismatches: 0.** All 32 legitimate-traffic checks (16 scenarios × 2 modes) passed. Every baseline probe succeeded, so each weakness was demonstrated before the OWL control was measured against it.

## OWASP Top 10 (2021) coverage

Every category A01–A10 has at least one running probe; the test suite fails if one goes uncovered.

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

| ID | Weakness (upstream) | OWL control | Evidence (abridged) |
|---|---|---|---|
| JS-01 | Mass assignment on `POST /api/Users` (J10) | `assertValidInput(..., { allowUnknownFields: false })` | `400 {"error":"INVALID_INPUT" … "role is not allowed"}` |
| JS-03 | SSRF via profile image URL (J14) | `assertSafeOutboundUrl()` + `SafeFetcher` | `403 {"error":"SSRF_BLOCKED" … "Private or loopback target blocked"}` |
| JS-04 | Weak password at registration (J19) | `SecretPolicy.isEntropySufficient()` | `400 … "weak_secret" … "password is too predictable"` |
| JS-05 | Unsigned, forgeable coupon token (J24) | `CryptoManager.encrypt()` / `decrypt()` (AES-256-GCM) | tampered ciphertext → `400 {"error":"invalid_coupon"}` |
| JS-06 | Stack trace disclosed on a 500 (J27) | `toErrorResponse()` | `500 {"error":"internal_error"}` (no stack, no SQL text) |
| NG-01 | Missing function-level authorization (#14) | `assertPermission()` over `RBACManager` | `403 {"error":"ACCESS_DENIED" … "Not allowed to read benefits"}` |
| NG-02 | CSRF disabled on `POST /profile` (#17) | `verifyCsrf()` + `CSRFTokenManager` | `403 {"error":"CSRF_INVALID" … "CSRF token validation failed"}` |
| NG-04 | `eval("1+" + preTax)` (#1) | `assertValidInput()` with a numeric `pattern` | `400 … "preTax format is invalid"`; attacker code never ran |
| NG-05 | `$where` string built from input (#2) | `assertValidInput()` with a numeric `pattern` | `400 … "threshold format is invalid"`; no attacker JS executed |
| NG-06 | Stored XSS, autoescape off (#4) | `sanitizeFields()` with `InputSanitizer("moderate")` | memo stored as `"Nice list"` — the `<script>` is gone |
| NG-08 | `marked@0.3.5` in `package.json` (#18) | `ComponentPolicy` minimum-version gate | `below_minimum_version (requires 4.0.1)` |
| NG-09 | User input written raw to the log (#3) | `SecurityLogger` JSON sink | no forged entry; the injected CR/LF stays inside one JSON line |
| NG-10 | helmet commented out (#8) | `securityHeaders()` / `DEFAULT_SECURITY_HEADERS` | `content-security-policy`, `x-frame-options`, `x-content-type-options` all present |

## Coverage gaps (3)

These probes succeed under OWL **by design** — the run pins the gap so a future fix has a failing expectation to turn around. Both static matrices already record the same gaps.

| ID | Weakness | Why it is not blocked | Roadmap |
|---|---|---|---|
| JS-02 | SQL injection login, `' OR 1=1--` (J01) | OWL has no bound-parameter API, and `validateEmail`/`validateSchema` are not injection defenses. The replica builds its query from a string in **both** modes, so the OWL mode signs the attacker in as `admin` exactly as upstream does. | [R11](./juice-shop.md#roadmap) |
| NG-03 | IDOR: user `u1` reads `u2`'s allocations (#13) | The OWL-wired route checks the caller's role (`read:allocations`) but never compares owner and subject — OWL has no ownership primitive, so a valid session can still read another user's rows. | [R7](./nodegoat.md#roadmap) |
| NG-07 | Credential brute force: 15 failed logins, no lockout (#12) | The OWL-wired login validates input and hashes the password but counts no attempts, so all 15 attempts return `401` and the correct password still works afterwards. | [R6](./nodegoat.md#roadmap) |

## Legitimate traffic

A control that blocks everything would "pass" every probe, so each scenario also sends the legitimate version of the same request — a normal registration, a real login, a same-origin profile update with the issued CSRF token, an `admin` reading benefits, a numeric contribution, an allowed outbound URL, `marked@5.1.2`. All 32 checks (16 scenarios × baseline and OWL) returned the expected success, i.e. the OWL mode behaves like the baseline for honest users.

## Reproduce

```bash
npm ci
npm test -- src/__tests__/benchmark   # this benchmark only
npm test                              # full suite (what CI runs)
```

Both commands print the results table and the evidence line for every probe. A healthy run ends with:

```
Total: 16 probes | blocked under OWL: 13 | succeeded under OWL: 3 | errors: 0 | expectation mismatches: 0
Test Suites: 1 passed, 1 total
Tests:       18 passed, 18 total
```

The 18 tests are: no probe errored, A01–A10 are all represented, and one assertion per scenario for the expected baseline/OWL outcome plus the legitimate-traffic checks. Exit code `0`, no open handles, no network access, no extra dependencies.

## Layout

| File | Role |
|---|---|
| [`src/__tests__/benchmark/scenarios.js`](../../src/__tests__/benchmark/scenarios.js) | The 16 scenarios: title, OWASP/CWE IDs, upstream reference, OWL control, expected outcome, probe and legitimate request |
| [`src/__tests__/benchmark/targets/juice-shop.js`](../../src/__tests__/benchmark/targets/juice-shop.js) | Juice Shop route replica (baseline and OWL modes) |
| [`src/__tests__/benchmark/targets/nodegoat.js`](../../src/__tests__/benchmark/targets/nodegoat.js) | NodeGoat route replica (baseline and OWL modes) |
| [`src/__tests__/benchmark/harness.js`](../../src/__tests__/benchmark/harness.js) | Starts the five servers, runs every probe, renders the report |
| [`src/__tests__/benchmark/http.js`](../../src/__tests__/benchmark/http.js) | Loopback server and client helpers (no dependencies) |
| [`src/__tests__/benchmark/runtime-benchmark.test.js`](../../src/__tests__/benchmark/runtime-benchmark.test.js) | Jest suite that asserts the expectations above |

## Scope and limitations

- **Replicas, not upstream.** The run proves OWL's controls stop (or fail to stop) the *documented* weaknesses. It does not exercise Juice Shop's or NodeGoat's full attack surface; for per-challenge coverage use [juice-shop.md](./juice-shop.md) and [nodegoat.md](./nodegoat.md).
- **Wiring is ours.** Each OWL mode shows how a *documented* OWL API addresses the weakness; it is not a claim that upstream apps are patched.
- **NG-08 is a startup gate**, not a per-request check: `ComponentPolicy.evaluate()` runs before the server answers traffic, as it would at boot.
- **No performance, fuzzing or browser-side testing** — this benchmark measures security outcomes only.
