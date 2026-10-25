// Representative attack catalogue for the runtime benchmark (issue #54).
//
// Every scenario reproduces one weakness documented in the static benchmark
// matrices (docs/benchmarks/juice-shop.md, docs/benchmarks/nodegoat.md) against
// two local targets: `baseline` (upstream wiring, no OWL) and `owl` (the same
// routes with OWL's documented control applied). `expect` records what the
// benchmark must observe, so a result of `success` under `owl` is an explicitly
// documented coverage gap rather than an unexplained failure.
//
// `outcome: "success"`  — the weakness manifested (the attack worked).
// `outcome: "blocked"`  — a control stopped the attack.
import { ComponentPolicy } from "@owasp-webshield/core";
import { cookieOf } from "./http.js";

const STRONG_PASSWORD = "jU1cy-Secre7!";
const NODEGOAT_ALICE = { email: "alice@nodegoat.local", password: "S3cure-ish!" };
const NODEGOAT_ADMIN = { email: "admin@nodegoat.local", password: "C0rrect-Horse-Battery-9" };
// The CSRF scenario changes this account's e-mail, so it gets its own victim.
const NODEGOAT_CAROL = { id: "u4", email: "carol@nodegoat.local", password: "Carol-Passw0rd!" };

async function session(ctx, loginPath, { email, password }) {
  const response = await ctx.request({ method: "POST", path: loginPath, body: { email, password } });
  if (response.status !== 200) throw new Error(`login failed (${response.status}): ${response.text}`);
  return { cookie: cookieOf(response.headers), csrfToken: response.json.csrfToken };
}

const nodeGoatSession = (ctx) => session(ctx, "/login", NODEGOAT_ALICE);

export const SCENARIOS = [
  {
    id: "JS-01",
    app: "juice-shop",
    title: "Mass assignment: register with role=admin",
    owasp: "A08",
    cwe: "CWE-915",
    upstream: "Juice Shop: `POST /api/Users` via finale-rest (juice-shop.md J10)",
    control: "`assertValidInput(..., { allowUnknownFields: false })`",
    expect: { baseline: "success", owl: "blocked" },
    probe: async (ctx) => {
      const response = await ctx.request({
        method: "POST",
        path: "/api/Users",
        body: { email: "js01@juice-sh.op", password: STRONG_PASSWORD, role: "admin" }
      });
      if (response.status === 201 && response.json?.role === "admin") {
        return { outcome: "success", evidence: `201 Created with role="${response.json.role}"` };
      }
      return { outcome: "blocked", evidence: `${response.status} ${response.text}` };
    },
    legit: async (ctx) => {
      const response = await ctx.request({
        method: "POST",
        path: "/api/Users",
        body: { email: "js01-legit@juice-sh.op", password: STRONG_PASSWORD }
      });
      return { allowed: response.status === 201, evidence: `${response.status} role=${response.json?.role}` };
    }
  },
  {
    id: "JS-02",
    app: "juice-shop",
    title: "SQL injection login: `' OR 1=1--`",
    owasp: "A03",
    cwe: "CWE-89",
    upstream: "Juice Shop: `routes/login.ts` unparameterized query (juice-shop.md J01)",
    control: "none — OWL has no bound-parameter API (juice-shop.md R11)",
    expect: { baseline: "success", owl: "success" },
    gap: "SQL injection is unmitigated: `validateEmail` is not an injection defense.",
    probe: async (ctx) => {
      const response = await ctx.request({
        method: "POST",
        path: "/rest/login",
        body: { email: "' OR 1=1--", password: "ignored" }
      });
      if (response.status === 200 && response.json?.user?.role === "admin") {
        return {
          outcome: "success",
          evidence: `signed in as ${response.json.user.email} (role ${response.json.user.role}) with no credentials`
        };
      }
      return { outcome: "blocked", evidence: `${response.status} ${response.text}` };
    },
    legit: async (ctx) => {
      const response = await ctx.request({
        method: "POST",
        path: "/rest/login",
        body: { email: "customer@juice-sh.op", password: STRONG_PASSWORD }
      });
      return { allowed: response.status === 200, evidence: String(response.status) };
    }
  },
  {
    id: "JS-03",
    app: "juice-shop",
    title: "SSRF: fetch an internal URL as the profile image",
    owasp: "A10",
    cwe: "CWE-918",
    upstream: "Juice Shop: `routes/profileImageUrlUpload.ts` (juice-shop.md J14)",
    control: "`assertSafeOutboundUrl()` + `SafeFetcher`",
    expect: { baseline: "success", owl: "blocked" },
    probe: async (ctx) => {
      const { cookie } = await session(ctx, "/rest/login", { email: "customer@juice-sh.op", password: STRONG_PASSWORD });
      const target = `${ctx.internalServiceUrl}/latest/meta-data/iam`;
      const response = await ctx.request({
        method: "POST",
        path: "/profile-image-url",
        headers: { cookie },
        body: { url: target }
      });
      if (response.status === 200 && response.text.includes("internal-only")) {
        return { outcome: "success", evidence: `server fetched ${target} → ${response.json.bytes}` };
      }
      return { outcome: "blocked", evidence: `${response.status} ${response.text}` };
    },
    legit: async (ctx) => {
      const { cookie } = await session(ctx, "/rest/login", { email: "customer@juice-sh.op", password: STRONG_PASSWORD });
      const response = await ctx.request({
        method: "POST",
        path: "/profile-image-url",
        headers: { cookie },
        body: { url: "http://203.0.113.10/avatar.png" }
      });
      return { allowed: response.status === 200, evidence: `${response.status} bytes=${response.json?.bytes}` };
    }
  },
  {
    id: "JS-04",
    app: "juice-shop",
    title: "Weak password accepted at registration",
    owasp: "A07",
    cwe: "CWE-521",
    upstream: "Juice Shop: registration policy (juice-shop.md J19)",
    control: "`SecretPolicy.isEntropySufficient()`",
    expect: { baseline: "success", owl: "blocked" },
    probe: async (ctx) => {
      const email = "js04@juice-sh.op";
      const created = await ctx.request({
        method: "POST",
        path: "/api/Users",
        body: { email, password: "admin123" }
      });
      if (created.status !== 201) return { outcome: "blocked", evidence: `${created.status} ${created.text}` };
      const login = await ctx.request({ method: "POST", path: "/rest/login", body: { email, password: "admin123" } });
      if (login.status === 200) {
        return { outcome: "success", evidence: `account created with password "admin123"; login → ${login.status}` };
      }
      return { outcome: "error", evidence: `registered but login → ${login.status}` };
    },
    legit: async (ctx) => {
      const response = await ctx.request({
        method: "POST",
        path: "/api/Users",
        body: { email: "js04-legit@juice-sh.op", password: STRONG_PASSWORD }
      });
      return { allowed: response.status === 201, evidence: String(response.status) };
    }
  },
  {
    id: "JS-05",
    app: "juice-shop",
    title: "Forge or tamper a coupon token",
    owasp: "A02",
    cwe: "CWE-347",
    upstream: "Juice Shop: `generateCoupon` z85 token, no integrity (juice-shop.md J24)",
    control: "`CryptoManager.encrypt()` / `decrypt()` (AES-256-GCM)",
    expect: { baseline: "success", owl: "blocked" },
    probe: async (ctx) => {
      const issued = await ctx.request({ method: "GET", path: "/rest/coupon/issue?discount=10" });
      const claims = JSON.parse(Buffer.from(issued.json.token, "base64url").toString("utf8"));
      let forged;
      if (ctx.mode === "owl") {
        // The ciphertext shape is public; the key is not. Flip one byte.
        claims.ciphertext = (claims.ciphertext[0] === "A" ? "B" : "A") + claims.ciphertext.slice(1);
        forged = Buffer.from(JSON.stringify(claims)).toString("base64url");
      } else {
        // Unsigned token: anyone can encode their own claims.
        forged = Buffer.from(JSON.stringify({ discount: 100 })).toString("base64url");
      }
      const response = await ctx.request({ method: "POST", path: "/rest/coupon", body: { token: forged } });
      if (response.json?.applied && response.json.discount === 100) {
        return { outcome: "success", evidence: `forged token redeemed for discount=${response.json.discount}` };
      }
      return { outcome: "blocked", evidence: `${response.status} ${response.text}` };
    },
    legit: async (ctx) => {
      const issued = await ctx.request({ method: "GET", path: "/rest/coupon/issue?discount=10" });
      const response = await ctx.request({ method: "POST", path: "/rest/coupon", body: { token: issued.json.token } });
      return { allowed: response.json?.discount === 10, evidence: `${response.status} discount=${response.json?.discount}` };
    }
  },
  {
    id: "JS-06",
    app: "juice-shop",
    title: "Stack trace / internal detail disclosure on a failed request",
    owasp: "A05",
    cwe: "CWE-209",
    upstream: "Juice Shop: `errorhandler()` in `server.ts` (juice-shop.md J27)",
    control: "`toErrorResponse()` (5xx messages are never exposed)",
    expect: { baseline: "success", owl: "blocked" },
    probe: async (ctx) => {
      const response = await ctx.request({ method: "GET", path: "/rest/error" });
      const disclosed = response.status === 500 && (response.text.includes("SQLITE_ERROR") || response.text.includes(" at "));
      if (disclosed) {
        return {
          outcome: "success",
          evidence: `500 body exposes "${response.json?.error}"${response.json?.stack ? " plus a stack trace" : ""}`
        };
      }
      return { outcome: "blocked", evidence: `${response.status} ${response.text}` };
    }
  },
  {
    id: "NG-01",
    app: "nodegoat",
    title: "Function-level access control: user reads /benefits",
    owasp: "A01",
    cwe: "CWE-285",
    upstream: "NodeGoat: `app/routes/index.js`, `isAdmin` never applied (nodegoat.md #14)",
    control: "`assertPermission()` over `RBACManager`",
    expect: { baseline: "success", owl: "blocked" },
    probe: async (ctx) => {
      const { cookie } = await nodeGoatSession(ctx);
      const response = await ctx.request({ method: "GET", path: "/benefits", headers: { cookie } });
      if (response.status === 200 && Array.isArray(response.json?.benefits)) {
        return { outcome: "success", evidence: `200 with benefits data for role "user"` };
      }
      return { outcome: "blocked", evidence: `${response.status} ${response.text}` };
    },
    legit: async (ctx) => {
      const { cookie } = await session(ctx, "/login", NODEGOAT_ADMIN);
      const response = await ctx.request({ method: "GET", path: "/benefits", headers: { cookie } });
      return { allowed: response.status === 200, evidence: String(response.status) };
    }
  },
  {
    id: "NG-02",
    app: "nodegoat",
    title: "CSRF: cross-site POST /profile without a token",
    owasp: "A01",
    cwe: "CWE-352",
    upstream: "NodeGoat: `csurf` disabled, `POST /profile` (nodegoat.md #17)",
    control: "`verifyCsrf()` + `CSRFTokenManager` (synchronizer token)",
    expect: { baseline: "success", owl: "blocked" },
    probe: async (ctx) => {
      const { cookie } = await session(ctx, "/login", NODEGOAT_CAROL);
      const response = await ctx.request({
        method: "POST",
        path: "/profile",
        headers: { cookie, origin: "https://evil.example" },
        body: { email: "attacker@evil.example" }
      });
      if (response.status === 200 && response.json?.email === "attacker@evil.example") {
        return { outcome: "success", evidence: `tokenless cross-site POST set the profile email to ${response.json.email}` };
      }
      return { outcome: "blocked", evidence: `${response.status} ${response.text}` };
    },
    legit: async (ctx) => {
      // The attack may have replaced Carol's e-mail: log in with whatever the
      // account has now, then put the legitimate address back.
      const victim = ctx.state.users.find((user) => user.id === NODEGOAT_CAROL.id);
      const { cookie, csrfToken } = await session(ctx, "/login", { email: victim.email, password: NODEGOAT_CAROL.password });
      const response = await ctx.request({
        method: "POST",
        path: "/profile",
        headers: { cookie, "x-csrf-token": csrfToken },
        body: { email: NODEGOAT_CAROL.email }
      });
      return { allowed: response.status === 200, evidence: `${response.status} email=${response.json?.email}` };
    }
  },
  {
    id: "NG-03",
    app: "nodegoat",
    title: "Insecure direct object reference: read another user's allocations",
    owasp: "A01",
    cwe: "CWE-639",
    upstream: "NodeGoat: `GET /allocations/:userId` (nodegoat.md #13)",
    control: "none — OWL has no ownership primitive (nodegoat.md R7)",
    expect: { baseline: "success", owl: "success" },
    gap: "The OWL-wired build checks the role but never compares owner and subject.",
    probe: async (ctx) => {
      const { cookie } = await nodeGoatSession(ctx);
      const response = await ctx.request({ method: "GET", path: "/allocations/u2", headers: { cookie } });
      const rows = response.json?.allocations || [];
      if (response.status === 200 && rows.length > 0) {
        return {
          outcome: "success",
          evidence: `caller u1 (alice) read ${rows.length} allocation row(s) of u2: ${rows.map((row) => `${row.label}=${row.amount}`).join(", ")}`
        };
      }
      return { outcome: "blocked", evidence: `${response.status} ${response.text}` };
    },
    legit: async (ctx) => {
      const { cookie } = await nodeGoatSession(ctx);
      const response = await ctx.request({ method: "GET", path: "/allocations/u1", headers: { cookie } });
      return { allowed: response.status === 200 && (response.json?.allocations || []).length > 0, evidence: String(response.status) };
    }
  },
  {
    id: "NG-04",
    app: "nodegoat",
    title: "Server-side code injection through the contribution amount",
    owasp: "A03",
    cwe: "CWE-95",
    upstream: "NodeGoat: `eval(\"1+\" + preTax)` in `app/routes/contributions.js` (nodegoat.md #1)",
    control: "`assertValidInput()` with a numeric `pattern`",
    expect: { baseline: "success", owl: "blocked" },
    probe: async (ctx) => {
      const { cookie } = await nodeGoatSession(ctx);
      const payload = '-1;globalThis.__owlBenchPwned="x"';
      delete globalThis.__owlBenchPwned;
      try {
        const response = await ctx.request({
          method: "POST",
          path: "/contributions",
          headers: { cookie },
          body: { preTax: payload }
        });
        if (globalThis.__owlBenchPwned === "x") {
          return { outcome: "success", evidence: `eval ran attacker code (preTax=${JSON.stringify(payload)}, response ${response.status})` };
        }
        return { outcome: "blocked", evidence: `${response.status} ${response.text}` };
      } finally {
        delete globalThis.__owlBenchPwned;
      }
    },
    legit: async (ctx) => {
      const { cookie } = await nodeGoatSession(ctx);
      const response = await ctx.request({
        method: "POST",
        path: "/contributions",
        headers: { cookie },
        body: { preTax: "42" }
      });
      return { allowed: response.status === 200 && response.json?.total === 43, evidence: `${response.status} total=${response.json?.total}` };
    }
  },
  {
    id: "NG-05",
    app: "nodegoat",
    title: "NoSQL injection: attacker JavaScript inside the `$where` threshold",
    owasp: "A03",
    cwe: "CWE-943",
    upstream: "NodeGoat: `getByUserIdAndThreshold` `$where` string (nodegoat.md #2)",
    control: "`assertValidInput()` with a numeric `pattern`",
    expect: { baseline: "success", owl: "blocked" },
    probe: async (ctx) => {
      const { cookie } = await nodeGoatSession(ctx);
      const payload = "(globalThis.__owlBenchNoSql=1) || amount > 0";
      delete globalThis.__owlBenchNoSql;
      try {
        const response = await ctx.request({
          method: "GET",
          path: `/allocations?threshold=${encodeURIComponent(payload)}`,
          headers: { cookie }
        });
        const rows = response.json?.allocations || [];
        if (globalThis.__owlBenchNoSql === 1) {
          const belowThreshold = rows.filter((row) => row.amount < 100).length;
          return {
            outcome: "success",
            evidence: `$where executed attacker JS; ${rows.length} row(s) returned, ${belowThreshold} below the legit threshold of 100`
          };
        }
        return { outcome: "blocked", evidence: `${response.status} ${response.text}` };
      } finally {
        delete globalThis.__owlBenchNoSql;
      }
    },
    legit: async (ctx) => {
      const { cookie } = await nodeGoatSession(ctx);
      const response = await ctx.request({
        method: "GET",
        path: "/allocations?threshold=100",
        headers: { cookie }
      });
      const rows = response.json?.allocations || [];
      return { allowed: response.status === 200 && rows.length === 1, evidence: `${response.status} rows=${rows.length}` };
    }
  },
  {
    id: "NG-06",
    app: "nodegoat",
    title: "Stored XSS in a memo",
    owasp: "A03",
    cwe: "CWE-79",
    upstream: "NodeGoat: `app/views/memos.html`, autoescape off (nodegoat.md #4)",
    control: "`sanitizeFields()` with `InputSanitizer(\"moderate\")`",
    expect: { baseline: "success", owl: "blocked" },
    probe: async (ctx) => {
      const { cookie } = await nodeGoatSession(ctx);
      await ctx.request({
        method: "POST",
        path: "/memos",
        headers: { cookie },
        body: { memo: "<script>alert(1)</script>Nice list" }
      });
      const served = await ctx.request({ method: "GET", path: "/memos", headers: { cookie } });
      const memos = served.json?.memos || [];
      const injected = memos.find((memo) => memo.includes("<script>"));
      if (injected) return { outcome: "success", evidence: `memo served verbatim: ${JSON.stringify(injected)}` };
      return { outcome: "blocked", evidence: `memo stored as: ${JSON.stringify(memos[memos.length - 1])}` };
    },
    legit: async (ctx) => {
      const { cookie } = await nodeGoatSession(ctx);
      await ctx.request({ method: "POST", path: "/memos", headers: { cookie }, body: { memo: "Buy milk" } });
      const served = await ctx.request({ method: "GET", path: "/memos", headers: { cookie } });
      return { allowed: (served.json?.memos || []).includes("Buy milk"), evidence: `${served.status}` };
    }
  },
  {
    id: "NG-07",
    app: "nodegoat",
    title: "Credential brute force: no attempt limit or lockout",
    owasp: "A04",
    cwe: "CWE-307",
    upstream: "NodeGoat: `handleLoginRequest` has no lockout (nodegoat.md #12)",
    control: "none — OWL has no attempt limiter (nodegoat.md R6)",
    expect: { baseline: "success", owl: "success" },
    gap: "OWL can express the rule in `ThreatModelGuard` but counts no attempts.",
    probe: async (ctx) => {
      const statuses = [];
      for (let attempt = 0; attempt < 15; attempt++) {
        const response = await ctx.request({
          method: "POST",
          path: "/login",
          body: { email: "bob@nodegoat.local", password: `wrong-${attempt}` }
        });
        statuses.push(response.status);
      }
      const throttled = statuses.filter((status) => status === 429 || status === 403 || status === 503).length;
      const final = await ctx.request({
        method: "POST",
        path: "/login",
        body: { email: "bob@nodegoat.local", password: "bob-password-1" }
      });
      if (throttled === 0 && final.status === 200) {
        const distinct = [...new Set(statuses)].join("/");
        return { outcome: "success", evidence: `15 failed attempts → ${distinct}, no lockout; correct password after → ${final.status}` };
      }
      return { outcome: "blocked", evidence: `${throttled}/15 attempts throttled; final login → ${final.status}` };
    },
    legit: async (ctx) => {
      const response = await ctx.request({
        method: "POST",
        path: "/login",
        body: { email: "bob@nodegoat.local", password: "bob-password-1" }
      });
      return { allowed: response.status === 200, evidence: String(response.status) };
    }
  },
  {
    id: "NG-08",
    app: "nodegoat",
    title: "Vulnerable component (marked@0.3.5) loaded at startup",
    owasp: "A06",
    cwe: "CWE-1104",
    upstream: "NodeGoat: `package.json` pins `marked@0.3.5` (nodegoat.md #18)",
    control: "`ComponentPolicy` minVersions gate (startup, not per request)",
    expect: { baseline: "success", owl: "blocked" },
    probe: async (ctx) => {
      const component = { name: "marked", version: "0.3.5" };
      if (ctx.mode !== "owl") {
        return { outcome: "success", evidence: "marked@0.3.5 loaded: the baseline has no component policy" };
      }
      const verdict = new ComponentPolicy({ minVersions: { marked: "4.0.1" } }).evaluate(component);
      if (verdict.allowed) return { outcome: "success", evidence: `ComponentPolicy allowed ${component.name}@${component.version}` };
      return {
        outcome: "blocked",
        evidence: `ComponentPolicy rejected ${component.name}@${component.version}: ${verdict.reason} (requires ${verdict.required})`
      };
    },
    legit: async (ctx) => {
      if (ctx.mode !== "owl") return { allowed: true, evidence: "no policy in the baseline" };
      const verdict = new ComponentPolicy({ minVersions: { marked: "4.0.1" } }).evaluate({ name: "marked", version: "5.1.2" });
      return { allowed: verdict.allowed, evidence: verdict.reason };
    }
  },
  {
    id: "NG-09",
    app: "nodegoat",
    title: "Log injection: forge a log line through the username",
    owasp: "A09",
    cwe: "CWE-117",
    upstream: "NodeGoat: `console.log` of `userName` in `handleLoginRequest` (nodegoat.md #3)",
    control: "`SecurityLogger` JSON sink (CR/LF stay inside the string)",
    expect: { baseline: "success", owl: "blocked" },
    probe: async (ctx) => {
      const forgedUsername = 'eve\n{"level":"info","event":"audit.login_success","user":"attacker"}';
      await ctx.request({ method: "POST", path: "/login", body: { email: forgedUsername, password: "x" } });
      const forgedLine = ctx.state.logText
        .split("\n")
        .find((line) => {
          try {
            return JSON.parse(line).event === "audit.login_success";
          } catch {
            return false;
          }
        });
      if (forgedLine) return { outcome: "success", evidence: `forged entry accepted: ${forgedLine}` };
      return {
        outcome: "blocked",
        evidence: `no forged entry; the username stays on one JSON line: ${ctx.state.logText.trim().slice(0, 160)}`
      };
    }
  },
  {
    id: "NG-10",
    app: "nodegoat",
    title: "Missing security response headers (clickjacking, MIME sniffing)",
    owasp: "A05",
    cwe: "CWE-693",
    upstream: "NodeGoat: helmet commented out in `server.js` (nodegoat.md #8)",
    control: "`securityHeaders()` / `DEFAULT_SECURITY_HEADERS`",
    expect: { baseline: "success", owl: "blocked" },
    probe: async (ctx) => {
      const response = await ctx.request({ method: "GET", path: "/" });
      const required = ["content-security-policy", "x-frame-options", "x-content-type-options"];
      const missing = required.filter((name) => !response.headers.get(name));
      if (missing.length) return { outcome: "success", evidence: `missing ${missing.join(", ")}` };
      return { outcome: "blocked", evidence: `present: ${required.join(", ")}` };
    }
  }
];

export const OWASP_CATEGORIES = ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"];
