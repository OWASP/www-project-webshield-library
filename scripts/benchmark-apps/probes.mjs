// Attack catalogue for the actual-app benchmark (issue #54).
//
// Each scenario reproduces one weakness documented in the static benchmark
// matrices (docs/benchmarks/juice-shop.md, docs/benchmarks/nodegoat.md) against
// the real, pinned deployments under ~/.cache/owl-issue54-apps (override with
// OWL_BENCH_APPS_DIR): once as shipped (`baseline`) and once started through
// the OWL wiring preloads (`owl`). `expect` records what the run must observe;
// a `success` outcome under `owl` is a documented coverage gap, and
// `unexploitable` records a documented attack that does not manifest on the
// real application at all.
//
//   outcome: "success"       the weakness manifested (the attack worked)
//   outcome: "blocked"       an OWL control stopped the attack
//   outcome: "unexploitable" the payload reaches the sink but cannot execute
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { createRequire } from "node:module";
import { ComponentPolicy } from "@owasp-webshield/core";

const STRONG_PASSWORD = "jU1cy-Secre7!";
const MONTHS = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"];

const unique = (tag) => `${tag}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}@juice-sh.op`;
const toMMMYY = (date) => MONTHS[date.getMonth()] + String(date.getFullYear()).slice(2, 4);

export const setCookiePairs = (headers) => {
  const list = typeof headers.getSetCookie === "function" ? headers.getSetCookie() : [];
  if (list.length === 0 && headers.get("set-cookie")) list.push(headers.get("set-cookie"));
  return list.map((cookie) => cookie.split(";")[0].trim()).filter(Boolean);
};
export const cookieOf = (headers) => setCookiePairs(headers).join("; ");
export const mergeCookies = (...pairs) => {
  const byName = new Map();
  for (const pair of pairs.flat()) {
    const eq = pair.indexOf("=");
    byName.set(eq === -1 ? pair : pair.slice(0, eq), pair);
  }
  return [...byName.values()].join("; ");
};
const jwtClaims = (token) => {
  try {
    return JSON.parse(Buffer.from(String(token).split(".")[1], "base64url").toString("utf8"));
  } catch {
    return {};
  }
};
const short = (text) => String(text || "").replace(/\s+/g, " ").slice(0, 160);

async function juiceRegister(ctx, tag, password = STRONG_PASSWORD) {
  const email = unique(tag);
  const response = await ctx.request({ method: "POST", path: "/api/Users", body: { email, password } });
  return { email, response };
}

async function juiceSession(ctx, tag, password = STRONG_PASSWORD) {
  const { email, response: created } = await juiceRegister(ctx, tag, password);
  if (created.status !== 201) throw new Error(`registration failed for ${tag}: ${created.status} ${short(created.text)}`);
  const login = await ctx.request({ method: "POST", path: "/rest/user/login", body: { email, password } });
  const token = login.json && login.json.authentication && login.json.authentication.token;
  if (login.status !== 200 || !token) throw new Error(`login failed for ${tag}: ${login.status} ${short(login.text)}`);
  return {
    token,
    bid: login.json.authentication.bid,
    email,
    // `req.cookies.token` feeds the profile-image route; express-jwt on
    // /rest/basket/* only accepts an Authorization header.
    headers: { cookie: `token=${token}`, authorization: `Bearer ${token}` }
  };
}

async function ngSession(ctx, password = "User1_123", userName = "user1") {
  const login = await ctx.request({ method: "POST", path: "/login", body: { userName, password } });
  if (login.status !== 302) throw new Error(`nodegoat login failed for ${userName}: ${login.status} ${short(login.text)}`);
  return { cookie: cookieOf(login.headers), setCookies: setCookiePairs(login.headers) };
}

const z85Cache = new Map();
const z85Of = (appDir) => {
  if (!z85Cache.has(appDir)) z85Cache.set(appDir, createRequire(join(appDir, "package.json"))("z85"));
  return z85Cache.get(appDir);
};

export const PROBES = [
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
        body: { email: unique("js01"), password: STRONG_PASSWORD, role: "admin" }
      });
      const role = (response.json && response.json.data && response.json.data.role) || (response.json && response.json.role);
      if (response.status === 201 && role === "admin") {
        return { outcome: "success", evidence: `201 Created with role="${role}"` };
      }
      return { outcome: "blocked", evidence: `${response.status} ${short(response.text)}` };
    },
    legit: async (ctx) => {
      const { response } = await juiceRegister(ctx, "js01-legit");
      return { allowed: response.status === 201, evidence: `${response.status}` };
    }
  },
  {
    id: "JS-02",
    app: "juice-shop",
    title: "SQL injection login: `' OR 1=1--`",
    owasp: "A03",
    cwe: "CWE-89",
    upstream: "Juice Shop: `routes/login.ts` unparameterized query (juice-shop.md J01)",
    control: "none - OWL has no bound-parameter API (juice-shop.md R11)",
    expect: { baseline: "success", owl: "success" },
    gap: "SQL injection is unmitigated: `validateEmail` is not an injection defense.",
    probe: async (ctx) => {
      const response = await ctx.request({
        method: "POST",
        path: "/rest/user/login",
        body: { email: "' OR 1=1--", password: "ignored" }
      });
      const token = response.json && response.json.authentication && response.json.authentication.token;
      if (response.status === 200 && token) {
        const claims = jwtClaims(token);
        const email = (claims.data && claims.data.email) || "unknown";
        const role = (claims.data && claims.data.role) || "unknown";
        return { outcome: "success", evidence: `signed in as ${email} (role ${role}) with no credentials` };
      }
      return { outcome: "blocked", evidence: `${response.status} ${short(response.text)}` };
    },
    legit: async (ctx) => {
      const { email, response: created } = await juiceRegister(ctx, "js02-legit");
      if (created.status !== 201) return { allowed: false, evidence: `register ${created.status}` };
      const login = await ctx.request({ method: "POST", path: "/rest/user/login", body: { email, password: STRONG_PASSWORD } });
      return { allowed: login.status === 200, evidence: `${login.status}` };
    }
  },
  {
    id: "JS-03",
    app: "juice-shop",
    title: "SSRF: fetch an internal URL as the profile image",
    owasp: "A10",
    cwe: "CWE-918",
    upstream: "Juice Shop: `routes/profileImageUrlUpload.ts` (juice-shop.md J14)",
    control: "`assertSafeOutboundUrl()` guarding `fetch`",
    expect: { baseline: "success", owl: "blocked" },
    probe: async (ctx) => {
      const session = await juiceSession(ctx, "js03");
      const target = `${ctx.internalUrl}/latest/meta-data/iam`;
      ctx.resetHits();
      // The upload routes are registered before the JSON body parser, so the
      // upstream client (and this probe) submits the URL form-encoded.
      const response = await ctx.request({
        method: "POST",
        path: "/profile/image/url",
        headers: session.headers,
        form: { imageUrl: target }
      });
      const hits = ctx.internalHits();
      if (hits.length > 0) {
        return { outcome: "success", evidence: `server fetched ${target} (${hits.length} internal request(s), response ${response.status})` };
      }
      return { outcome: "blocked", evidence: `${response.status}; internal service not contacted` };
    },
    legit: {
      skip: "no outbound legit check: the benchmark isolates the app (no external fetches), and the upstream route answers 302 whether the fetch succeeds or is blocked"
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
      const { email, response: created } = await juiceRegister(ctx, "js04", "admin123");
      if (created.status !== 201) return { outcome: "blocked", evidence: `${created.status} ${short(created.text)}` };
      const login = await ctx.request({ method: "POST", path: "/rest/user/login", body: { email, password: "admin123" } });
      if (login.status === 200) {
        return { outcome: "success", evidence: `account created with password "admin123"; login -> ${login.status}` };
      }
      return { outcome: "error", evidence: `registered but login -> ${login.status}` };
    },
    legit: async (ctx) => {
      const { response } = await juiceRegister(ctx, "js04-legit");
      return { allowed: response.status === 201, evidence: `${response.status}` };
    }
  },
  {
    id: "JS-05",
    app: "juice-shop",
    title: "Forge a coupon token (unsigned z85)",
    owasp: "A02",
    cwe: "CWE-347",
    upstream: "Juice Shop: `generateCoupon` z85 token, no integrity (juice-shop.md J24)",
    control: "`CryptoManager.encrypt()` / `decrypt()` (AES-256-GCM)",
    expect: { baseline: "success", owl: "blocked" },
    probe: async (ctx) => {
      const z85 = z85Of(ctx.appDir);
      const session = await juiceSession(ctx, "js05");
      const validity = toMMMYY(new Date());
      let forged;
      for (const discount of ["000100", "000101", "000102", "000080", "000090"]) {
        const encoded = z85.encode(`${validity}-${discount}`);
        // `?`, `#` and `%` would be eaten by URL parsing or the route's second
        // decodeURIComponent; skip such encodings instead of guessing.
        if (encoded && !/[?#%]/.test(encoded)) {
          forged = encoded;
          break;
        }
      }
      if (!forged) throw new Error(`no URL-safe z85 encoding for ${validity}`);
      const response = await ctx.request({
        method: "PUT",
        path: `/rest/basket/${session.bid}/coupon/${encodeURIComponent(forged)}`,
        headers: session.headers
      });
      if (response.json && response.json.discount === 100) {
        return { outcome: "success", evidence: `self-minted z85 coupon redeemed for discount=100 (response ${response.status})` };
      }
      return { outcome: "blocked", evidence: `${response.status} ${short(response.text)}` };
    },
    legit: {
      skip: "no HTTP-reachable issuance endpoint: upstream only mints coupons through the LLM chat tool, which needs a local model the isolated benchmark does not run"
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
      const response = await ctx.request({ method: "GET", path: "/rest/does-not-exist" });
      const disclosed =
        response.status === 500 && response.text.includes("Error:") && (response.text.includes(" at ") || response.text.includes("node_modules"));
      if (disclosed) {
        return { outcome: "success", evidence: `500 body exposes "${short(response.text)}"` };
      }
      return { outcome: "blocked", evidence: `${response.status} ${short(response.text)}` };
    },
    legit: { skip: "no legitimate counterpart for an invalid-path request" }
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
      const session = await ngSession(ctx);
      const response = await ctx.request({ method: "GET", path: "/benefits", headers: { cookie: session.cookie } });
      if (response.status === 200 && /benefit/i.test(response.text)) {
        return { outcome: "success", evidence: `200 with benefits content for role "user"` };
      }
      return { outcome: "blocked", evidence: `${response.status} ${short(response.text)}` };
    },
    legit: async (ctx) => {
      const session = await ngSession(ctx, "Admin_123", "admin");
      const response = await ctx.request({ method: "GET", path: "/benefits", headers: { cookie: session.cookie } });
      return { allowed: response.status === 200 && /benefit/i.test(response.text), evidence: `${response.status}` };
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
      const session = await ngSession(ctx);
      const marker = `Pwned${Date.now().toString(36)}`;
      const post = await ctx.request({
        method: "POST",
        path: "/profile",
        headers: { cookie: session.cookie, origin: "https://evil.example" },
        body: { firstName: marker, lastName: marker, ssn: "111-11-1111", dob: "1/1/2000", address: `addr-${marker}`, bankAcc: "1", bankRouting: "1234#" }
      });
      const page = await ctx.request({ method: "GET", path: "/profile", headers: { cookie: session.cookie } });
      if (page.text.includes(marker)) {
        return { outcome: "success", evidence: `tokenless cross-site POST updated the profile (POST ${post.status})` };
      }
      return { outcome: "blocked", evidence: `POST ${post.status} ${short(post.text)}; marker absent from profile` };
    },
    legit: async (ctx) => {
      const session = await ngSession(ctx);
      const get = await ctx.request({ method: "GET", path: "/profile", headers: { cookie: session.cookie } });
      const cookies = mergeCookies(session.setCookies, setCookiePairs(get.headers));
      const xsrf = setCookiePairs(get.headers).find((pair) => pair.startsWith("XSRF-TOKEN="));
      const headers = { cookie: cookies };
      if (xsrf) headers["x-csrf-token"] = xsrf.slice("XSRF-TOKEN=".length);
      const marker = `Legit${Date.now().toString(36)}`;
      const post = await ctx.request({
        method: "POST",
        path: "/profile",
        headers,
        body: { firstName: marker, lastName: marker, ssn: "222-22-2222", dob: "2/2/2002", address: `addr-${marker}`, bankAcc: "2", bankRouting: "1234#" }
      });
      const page = await ctx.request({ method: "GET", path: "/profile", headers: { cookie: cookies } });
      return { allowed: page.text.includes(marker), evidence: `POST ${post.status}; token issued=${Boolean(xsrf)}; updated=${page.text.includes(marker)}` };
    }
  },
  {
    id: "NG-03",
    app: "nodegoat",
    title: "IDOR: user1 reads user2's allocations",
    owasp: "A01",
    cwe: "CWE-639",
    upstream: "NodeGoat: `GET /allocations/:userId` has no ownership check (nodegoat.md #13)",
    control: "`assertPermission()` role check only - ownership is the documented gap",
    expect: { baseline: "success", owl: "success" },
    gap: "OWL checks the role, not the resource owner: `/allocations/3` stays readable as user1.",
    probe: async (ctx) => {
      const session = await ngSession(ctx);
      // threshold=0 keeps the $where predicate `stocks > '0'` satisfiable -
      // db-reset seeds stocks randomly in [1, 40], so `> '10'` can return no rows.
      const response = await ctx.request({ method: "GET", path: "/allocations/3?threshold=0", headers: { cookie: session.cookie } });
      if (response.status === 200 && /Smith/.test(response.text)) {
        return { outcome: "success", evidence: `user1 (Doe) received Will Smith's allocations page` };
      }
      return { outcome: "blocked", evidence: `${response.status} ${short(response.text)}` };
    },
    legit: async (ctx) => {
      const session = await ngSession(ctx);
      const response = await ctx.request({ method: "GET", path: "/allocations/2?threshold=0", headers: { cookie: session.cookie } });
      return { allowed: response.status === 200, evidence: `${response.status}` };
    }
  },
  {
    id: "NG-04",
    app: "nodegoat",
    title: "Server-side code injection through the contribution amount",
    owasp: "A03",
    cwe: "CWE-95",
    upstream: "NodeGoat: `eval(req.body.preTax)` in `app/routes/contributions.js` (nodegoat.md #1)",
    control: "`assertValidInput()` with a numeric `pattern`",
    expect: { baseline: "success", owl: "blocked" },
    probe: async (ctx) => {
      const session = await ngSession(ctx);
      const markerPath = join(ctx.markerDir, `ng04-${Date.now().toString(36)}`);
      const payload = `require("fs").writeFileSync(${JSON.stringify(markerPath)},"pwned")`;
      const response = await ctx.request({
        method: "POST",
        path: "/contributions",
        headers: { cookie: session.cookie },
        body: { preTax: payload, afterTax: "5", roth: "5" }
      });
      if (existsSync(markerPath)) {
        return { outcome: "success", evidence: `eval ran attacker code (POST ${response.status})` };
      }
      return { outcome: "blocked", evidence: `${response.status} ${short(response.text)}` };
    },
    legit: async (ctx) => {
      const session = await ngSession(ctx);
      const response = await ctx.request({
        method: "POST",
        path: "/contributions",
        headers: { cookie: session.cookie },
        body: { preTax: "5", afterTax: "5", roth: "5" }
      });
      const rejected = /Invalid contribution percentages|cannot exceed 30/.test(response.text);
      return { allowed: response.status === 200 && !rejected, evidence: `${response.status}; rejected=${rejected}` };
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
      const session = await ngSession(ctx);
      const response = await ctx.request({
        method: "GET",
        path: `/allocations/2?threshold=${encodeURIComponent("' || 1==1 || '")}`,
        headers: { cookie: session.cookie }
      });
      if (response.status === 200 && /Smith/.test(response.text)) {
        return { outcome: "success", evidence: `injected $where predicate returned every user's allocations (${response.status})` };
      }
      return { outcome: "blocked", evidence: `${response.status} ${short(response.text)}` };
    },
    legit: async (ctx) => {
      const session = await ngSession(ctx);
      const response = await ctx.request({ method: "GET", path: "/allocations/2?threshold=0", headers: { cookie: session.cookie } });
      return { allowed: response.status === 200, evidence: `${response.status}` };
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
    expect: { baseline: "unexploitable", owl: "blocked" },
    probe: async (ctx) => {
      const session = await ngSession(ctx);
      const marker = `Calib${Date.now().toString(36)}`;
      await ctx.request({
        method: "POST",
        path: "/memos",
        headers: { cookie: session.cookie },
        body: { memo: `<script>alert(1)</script>Nice list ${marker}` }
      });
      const served = await ctx.request({ method: "GET", path: "/memos", headers: { cookie: session.cookie } });
      if (served.text.includes("<script>alert(1)</script>")) {
        return { outcome: "success", evidence: "memo served verbatim with executable <script> tag" };
      }
      if (served.text.includes("&lt;script&gt;")) {
        return {
          outcome: "unexploitable",
          evidence: `payload stored but rendered HTML-escaped by marked@0.3.5 (sanitize:true); marker=${served.text.includes(marker)}`
        };
      }
      return { outcome: "blocked", evidence: `payload removed at input; marker present=${served.text.includes(marker)}` };
    },
    legit: async (ctx) => {
      const session = await ngSession(ctx);
      const marker = `Buy milk ${Date.now().toString(36)}`;
      await ctx.request({ method: "POST", path: "/memos", headers: { cookie: session.cookie }, body: { memo: marker } });
      const served = await ctx.request({ method: "GET", path: "/memos", headers: { cookie: session.cookie } });
      return { allowed: served.text.includes(marker), evidence: `${served.status}` };
    }
  },
  {
    id: "NG-07",
    app: "nodegoat",
    title: "Credential brute force: no attempt limit or lockout",
    owasp: "A04",
    cwe: "CWE-307",
    upstream: "NodeGoat: `handleLoginRequest` has no lockout (nodegoat.md #12)",
    control: "none - OWL has no attempt limiter (nodegoat.md R6)",
    expect: { baseline: "success", owl: "success" },
    gap: "OWL can express the rule in `ThreatModelGuard` but counts no attempts.",
    probe: async (ctx) => {
      const statuses = [];
      for (let attempt = 0; attempt < 15; attempt++) {
        const response = await ctx.request({ method: "POST", path: "/login", body: { userName: "user1", password: `wrong-${attempt}` } });
        statuses.push(response.status);
      }
      const throttled = statuses.filter((status) => status === 429 || status === 403 || status === 503).length;
      const final = await ctx.request({ method: "POST", path: "/login", body: { userName: "user1", password: "User1_123" } });
      if (throttled === 0 && final.status === 302) {
        const distinct = [...new Set(statuses)].join("/");
        return { outcome: "success", evidence: `15 failed attempts -> ${distinct}, no lockout; correct password -> ${final.status}` };
      }
      return { outcome: "blocked", evidence: `${throttled}/15 attempts throttled; final login -> ${final.status}` };
    },
    legit: async (ctx) => {
      const response = await ctx.request({ method: "POST", path: "/login", body: { userName: "user1", password: "User1_123" } });
      return { allowed: response.status === 302, evidence: `${response.status}` };
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
      const pkg = JSON.parse(readFileSync(join(ctx.appDir, "package.json"), "utf8"));
      const component = { name: "marked", version: String((pkg.dependencies && pkg.dependencies.marked) || "").replace(/^[\^~]/, "") };
      if (ctx.mode !== "owl") {
        return { outcome: "success", evidence: `marked@${component.version} allowed: the baseline has no component policy` };
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
      await ctx.request({ method: "POST", path: "/login", body: { userName: forgedUsername, password: "x" } });
      const logs = ctx.logs().slice(ctx.logStart);
      const forgedLine = logs
        .split("\n")
        .find((line) => {
          try {
            return JSON.parse(line).event === "audit.login_success";
          } catch {
            return false;
          }
        });
      if (forgedLine) return { outcome: "success", evidence: `forged entry accepted: ${forgedLine.trim()}` };
      const sample = logs.split("\n").find((line) => line.includes("invalid user")) || "";
      return { outcome: "blocked", evidence: `username stayed on one structured line: ${short(sample)}` };
    },
    legit: { skip: "no legitimate-flow counterpart: the control is the shape of the log sink itself" }
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
    },
    legit: { skip: "the control is the response header set; the probe never relies on browsers enforcing it" }
  }
];

export const OWASP_CATEGORIES = ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"];
