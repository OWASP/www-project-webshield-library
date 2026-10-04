// End-to-end tests against the production build (`npm test` builds it first):
// starts `next start` on a free port and talks to it over HTTP, as a browser
// or an attacker would.
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { fileURLToPath } from "node:url";

const appDir = fileURLToPath(new URL("..", import.meta.url));
let server;
let base;

async function freePort() {
  const probe = createServer().listen(0);
  await new Promise((resolve) => probe.once("listening", resolve));
  const { port } = probe.address();
  await new Promise((resolve) => probe.close(resolve));
  return port;
}

before(async () => {
  const port = await freePort();
  base = `http://127.0.0.1:${port}`;
  server = spawn(process.execPath, ["node_modules/next/dist/bin/next", "start", "-p", String(port)], {
    cwd: appDir,
    // Fast password hashing for tests; production uses the 600,000-iteration default.
    env: { ...process.env, NEXT_TELEMETRY_DISABLED: "1", OWL_KDF_ITERATIONS: "1000", OWL_SIGNIN_FAILURES_PER_MINUTE: "8" },
    stdio: ["ignore", "pipe", "pipe"]
  });
  server.stderr.on("data", (chunk) => process.stderr.write(chunk));
  for (let attempt = 0; attempt < 100; attempt++) {
    try {
      await fetch(`${base}/login`);
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
  }
  throw new Error("next start did not come up");
});

after(() => server?.kill());

/**
 * A simulated browser: a cookie jar and its own client address, sent the way a
 * reverse proxy in front of the app would (the app trusts one proxy hop).
 */
let clientSeq = 0;
function browser({ ip = `198.51.100.${++clientSeq}` } = {}) {
  const jar = new Map();
  const cookieHeader = () => [...jar].map(([name, value]) => `${name}=${value}`).join("; ");

  async function call(path, { method = "GET", json, body, headers = {}, csrf = true, redirect = "manual" } = {}) {
    const allHeaders = { "X-Forwarded-For": ip, ...headers };
    if (jar.size) allHeaders.Cookie = cookieHeader();
    if (csrf && jar.has("XSRF-TOKEN") && method !== "GET") allHeaders["X-CSRF-Token"] = decodeURIComponent(jar.get("XSRF-TOKEN"));
    if (json !== undefined) allHeaders["Content-Type"] = "application/json";
    const res = await fetch(base + path, { method, headers: allHeaders, body: json !== undefined ? JSON.stringify(json) : body, redirect });
    for (const cookie of res.headers.getSetCookie()) {
      const [pair, ...attributes] = cookie.split(";");
      const [name, ...value] = pair.split("=");
      if (attributes.some((attribute) => /max-age=0|expires=thu, 01 jan 1970/i.test(attribute))) jar.delete(name.trim());
      else jar.set(name.trim(), value.join("="));
    }
    const text = await res.text();
    let data = text;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      // HTML or a file
    }
    return { status: res.status, headers: res.headers, data, setCookies: res.headers.getSetCookie() };
  }

  return { jar, call };
}

const PASSWORDS = { emma: "owl-demo-employee", omar: "owl-demo-employee", max: "owl-demo-manager", fiona: "owl-demo-finance" };

async function signedIn(username) {
  const user = browser();
  await user.call("/login"); // the proxy issues the pre-login CSRF cookie
  const res = await user.call("/api/session", { method: "POST", json: { username, password: PASSWORDS[username] } });
  assert.equal(res.status, 201, JSON.stringify(res.data));
  return user;
}

let claimSeq = 0;
const today = new Date().toISOString().slice(0, 10);
const newClaim = (overrides = {}) => ({
  merchant: `Rail Europe ${++claimSeq}`,
  amount: "128.40",
  category: "travel",
  spentOn: today,
  description: "Train to the customer workshop",
  ...overrides
});

describe("A05: headers", () => {
  test("pages get the page CSP and no X-Powered-By; API responses the strict JSON policy", async () => {
    const page = await browser().call("/login");
    assert.equal(page.status, 200);
    assert.match(page.headers.get("content-security-policy"), /script-src 'self' 'unsafe-inline'/);
    assert.equal(page.headers.get("x-frame-options"), "DENY");
    assert.equal(page.headers.get("x-powered-by"), null);

    const api = await browser().call("/api/claims");
    assert.equal(api.headers.get("content-security-policy"), "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
  });
});

describe("A07 + A08: signing in", () => {
  test("the sign-in page sets a CSRF cookie, and sign-in without it is refused (login CSRF)", async () => {
    const user = browser();
    const page = await user.call("/login");
    assert.ok(page.setCookies.some((cookie) => cookie.startsWith("XSRF-TOKEN=")));
    const forged = await user.call("/api/session", { method: "POST", json: { username: "emma", password: PASSWORDS.emma }, csrf: false });
    assert.equal(forged.status, 403);
    assert.equal(forged.data.error, "CSRF_INVALID");
  });

  test("a session cookie that script can't read, and a fresh CSRF token bound to the session", async () => {
    const user = browser();
    await user.call("/login");
    const before = user.jar.get("XSRF-TOKEN");
    const res = await user.call("/api/session", { method: "POST", json: { username: "emma", password: PASSWORDS.emma } });
    const session = res.setCookies.find((cookie) => cookie.startsWith("__Host-expense_session="));
    assert.match(session, /HttpOnly/i);
    assert.match(session, /Secure/i);
    assert.match(session, /SameSite=lax/i);
    assert.notEqual(user.jar.get("XSRF-TOKEN"), before);
  });

  test("one generic error for a wrong password and an unknown user", async () => {
    const user = browser();
    await user.call("/login");
    const wrong = await user.call("/api/session", { method: "POST", json: { username: "omar", password: "nope" } });
    const unknown = await user.call("/api/session", { method: "POST", json: { username: "mallory", password: "nope" } });
    assert.equal(wrong.status, 401);
    assert.equal(unknown.status, 401);
    assert.equal(wrong.data.message, unknown.data.message);
  });

  test("unknown fields in the sign-in body are refused", async () => {
    const user = browser();
    await user.call("/login");
    const res = await user.call("/api/session", { method: "POST", json: { username: "emma", password: PASSWORDS.emma, roles: ["finance"] } });
    assert.equal(res.status, 400);
  });

  test("signed-out visitors are sent to the sign-in page; the API answers 401", async () => {
    const visitor = browser();
    const page = await visitor.call("/claims");
    assert.equal(page.status, 307);
    assert.equal(new URL(page.headers.get("location"), base).pathname, "/login");
    assert.equal((await visitor.call("/api/claims")).status, 401);
  });

  test("signing out ends the session on the server", async () => {
    const user = await signedIn("omar");
    const stolen = user.jar.get("__Host-expense_session");
    assert.equal((await user.call("/api/session", { method: "DELETE" })).status, 204);
    const replay = await fetch(`${base}/api/claims`, { headers: { Cookie: `__Host-expense_session=${stolen}` } });
    assert.equal(replay.status, 401);
  });
});

describe("A08: CSRF on authenticated requests", () => {
  test("a token that isn't this session's is refused even when cookie and header match", async () => {
    const user = await signedIn("emma");
    // An attacker who can plant a cookie (e.g. from a sibling subdomain) still
    // doesn't know the session's token, so double submit alone isn't enough.
    user.jar.set("XSRF-TOKEN", "planted-token-value");
    const res = await user.call("/api/claims", { method: "POST", json: newClaim() });
    assert.equal(res.status, 403);
    assert.equal(res.data.error, "CSRF_INVALID");
  });
});

describe("A01 + A04: claims over the API", () => {
  let emma, omar, max, fiona;
  before(async () => {
    [emma, omar, max, fiona] = await Promise.all(["emma", "omar", "max", "fiona"].map(signedIn));
  });

  test("submitting smuggled fields (mass assignment) is refused", async () => {
    const res = await emma.call("/api/claims", { method: "POST", json: { ...newClaim(), status: "approved" } });
    assert.equal(res.status, 400);
    assert.deepEqual(res.data.errors.map((error) => error.field), ["status"]);
  });

  test("another employee's claim is a 404, not a 403", async () => {
    const created = await emma.call("/api/claims", { method: "POST", json: newClaim() });
    assert.equal(created.status, 201);
    const peek = await omar.call(`/api/claims/${created.data.id}`);
    assert.equal(peek.status, 404);
    assert.equal((await omar.call(`/claims/${created.data.id}`)).status, 404);
    assert.equal((await max.call(`/api/claims/${created.data.id}`)).status, 200); // emma's manager
    assert.ok(!(await omar.call("/api/claims")).data.some((claim) => claim.id === created.data.id));
  });

  test("approve: not your own, not as an employee, managers within their limit", async () => {
    const own = await max.call("/api/claims", { method: "POST", json: newClaim() });
    const selfApproval = await max.call(`/api/claims/${own.data.id}/status`, { method: "POST", json: { status: "approved" } });
    assert.equal(selfApproval.status, 403);
    assert.match(selfApproval.data.message, /own claim/);

    const small = await emma.call("/api/claims", { method: "POST", json: newClaim({ amount: "250.00" }) });
    assert.equal((await emma.call(`/api/claims/${small.data.id}/status`, { method: "POST", json: { status: "approved" } })).status, 403);
    assert.equal((await max.call(`/api/claims/${small.data.id}/status`, { method: "POST", json: { status: "approved" } })).data.status, "approved");

    const large = await emma.call("/api/claims", { method: "POST", json: newClaim({ amount: "4200.00", category: "equipment" }) });
    const overLimit = await max.call(`/api/claims/${large.data.id}/status`, { method: "POST", json: { status: "approved" } });
    assert.equal(overLimit.status, 403);
    assert.equal((await fiona.call(`/api/claims/${large.data.id}/status`, { method: "POST", json: { status: "approved" } })).status, 200);
  });

  test("the payout account is finance-only", async () => {
    const claim = await emma.call("/api/claims", { method: "POST", json: newClaim() });
    await max.call(`/api/claims/${claim.data.id}/status`, { method: "POST", json: { status: "approved" } });
    assert.equal((await max.call(`/api/claims/${claim.data.id}/payout`)).status, 403);
    const res = await fiona.call(`/api/claims/${claim.data.id}/payout`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("cache-control"), "no-store");
  });

  test("comments are stored sanitized and render without script", async () => {
    const claim = await emma.call("/api/claims", { method: "POST", json: newClaim() });
    const posted = await max.call(`/api/claims/${claim.data.id}/comments`, {
      method: "POST",
      json: { body: "<b>Looks fine</b><img src=x onerror=alert(document.cookie)>" }
    });
    assert.equal(posted.status, 201);
    assert.doesNotMatch(posted.data.body, /onerror/);
    const page = await emma.call(`/claims/${claim.data.id}`);
    assert.match(page.data, /<b>Looks fine<\/b>/);
    assert.doesNotMatch(page.data, /onerror/);
  });

  test("oversized and non-JSON bodies are refused before parsing", async () => {
    const big = await emma.call("/api/claims", { method: "POST", json: newClaim({ description: "x".repeat(20 * 1024) }) });
    assert.equal(big.status, 413);
    const form = await emma.call("/api/claims", { method: "POST", body: "merchant=x", headers: { "Content-Type": "application/x-www-form-urlencoded" } });
    assert.equal(form.status, 415);
  });

  test("the finance page is not found for employees", async () => {
    assert.equal((await emma.call("/finance")).status, 404);
    const page = await fiona.call("/finance");
    assert.equal(page.status, 200);
    assert.match(page.data, /Audit log/);
    assert.match(page.data, /security\.access_denied/);
  });
});

describe("A10: receipt import", () => {
  test("internal and non-HTTP targets are refused before any request", async () => {
    const emma = await signedIn("emma");
    const claim = await emma.call("/api/claims", { method: "POST", json: newClaim() });
    for (const url of ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:22/", "http://[::1]/", "http://10.0.0.5/receipt.pdf"]) {
      const res = await emma.call(`/api/claims/${claim.data.id}/receipt`, { method: "POST", json: { url } });
      assert.equal(res.status, 403, url);
      assert.equal(res.data.error, "SSRF_BLOCKED", url);
    }
    const file = await emma.call(`/api/claims/${claim.data.id}/receipt`, { method: "POST", json: { url: "file:///etc/passwd" } });
    assert.ok([400, 403].includes(file.status));
  });
});

describe("A07: brute force", () => {
  test("the account locks after 5 failures, and the client IP is throttled after more", async () => {
    const attacker = browser();
    await attacker.call("/login");
    const attempt = (username) => attacker.call("/api/session", { method: "POST", json: { username, password: "guess" } });
    for (let i = 0; i < 5; i++) assert.equal((await attempt("omar")).status, 401);
    const locked = await attacker.call("/api/session", { method: "POST", json: { username: "omar", password: PASSWORDS.omar } });
    assert.equal(locked.status, 403);
    assert.match(locked.data.message, /Too many failed sign-ins/);

    // The lockout is per account: another client with the right password is refused too.
    const victim = browser();
    await victim.call("/login");
    assert.equal((await victim.call("/api/session", { method: "POST", json: { username: "omar", password: PASSWORDS.omar } })).status, 403);

    // Spraying other accounts from the same address hits the per-IP limit (8 in tests).
    let status;
    for (let i = 0; i < 6 && status !== 429; i++) status = (await attempt(`user${i}`)).status;
    assert.equal(status, 429);
  });
});

// ---- Server Actions --------------------------------------------------------
// Submitted the way a browser without JavaScript does (progressive enhancement):
// a multipart POST to the page with the hidden action fields Next.js renders.
// An attacker can send exactly the same request, which is why every action
// checks the session and the permission itself.

const decodeHtml = (value) => value.replace(/&quot;/g, '"').replace(/&amp;/g, "&");

async function actionForm(user, path, marker) {
  const { data: html } = await user.call(path);
  const form = html.split("<form").slice(1).find((candidate) => candidate.split("</form>")[0].includes(marker));
  assert.ok(form, `no form containing ${marker} on ${path}`);
  return [...form.split("</form>")[0].matchAll(/<input type="hidden" name="([^"]+)"(?: value="([^"]*)")?/g)].map(([, name, value = ""]) => [
    name,
    decodeHtml(value)
  ]);
}

async function submitAction(user, path, hidden, fields, { origin = base } = {}) {
  const form = new FormData();
  for (const [name, value] of hidden) form.append(name, value);
  for (const [name, value] of Object.entries(fields)) form.append(name, value);
  const res = await fetch(base + path, {
    method: "POST",
    body: form,
    redirect: "manual",
    headers: { Origin: origin, ...(user ? { Cookie: [...user.jar].map(([name, value]) => `${name}=${value}`).join("; ") } : {}) }
  });
  return { status: res.status, location: res.headers.get("location"), text: await res.text() };
}

describe("Server Actions", () => {
  let emma, max, fiona, claimId, submitFields;
  before(async () => {
    [emma, max, fiona] = await Promise.all(["emma", "max", "fiona"].map(signedIn));
    submitFields = await actionForm(emma, "/claims/new", 'name="merchant"');
  });

  test("submitting a claim works without JavaScript", async () => {
    const res = await submitAction(emma, "/claims/new", submitFields, newClaim({ merchant: "Action Rail" }));
    assert.equal(res.status, 303);
    claimId = /\/claims\/(\d+)$/.exec(res.location)[1];
  });

  test("a call from another origin is aborted by Next.js", async () => {
    const res = await submitAction(emma, "/claims/new", submitFields, newClaim(), { origin: "https://evil.example" });
    assert.equal(res.status, 500);
  });

  test("a call without a session does nothing", async () => {
    const before = (await fiona.call("/api/claims")).data.length;
    const res = await submitAction(null, "/claims/new", submitFields, newClaim());
    assert.notEqual(res.status, 303);
    assert.equal((await fiona.call("/api/claims")).data.length, before);
  });

  test("replaying a manager's decision form doesn't let an employee approve", async () => {
    const decide = await actionForm(max, `/claims/${claimId}`, 'value="approved"');
    const replay = await submitAction(emma, `/claims/${claimId}`, decide, { status: "approved" });
    assert.match(replay.text, /Not allowed to approve/);
    assert.equal((await emma.call(`/api/claims/${claimId}`)).data.status, "submitted");

    await submitAction(max, `/claims/${claimId}`, decide, { status: "approved" });
    assert.equal((await emma.call(`/api/claims/${claimId}`)).data.status, "approved");
  });

  test("bank details are checked, stored and shown masked; finance pays to them", async () => {
    const bank = await actionForm(emma, "/profile", 'name="iban"');
    assert.match((await submitAction(emma, "/profile", bank, { iban: "DE00 0000 0000 0000 0000 00" })).text, /valid IBAN/);
    assert.match((await submitAction(emma, "/profile", bank, { iban: "DE89 3704 0044 0532 0130 00" })).text, /DE•• •••• 3000/);

    const pay = await actionForm(fiona, `/claims/${claimId}`, 'value="paid"');
    await submitAction(fiona, `/claims/${claimId}`, pay, { status: "paid" });
    const paid = (await emma.call(`/api/claims/${claimId}`)).data;
    assert.equal(paid.status, "paid");
    assert.equal(paid.history.at(-1).paidTo, "DE•• •••• 3000");
    assert.match((await fiona.call(`/api/claims/${claimId}/payout`)).status.toString(), /403|404/); // paid: no longer needed
  });

  test("signing out ends the session", async () => {
    const out = await actionForm(emma, "/claims", "Sign out");
    const res = await submitAction(emma, "/claims", out, {});
    assert.equal(res.status, 303);
    assert.equal((await emma.call("/api/claims")).status, 401);
  });
});

describe("A05: startup", () => {
  test("the server exits instead of starting with debug on", async () => {
    const port = await freePort();
    const child = spawn(process.execPath, ["node_modules/next/dist/bin/next", "start", "-p", String(port)], {
      cwd: appDir,
      env: { ...process.env, NEXT_TELEMETRY_DISABLED: "1", OWL_DEBUG: "true" },
      stdio: ["ignore", "pipe", "pipe"]
    });
    let output = "";
    child.stdout.on("data", (chunk) => (output += chunk));
    child.stderr.on("data", (chunk) => (output += chunk));
    const code = await new Promise((resolve) => {
      const timer = setTimeout(() => {
        child.kill();
        resolve("still running");
      }, 30_000);
      child.once("exit", (exitCode) => {
        clearTimeout(timer);
        resolve(exitCode);
      });
    });
    assert.equal(code, 1);
    assert.match(output, /refusing to start: .*debug_enabled/);
  });
});
