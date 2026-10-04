// HTTP-level tests for the Express API: `npm test` (Node's built-in test runner).
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { SSRFGuard } from "@owasp-webshield/core";
import { createIncidentDeskApp } from "../server/app.js";
import { createUserStore } from "../server/users.js";

let server;
let base;
let desk;
const webhookCalls = [];

before(async () => {
  desk = createIncidentDeskApp({
    kdfIterations: 1000, // fast hashing for tests; production uses the 600,000 default
    sessionTtlMs: 2_000,
    // Offline DNS: hooks.example.com is "public", internal.example.com resolves to a private address.
    guard: new SSRFGuard({
      resolveHost: async (host) => (host === "hooks.example.com" ? ["203.0.113.10"] : ["10.0.0.7"])
    }),
    fetchImpl: async (url, init) => {
      webhookCalls.push({ url, init });
      return new Response("ok", { status: 202 });
    },
    auditProvider: { scan: async () => [{ name: "left-pad", severity: "high", currentVersion: "1.0.0" }] }
  });
  server = desk.app.listen(0);
  await new Promise((resolve) => server.once("listening", resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

async function call(path, { method = "GET", session, csrf = session?.csrfToken, body, rawBody, headers = {} } = {}) {
  const allHeaders = { ...headers };
  if (session) allHeaders.Authorization = `Bearer ${session.accessToken}`;
  if (csrf) allHeaders["X-CSRF-Token"] = csrf;
  if (body !== undefined || rawBody !== undefined) allHeaders["Content-Type"] = "application/json";
  const res = await fetch(base + path, { method, headers: allHeaders, body: rawBody ?? (body === undefined ? undefined : JSON.stringify(body)) });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = text;
  }
  return { status: res.status, headers: res.headers, json };
}

async function login(username, password = `owl-demo-${{ alice: "reporter", riley: "responder", ada: "admin" }[username]}`) {
  const res = await call("/api/session", { method: "POST", body: { username, password } });
  assert.equal(res.status, 201, JSON.stringify(res.json));
  const cookie = res.headers.get("set-cookie");
  const csrfToken = decodeURIComponent(/XSRF-TOKEN=([^;]+)/.exec(cookie)[1]);
  return { ...res.json, csrfToken, cookie };
}

const newIncident = (overrides = {}) => ({
  title: "Checkout returns 500",
  severity: "high",
  description: "<p>Customers see <b>500</b> on checkout</p>",
  ...overrides
});

describe("A07 sign-in and sessions", () => {
  test("valid credentials create a session and a script-readable CSRF cookie", async () => {
    const alice = await login("alice");
    assert.match(alice.accessToken, /^[A-Za-z0-9_-]{43}$/);
    assert.deepEqual(alice.user.roles, ["reporter"]);
    assert.match(alice.cookie, /XSRF-TOKEN=[^;]+; Path=\/; Secure; SameSite=Strict/);
    assert.doesNotMatch(alice.cookie, /HttpOnly/);
    const me = await call("/api/session", { session: alice });
    assert.equal(me.json.user.name, "Alice (reporter)");
  });

  test("unknown user and wrong password get the same answer", async () => {
    const unknown = await call("/api/session", { method: "POST", body: { username: "nobody", password: "x" } });
    const wrong = await call("/api/session", { method: "POST", body: { username: "riley", password: "x" } });
    assert.equal(unknown.status, 401);
    assert.equal(wrong.status, 401);
    assert.deepEqual(unknown.json, wrong.json);
  });

  test("repeated failures lock the account for a while", () => {
    // A store of its own, so the lockout doesn't affect the other tests' sign-ins.
    let clock = 0;
    const users = createUserStore({ kdfIterations: 1000, now: () => clock });
    for (let i = 0; i < 5; i++) assert.throws(() => users.verify("ada", "guess" + i), /Invalid username or password/);
    assert.throws(() => users.verify("ada", "owl-demo-admin"), /Too many failed sign-ins/);
    clock += 61_000;
    assert.equal(users.verify("ada", "owl-demo-admin").id, "u-ada");
    // After the lockout ends, one more mistake doesn't lock the account again.
    assert.throws(() => users.verify("ada", "typo"), /Invalid username or password/);
    assert.equal(users.verify("ada", "owl-demo-admin").id, "u-ada");
  });

  test("login rejects extra fields and wrong types", async () => {
    assert.equal((await call("/api/session", { method: "POST", body: { username: "alice", password: "owl-demo-reporter", roles: ["admin"] } })).status, 400);
    assert.equal((await call("/api/session", { method: "POST", body: { username: ["alice"], password: "x" } })).status, 400);
  });

  test("logout ends only that session and clears the CSRF cookie", async () => {
    const one = await login("alice");
    const two = await login("alice");
    const out = await call("/api/session", { method: "DELETE", session: one });
    assert.equal(out.status, 204);
    assert.match(out.headers.get("set-cookie"), /XSRF-TOKEN=; Path=\/; Max-Age=0/);
    assert.equal((await call("/api/incidents", { session: one })).status, 401);
    assert.equal((await call("/api/incidents", { session: two })).status, 200);
  });

  test("sessions expire", async () => {
    const alice = await login("alice");
    await new Promise((resolve) => setTimeout(resolve, 2_100));
    const res = await call("/api/incidents", { session: alice });
    assert.equal(res.status, 401);
    assert.equal(res.headers.get("www-authenticate"), "Bearer");
  });
});

describe("A08 CSRF", () => {
  test("writes need this session's token; reads don't", async () => {
    const alice = await login("alice");
    const other = await login("alice");
    assert.equal((await call("/api/incidents", { session: alice, csrf: null })).status, 200);
    assert.equal((await call("/api/incidents", { method: "POST", session: alice, csrf: null, body: newIncident() })).status, 403);
    assert.equal((await call("/api/incidents", { method: "POST", session: alice, csrf: other.csrfToken, body: newIncident() })).status, 403);
    assert.equal((await call("/api/incidents", { method: "POST", session: alice, body: newIncident() })).status, 201);
  });
});

describe("A01 access control", () => {
  test("roles are enforced by the API, not just hidden in the UI", async () => {
    const alice = await login("alice");
    const riley = await login("riley");
    const created = await call("/api/incidents", { method: "POST", session: alice, body: newIncident() });
    const id = created.json.id;

    assert.equal((await call(`/api/incidents/${id}/status`, { method: "PATCH", session: alice, body: { status: "investigating" } })).status, 403);
    assert.equal((await call(`/api/incidents/${id}/notes`, { session: alice })).status, 403);
    assert.equal((await call(`/api/incidents/${id}`, { method: "DELETE", session: riley })).status, 403);
    assert.equal((await call("/api/admin/audit", { session: riley })).status, 403);
    assert.equal((await call(`/api/incidents/${id}/status`, { method: "PATCH", session: riley, body: { status: "investigating" } })).status, 200);
  });

  test("locking an incident denies updates and notes even to admins", async () => {
    const riley = await login("riley");
    const ada = await login("ada");
    const { json: incident } = await call("/api/incidents", { method: "POST", session: riley, body: newIncident() });
    const path = `/api/incidents/${incident.id}`;

    assert.equal((await call(`${path}/lock`, { method: "PUT", session: riley, body: { locked: true } })).status, 403);
    assert.equal((await call(`${path}/lock`, { method: "PUT", session: ada, body: { locked: true } })).json.locked, true);
    assert.equal((await call(`${path}/status`, { method: "PATCH", session: ada, body: { status: "investigating" } })).status, 403);
    assert.equal((await call(`${path}/notes`, { method: "POST", session: riley, body: { text: "x" } })).status, 403);
    assert.equal((await call(path, { session: riley })).status, 200); // still readable

    await call(`${path}/lock`, { method: "PUT", session: ada, body: { locked: false } });
    assert.equal((await call(`${path}/status`, { method: "PATCH", session: ada, body: { status: "investigating" } })).status, 200);
  });

  test("a reporter can't make themselves the reporter of record for someone else", async () => {
    const alice = await login("alice");
    const res = await call("/api/incidents", { method: "POST", session: alice, body: { ...newIncident(), reporterId: "u-ada" } });
    assert.equal(res.status, 400);
    assert.equal(res.json.errors[0].field, "reporterId");
  });
});

describe("A03 validation and sanitization", () => {
  test("field errors come back per field, without the submitted values", async () => {
    const alice = await login("alice");
    const res = await call("/api/incidents", { method: "POST", session: alice, body: { title: "x", severity: "apocalyptic", description: "" } });
    assert.equal(res.status, 400);
    assert.deepEqual(res.json.errors.map((e) => e.field).sort(), ["description", "severity", "title"]);
    assert.doesNotMatch(JSON.stringify(res.json), /apocalyptic/);
  });

  test("stored descriptions are sanitized, and sanitizing again changes nothing", async () => {
    const alice = await login("alice");
    const description = `<p>Tom &amp; Jerry <b>broke</b> it</p><img src=x onerror="alert(1)"><a href="javascript:alert(2)">x</a><script>alert(3)</script>`;
    const { json } = await call("/api/incidents", { method: "POST", session: alice, body: newIncident({ description }) });
    assert.doesNotMatch(json.description, /onerror|javascript:|<script/i);
    assert.match(json.description, /<b>broke<\/b>/);
    assert.match(json.description, /Tom &amp; Jerry/);
  });
});

describe("A04 insecure design guards", () => {
  test("the lifecycle only allows defined transitions, and closed is final", async () => {
    const riley = await login("riley");
    const { json: incident } = await call("/api/incidents", { method: "POST", session: riley, body: newIncident() });
    const move = (status) => call(`/api/incidents/${incident.id}/status`, { method: "PATCH", session: riley, body: { status } });
    assert.equal((await move("resolved")).status, 400); // open -> resolved skips investigating
    assert.equal((await move("investigating")).status, 200);
    assert.equal((await move("resolved")).status, 200);
    assert.equal((await move("closed")).status, 200);
    const reopen = await move("open");
    assert.equal(reopen.status, 400);
    assert.match(reopen.json.message, /can't move from closed to open/);
  });

  test("one person can't flood the desk with open incidents", async () => {
    // A user record of its own, so other tests' incidents don't count towards the cap.
    const flood = createIncidentDeskApp({ kdfIterations: 1000, auditProvider: { scan: async () => [] } });
    const reporter = { userId: "u-flood", metadata: { name: "Flood" } };
    for (let i = 0; i < 10; i++) flood.incidents.create(newIncident({ title: `Incident ${i}` }), reporter);
    assert.throws(() => flood.incidents.create(newIncident(), reporter), /already have 10 open incidents/);
  });
});

describe("A02 encrypted private notes and A09 redacted audit log", () => {
  test("notes are stored encrypted and never logged in clear", async () => {
    const riley = await login("riley");
    const ada = await login("ada");
    const { json: incident } = await call("/api/incidents", { method: "POST", session: riley, body: newIncident() });
    const secret = "Root cause: leaked staging key sk_test_9f8e7d";
    assert.equal((await call(`/api/incidents/${incident.id}/notes`, { method: "POST", session: riley, body: { text: secret } })).status, 201);

    const stored = desk.incidents.rawNotes(incident.id);
    assert.equal(stored.length, 1);
    assert.doesNotMatch(JSON.stringify(stored), /leaked staging key/);
    assert.equal((await call(`/api/incidents/${incident.id}/notes`, { session: riley })).json[0].text, secret);

    const audit = (await call("/api/admin/audit", { session: ada })).json;
    const serialized = JSON.stringify(audit);
    assert.doesNotMatch(serialized, /leaked staging key|owl-demo-|sk_test_/);
    assert.ok(audit.some((entry) => entry.event === "incident.note_added" && entry.details.secretNote === "[REDACTED]"));
    assert.ok(audit.some((entry) => entry.event === "security.access_denied"));
  });
});

describe("A10 SSRF-guarded webhook test", () => {
  test("public targets are called; internal and metadata targets are blocked", async () => {
    const ada = await login("ada");
    const test = (url) => call("/api/admin/webhook-test", { method: "POST", session: ada, body: { url } });

    const delivered = await test("https://hooks.example.com/owl");
    assert.deepEqual(delivered.json, { delivered: true, status: 202 });
    assert.equal(webhookCalls.at(-1).url, "https://hooks.example.com/owl");

    const before = webhookCalls.length;
    for (const url of ["http://169.254.169.254/latest/meta-data", "http://127.0.0.1:8080/", "https://internal.example.com/", "file:///etc/passwd"]) {
      const res = await test(url);
      assert.equal(res.status, 403, url);
      assert.equal(res.json.error, "SSRF_BLOCKED", url);
    }
    assert.equal((await test("not a url")).status, 400);
    assert.equal(webhookCalls.length, before);
  });

  test("only admins can trigger it", async () => {
    const riley = await login("riley");
    assert.equal((await call("/api/admin/webhook-test", { method: "POST", session: riley, body: { url: "https://hooks.example.com/" } })).status, 403);
  });
});

describe("A05 and A06 reports, headers and limits", () => {
  test("the security report and dependency scan are admin-only", async () => {
    const ada = await login("ada");
    const report = await call("/api/admin/security-report", { session: ada });
    assert.deepEqual(report.json.hardening, []);
    assert.equal(report.json.designChecklist.valid, true);
    const scan = await call("/api/admin/dependency-scan", { method: "POST", session: ada });
    assert.equal(scan.json.passes, false);
    assert.equal(scan.json.findings[0].package, "left-pad");
  });

  test("the server refuses to start with debug on", () => {
    assert.throws(
      () => createIncidentDeskApp({ kdfIterations: 1000, config: { debug: true, cors: { origin: "*" } } }),
      /debug_enabled, wildcard_cors/
    );
  });

  test("responses carry the CSP and security headers, never X-Powered-By", async () => {
    const res = await call("/api/incidents");
    assert.match(res.headers.get("content-security-policy"), /default-src 'self'; script-src 'self'/);
    assert.equal(res.headers.get("x-frame-options"), "DENY");
    assert.equal(res.headers.get("x-powered-by"), null);
  });

  test("oversized and malformed bodies are rejected before any handler runs", async () => {
    const alice = await login("alice");
    const huge = await call("/api/incidents", { method: "POST", session: alice, rawBody: JSON.stringify(newIncident({ description: "x".repeat(40_000) })) });
    assert.equal(huge.status, 413);
    const malformed = await call("/api/incidents", { method: "POST", session: alice, rawBody: "{oops" });
    assert.equal(malformed.status, 400);
    assert.equal(malformed.json.error, "bad_request");
  });
});
