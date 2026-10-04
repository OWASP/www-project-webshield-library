// HTTP-level smoke test for server.js: `npm test` (Node's built-in test runner).
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "../server.js";

let server;
let base;

before(async () => {
  ({ server } = createServer({ sessionTtlMs: 500 }));
  await new Promise((resolve) => server.listen(0, resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

async function call(path, { method = "GET", token, csrf, body, rawBody } = {}) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (csrf) headers["X-CSRF-Token"] = csrf;
  if (body !== undefined || rawBody !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(base + path, { method, headers, body: rawBody ?? (body === undefined ? undefined : JSON.stringify(body)) });
  return { status: res.status, headers: res.headers, json: await res.json() };
}

const login = async (role) => (await call("/login", { method: "POST", body: { role } })).json;

test("every response carries the security headers", async () => {
  const res = await call("/secrets");
  assert.equal(res.status, 401);
  assert.equal(res.headers.get("x-content-type-options"), "nosniff");
  assert.equal(res.headers.get("www-authenticate"), "Bearer");
});

test("concurrent users keep separate sessions", async () => {
  const viewer = await login("viewer");
  const admin = await login("admin");
  assert.notEqual(viewer.accessToken, admin.accessToken);
  assert.notEqual(viewer.csrfToken, admin.csrfToken);

  const created = await call("/secrets", {
    method: "POST",
    token: admin.accessToken,
    csrf: admin.csrfToken,
    body: { name: "API_KEY", value: "sk_live_4f9Qz7Lw2Rt8Yp", description: "billing" }
  });
  assert.equal(created.status, 201);

  // The admin logging in after the viewer didn't turn the viewer into an admin.
  const viewerReveal = await call("/secrets/API_KEY/reveal", { method: "POST", token: viewer.accessToken, csrf: viewer.csrfToken });
  assert.equal(viewerReveal.status, 403);
  const adminReveal = await call("/secrets/API_KEY/reveal", { method: "POST", token: admin.accessToken, csrf: admin.csrfToken });
  assert.equal(adminReveal.json.value, "sk_live_4f9Qz7Lw2Rt8Yp");
});

test("a role in the request body can't override the session's role", async () => {
  const viewer = await login("viewer");
  const res = await call("/secrets", {
    method: "POST",
    token: viewer.accessToken,
    csrf: viewer.csrfToken,
    body: { role: "admin", name: "ESCALATED", value: "x9Qz7Lw2Rt8Yp4f" }
  });
  assert.equal(res.status, 403);
  assert.equal(res.json.error, "ACCESS_DENIED");
});

test("CSRF tokens are per session", async () => {
  const one = await login("contributor");
  const two = await login("contributor");
  const body = { name: "CSRF_TEST", value: "x9Qz7Lw2Rt8Yp4f" };
  assert.equal((await call("/secrets", { method: "POST", token: one.accessToken, body })).status, 403);
  assert.equal((await call("/secrets", { method: "POST", token: one.accessToken, csrf: two.csrfToken, body })).status, 403);
  assert.equal((await call("/secrets", { method: "POST", token: one.accessToken, csrf: one.csrfToken, body })).status, 201);
});

test("logout ends only that session", async () => {
  const one = await login("viewer");
  const two = await login("viewer");
  assert.equal((await call("/logout", { method: "POST", token: one.accessToken, csrf: one.csrfToken })).status, 200);
  assert.equal((await call("/secrets", { token: one.accessToken })).status, 401);
  assert.equal((await call("/secrets", { token: two.accessToken })).status, 200);
});

test("sessions expire", async () => {
  const viewer = await login("viewer");
  assert.equal((await call("/secrets", { token: viewer.accessToken })).status, 200);
  await new Promise((resolve) => setTimeout(resolve, 600));
  assert.equal((await call("/secrets", { token: viewer.accessToken })).status, 401);
});

test("route parameters are URL-decoded", async () => {
  const admin = await login("admin");
  const auth = { token: admin.accessToken, csrf: admin.csrfToken };
  assert.equal((await call("/secrets", { method: "POST", ...auth, body: { name: "DB PASS", value: "x9Qz7Lw2Rt8Yp4f" } })).status, 201);
  const reveal = await call("/secrets/DB%20PASS/reveal", { method: "POST", ...auth });
  assert.equal(reveal.status, 200);
  assert.equal(reveal.json.name, "DB PASS");
  assert.equal((await call("/secrets/%E0%A4%A/reveal", { method: "POST", ...auth })).status, 400);
});

test("oversized and malformed bodies are rejected", async () => {
  const contributor = await login("contributor");
  const auth = { token: contributor.accessToken, csrf: contributor.csrfToken };
  const huge = await call("/secrets", { method: "POST", ...auth, rawBody: JSON.stringify({ name: "BIG", value: "x".repeat(100_000) }) });
  assert.equal(huge.status, 413);
  const malformed = await call("/secrets", { method: "POST", ...auth, rawBody: "{not json" });
  assert.equal(malformed.status, 400);
  assert.equal(malformed.json.error, "INVALID_INPUT");
});

test("unknown routes return 404", async () => {
  assert.equal((await call("/nope")).status, 404);
});
