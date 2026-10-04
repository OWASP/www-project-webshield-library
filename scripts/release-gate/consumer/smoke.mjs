import assert from "node:assert/strict";
import { createRequire } from "node:module";
import * as core from "@owasp-webshield/core";
import * as react from "@owasp-webshield/react";
import * as vue from "@owasp-webshield/vue";
import * as node from "@owasp-webshield/node";
import * as expressAdapter from "@owasp-webshield/express";
import * as next from "@owasp-webshield/next";
import * as nextClient from "@owasp-webshield/next/client";
import { Argon2Adapter } from "@owasp-webshield/core/modules/a02-crypto-integrity/index.js";
import express from "express";

const cjs = createRequire(import.meta.url)("@owasp-webshield/core");
const results = [];
const ok = (name) => results.push(`ok   ${name}`);

assert.deepEqual(Object.keys(cjs).sort(), Object.keys(core).sort()); ok(`core ESM and CJS: ${Object.keys(core).length} exports each`);
assert.throws(() => new Argon2Adapter().deriveKey("p", "s"), /deriveFn is required/); ok("core modules/* deep import works (separate module instance from the root bundle)");
const owl = core.createOwlClient({ roles: { viewer: { permissions: ["read:reports"] } } });
assert.equal(owl.rbacManager.can("viewer", "read", "reports"), true); ok("core createOwlClient + RBAC");
const { key } = new core.CryptoManager({ iterations: 1000 }).deriveKey("pw");
assert.equal(key.length, 32); ok("core CryptoManager PBKDF2 (shared KDF module)");
for (const [name, mod, probe] of [["react", react, "OwlProvider"], ["vue", vue, "createOwl"], ["node", node, "authenticate"], ["express", expressAdapter, "requireAuth"], ["next", next, "withOwl"], ["next/client", nextClient, "SanitizedText"]]) {
  assert.equal(typeof mod[probe], "function", name); ok(`${name}: ${probe}() exported (${Object.keys(mod).length} exports)`);
}
assert.equal(nextClient.useAuth, react.useAuth); ok("next/client re-exports the same React adapter functions");

// instanceof across packages: one copy of core.
try { await node.authenticate(new Request("https://x/"), { verifyToken: () => null }); } catch (error) { assert.ok(error instanceof core.SecurityError); ok("SecurityError from node adapter is instanceof core's SecurityError"); }

// Express end to end.
const app = express();
app.use(expressAdapter.securityHeaders());
app.get("/r", expressAdapter.requireAuth({ verifyToken: (t) => (t === "good" ? { userId: "u1", roles: ["viewer"] } : null) }), expressAdapter.requirePermission("read", "reports", owl), (req, res) => res.json({ user: req.owl.session.userId }));
app.use(expressAdapter.errorHandler());
const server = app.listen(0);
await new Promise((r) => server.once("listening", r));
const base = `http://127.0.0.1:${server.address().port}`;
assert.equal((await fetch(`${base}/r`)).status, 401);
const good = await fetch(`${base}/r`, { headers: { Authorization: "Bearer good" } });
assert.equal(good.status, 200); assert.equal(good.headers.get("x-content-type-options"), "nosniff");
server.close(); ok("express: 401 without token, 200 with, security headers set");

// Next route handler without Next.js running.
const route = next.withOwl((req, ctx, { session, params }) => Response.json({ user: session.userId, id: params.id }), { auth: { verifyToken: (t) => (t === "good" ? { userId: "u1", roles: [] } : null) } });
assert.equal((await route(new Request("https://x/"), { params: Promise.resolve({ id: "7" }) })).status, 401);
const r = await route(new Request("https://x/", { headers: { Authorization: "Bearer good" } }), { params: Promise.resolve({ id: "7" }) });
assert.deepEqual(await r.json(), { user: "u1", id: "7" }); ok("next: withOwl 401/200 with awaited params");
console.log(results.join("\n"));
