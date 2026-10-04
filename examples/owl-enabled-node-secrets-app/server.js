import http from "node:http";
import { SecurityError, SecurityErrorCode } from "@owasp-webshield/core";
import {
  assertHardened,
  authenticate,
  logRequestError,
  securityHeaders,
  toErrorResponse,
  verifyCsrf
} from "@owasp-webshield/node";
import { SecretsVault } from "./vault.js";

// Single global session, same simplification the CLI walkthrough (index.js)
// makes — one login at a time. Re-POST /login with a different role to
// switch identities.
//
// DEMO ONLY: /login trusts the role in the request body and checks no credentials,
// so anyone who can reach this server can become admin. Never copy it into a real service.
const vault = new SecretsVault();
const PORT = process.env.PORT || 8787;

function issueSession(role) {
  const accessToken = `demo.${role}.${Math.random().toString(36).slice(2)}`;
  vault.tokenManager.setTokens({ accessToken, expiresAt: Date.now() + 30 * 60 * 1000 });
  vault.authManager.setSession({ userId: role, roles: [role] });
  vault.csrfManager.rotateToken();
  return { accessToken, csrfToken: vault.csrfManager.getToken() };
}

// A05 — refuse to boot with an unsafe config (debug on, wildcard CORS, ...).
assertHardened(vault.configManager, { logger: vault.logger });

const SECURITY_HEADERS = securityHeaders();

// `authenticate()` keeps no state itself; `verifyToken` decides which session a
// token belongs to. A real service would look the token up in its session store
// or verify a JWT here; this demo compares it with the one global session.
async function requireAuth(req) {
  const session = await authenticate(req, {
    verifyToken: (token) => (token === vault.tokenManager.getAccessToken() ? vault.authManager.getSession() : null)
  });
  return session.roles[0];
}

// Synchronizer-token pattern: the expected token is the one stored server-side
// for the session, not one supplied by the browser.
function requireCsrf(req) {
  return verifyCsrf(req, { getExpectedToken: () => vault.csrfManager.getToken() });
}

async function readJsonBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new SecurityError(SecurityErrorCode.INVALID_INPUT, "Body must be valid JSON");
  }
}

function send(res, status, body, headers = {}) {
  const payload = JSON.stringify(body, null, 2);
  res.writeHead(status, {
    ...SECURITY_HEADERS,
    ...headers,
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload)
  });
  res.end(payload);
}

const routes = [
  {
    method: "POST",
    pattern: /^\/login$/,
    handler: async (req, res) => {
      const { role } = await readJsonBody(req);
      if (!["viewer", "contributor", "admin"].includes(role)) {
        throw new SecurityError(SecurityErrorCode.INVALID_INPUT, "role must be viewer, contributor, or admin");
      }
      send(res, 200, issueSession(role));
    }
  },
  {
    method: "GET",
    pattern: /^\/secrets$/,
    handler: async (req, res) => {
      const role = await requireAuth(req);
      send(res, 200, vault.listSecrets({ role }));
    }
  },
  {
    method: "POST",
    pattern: /^\/secrets$/,
    handler: async (req, res) => {
      const role = await requireAuth(req);
      await requireCsrf(req);
      const body = await readJsonBody(req);
      send(res, 201, vault.createSecret({ role, ...body }));
    }
  },
  {
    method: "POST",
    pattern: /^\/secrets\/([^/]+)\/reveal$/,
    handler: async (req, res, [name]) => {
      const role = await requireAuth(req);
      await requireCsrf(req);
      send(res, 200, { name, value: vault.revealSecret({ role, name }) });
    }
  },
  {
    method: "POST",
    pattern: /^\/secrets\/([^/]+)\/rotate$/,
    handler: async (req, res, [name]) => {
      const role = await requireAuth(req);
      await requireCsrf(req);
      const { newValue } = await readJsonBody(req);
      send(res, 200, vault.rotateSecret({ role, name, newValue }));
    }
  },
  {
    method: "POST",
    pattern: /^\/secrets\/([^/]+)\/freeze$/,
    handler: async (req, res, [name]) => {
      const role = await requireAuth(req);
      await requireCsrf(req);
      const { frozen } = await readJsonBody(req);
      vault.freezeSecret({ role, name, frozen: Boolean(frozen) });
      send(res, 200, { name, frozen: Boolean(frozen) });
    }
  },
  {
    method: "DELETE",
    pattern: /^\/secrets\/([^/]+)$/,
    handler: async (req, res, [name]) => {
      const role = await requireAuth(req);
      await requireCsrf(req);
      vault.deleteSecret({ role, name });
      send(res, 200, { name, deleted: true });
    }
  }
];

const server = http.createServer(async (req, res) => {
  try {
    const { pathname } = new URL(req.url, `http://${req.headers.host}`);
    const route = routes.find((r) => r.method === req.method && r.pattern.test(pathname));
    if (!route) {
      send(res, 404, { error: "not_found" });
      return;
    }
    const match = route.pattern.exec(pathname);
    await route.handler(req, res, match.slice(1));
  } catch (error) {
    // A09 — denials go to the vault's redacted audit trail as security.* events.
    logRequestError(vault.logger, error, req);
    if (!(error instanceof SecurityError)) console.error(error);
    const { status, headers, body } = toErrorResponse(error);
    send(res, status, body, headers);
  }
});

server.listen(PORT, () => {
  console.log(`OWL Enabled Node Secrets App listening on http://localhost:${PORT}`);
  console.log("See README.md for curl examples (login, create, reveal, freeze, rotate, delete).");
});
