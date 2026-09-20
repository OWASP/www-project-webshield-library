import http from "node:http";
import { SecurityError, SecurityErrorCode } from "@owasp-core/owl";
import { SecretsVault } from "./vault.js";

// Single global session, same simplification the CLI walkthrough (index.js)
// makes — one login at a time. Re-POST /login with a different role to
// switch identities.
const vault = new SecretsVault();
const PORT = process.env.PORT || 8787;

function issueSession(role) {
  const accessToken = `demo.${role}.${Math.random().toString(36).slice(2)}`;
  vault.tokenManager.setTokens({ accessToken, expiresAt: Date.now() + 30 * 60 * 1000 });
  vault.authManager.setSession({ userId: role, roles: [role] });
  vault.csrfManager.rotateToken();
  return { accessToken, csrfToken: vault.csrfManager.getToken() };
}

function requireAuth(req) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token || token !== vault.tokenManager.getAccessToken()) {
    throw new SecurityError(SecurityErrorCode.AUTH_REQUIRED, "Missing or invalid bearer token");
  }
  return vault.authManager.getSession().roles[0];
}

function requireCsrf(req) {
  const token = req.headers["x-csrf-token"];
  vault.csrfManager.validate(token); // throws SecurityError(CSRF_INVALID) on mismatch
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

function send(res, status, body) {
  const payload = JSON.stringify(body, null, 2);
  res.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) });
  res.end(payload);
}

function errorStatus(code) {
  switch (code) {
    case SecurityErrorCode.AUTH_REQUIRED:
      return 401;
    case SecurityErrorCode.ACCESS_DENIED:
    case SecurityErrorCode.CSRF_INVALID:
    case SecurityErrorCode.SSRF_BLOCKED:
    case SecurityErrorCode.CREDENTIAL_LEAK_BLOCKED:
      return 403;
    case SecurityErrorCode.INVALID_INPUT:
      return 400;
    default:
      return 500;
  }
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
      const role = requireAuth(req);
      send(res, 200, vault.listSecrets({ role }));
    }
  },
  {
    method: "POST",
    pattern: /^\/secrets$/,
    handler: async (req, res) => {
      const role = requireAuth(req);
      requireCsrf(req);
      const body = await readJsonBody(req);
      send(res, 201, vault.createSecret({ role, ...body }));
    }
  },
  {
    method: "POST",
    pattern: /^\/secrets\/([^/]+)\/reveal$/,
    handler: async (req, res, [name]) => {
      const role = requireAuth(req);
      requireCsrf(req);
      send(res, 200, { name, value: vault.revealSecret({ role, name }) });
    }
  },
  {
    method: "POST",
    pattern: /^\/secrets\/([^/]+)\/rotate$/,
    handler: async (req, res, [name]) => {
      const role = requireAuth(req);
      requireCsrf(req);
      const { newValue } = await readJsonBody(req);
      send(res, 200, vault.rotateSecret({ role, name, newValue }));
    }
  },
  {
    method: "POST",
    pattern: /^\/secrets\/([^/]+)\/freeze$/,
    handler: async (req, res, [name]) => {
      const role = requireAuth(req);
      requireCsrf(req);
      const { frozen } = await readJsonBody(req);
      vault.freezeSecret({ role, name, frozen: Boolean(frozen) });
      send(res, 200, { name, frozen: Boolean(frozen) });
    }
  },
  {
    method: "DELETE",
    pattern: /^\/secrets\/([^/]+)$/,
    handler: async (req, res, [name]) => {
      const role = requireAuth(req);
      requireCsrf(req);
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
    if (error instanceof SecurityError) {
      send(res, errorStatus(error.code), { error: error.code, message: error.message });
      return;
    }
    console.error(error);
    send(res, 500, { error: "internal_error" });
  }
});

server.listen(PORT, () => {
  console.log(`OWL Enabled Node Secrets App listening on http://localhost:${PORT}`);
  console.log("See README.md for curl examples (login, create, reveal, freeze, rotate, delete).");
});
