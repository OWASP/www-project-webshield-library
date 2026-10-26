import http from "node:http";
import { randomBytes } from "node:crypto";
import { pathToFileURL } from "node:url";
import { SecurityError, SecurityErrorCode } from "@owasp-webshield/core";
import {
  assertHardened,
  authenticate,
  generateCsrfToken,
  logRequestError,
  securityHeaders,
  toErrorResponse,
  verifyCsrf
} from "@owasp-webshield/node";
import { SecretsVault } from "./vault.js";

const PORT = process.env.PORT || 8787;
// Loopback only by default: the demo login hands out any role without a password,
// so the server must not be reachable from the network. Set HOST=0.0.0.0 to expose it.
const HOST = process.env.HOST || "127.0.0.1";
const SESSION_TTL_MS = 30 * 60 * 1000;
const MAX_BODY_BYTES = 64 * 1024;
const ROLES = ["viewer", "contributor", "admin"];

const SECURITY_HEADERS = securityHeaders();

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        // `status` + `expose` (the http-errors convention): toErrorResponse() turns it into a 413.
        // Stop reading; the 413 is sent with "Connection: close", so the rest is never read.
        req.pause();
        reject(Object.assign(new Error(`Request body is larger than ${MAX_BODY_BYTES} bytes`), { status: 413, expose: true }));
        return;
      }
      chunks.push(chunk);
    });
    req.on("error", reject);
    req.on("end", () => {
      if (!chunks.length) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch {
        reject(new SecurityError(SecurityErrorCode.INVALID_INPUT, "Body must be valid JSON"));
      }
    });
  });
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

function decodeParam(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    throw new SecurityError(SecurityErrorCode.INVALID_INPUT, "Malformed URL parameter");
  }
}

/**
 * Builds the HTTP server. Every login gets its own session: a random bearer
 * token and CSRF token, held server-side in `sessions` and looked up per
 * request. No request reads or writes shared "current user" state, so
 * concurrent users never see each other's session.
 */
export function createServer({ vault = new SecretsVault(), sessionTtlMs = SESSION_TTL_MS } = {}) {
  // A05: refuse to boot with an unsafe config (debug on, wildcard CORS, ...).
  assertHardened(vault.configManager, { logger: vault.logger });

  /** @type {Map<string, {userId: string, roles: string[], csrfToken: string, expiresAt: number}>} */
  const sessions = new Map();

  function createSession(role) {
    const accessToken = randomBytes(32).toString("base64url");
    const session = { userId: role, roles: [role], csrfToken: generateCsrfToken(), expiresAt: Date.now() + sessionTtlMs };
    sessions.set(accessToken, session);
    return { accessToken, csrfToken: session.csrfToken, expiresAt: session.expiresAt };
  }

  // A07: `authenticate()` keeps no state; `verifyToken` looks the token up in
  // this server's session store and rejects expired sessions.
  async function requireSession(req) {
    let token;
    const session = await authenticate(req, {
      verifyToken: (candidate) => {
        const found = sessions.get(candidate);
        if (!found) return null;
        if (found.expiresAt <= Date.now()) {
          sessions.delete(candidate);
          return null;
        }
        token = candidate;
        return found;
      }
    });
    return { token, role: session.roles[0], csrfToken: sessions.get(token).csrfToken };
  }

  // A08: synchronizer-token pattern. The expected token is the one stored in
  // this user's server-side session, not one the browser supplied.
  function requireCsrf(req, session) {
    return verifyCsrf(req, { getExpectedToken: () => session.csrfToken });
  }

  // Authenticated routes: resolve the session, check CSRF on unsafe methods, then run.
  const protectedRoute = (handler) => async (req, res, params) => {
    const session = await requireSession(req);
    await requireCsrf(req, session);
    return handler(req, res, params, session);
  };

  const routes = [
    {
      method: "POST",
      pattern: /^\/login$/,
      // DEMO ONLY: trusts the role in the request body and checks no credentials.
      handler: async (req, res) => {
        const { role } = await readJsonBody(req);
        if (!ROLES.includes(role)) {
          throw new SecurityError(SecurityErrorCode.INVALID_INPUT, "role must be viewer, contributor, or admin");
        }
        vault.logger.info("auth.login", { role });
        send(res, 200, createSession(role));
      }
    },
    {
      method: "POST",
      pattern: /^\/logout$/,
      handler: protectedRoute(async (req, res, _params, session) => {
        sessions.delete(session.token);
        send(res, 200, { loggedOut: true });
      })
    },
    {
      method: "GET",
      pattern: /^\/secrets$/,
      handler: protectedRoute(async (req, res, _params, { role }) => {
        send(res, 200, vault.listSecrets({ role }));
      })
    },
    {
      method: "POST",
      pattern: /^\/secrets$/,
      handler: protectedRoute(async (req, res, _params, { role }) => {
        const body = await readJsonBody(req);
        send(res, 201, vault.createSecret({ role, name: body.name, value: body.value, description: body.description }));
      })
    },
    {
      method: "POST",
      pattern: /^\/secrets\/([^/]+)\/reveal$/,
      handler: protectedRoute(async (req, res, [name], { role }) => {
        send(res, 200, { name, value: vault.revealSecret({ role, name }) });
      })
    },
    {
      method: "POST",
      pattern: /^\/secrets\/([^/]+)\/rotate$/,
      handler: protectedRoute(async (req, res, [name], { role }) => {
        const { newValue } = await readJsonBody(req);
        send(res, 200, vault.rotateSecret({ role, name, newValue }));
      })
    },
    {
      method: "POST",
      pattern: /^\/secrets\/([^/]+)\/freeze$/,
      handler: protectedRoute(async (req, res, [name], { role }) => {
        const { frozen } = await readJsonBody(req);
        vault.freezeSecret({ role, name, frozen: Boolean(frozen) });
        send(res, 200, { name, frozen: Boolean(frozen) });
      })
    },
    {
      method: "DELETE",
      pattern: /^\/secrets\/([^/]+)$/,
      handler: protectedRoute(async (req, res, [name], { role }) => {
        vault.deleteSecret({ role, name });
        send(res, 200, { name, deleted: true });
      })
    }
  ];

  const server = http.createServer(async (req, res) => {
    try {
      const { pathname } = new URL(req.url, "http://localhost");
      const route = routes.find((r) => r.method === req.method && r.pattern.test(pathname));
      if (!route) {
        send(res, 404, { error: "not_found" });
        return;
      }
      const params = route.pattern.exec(pathname).slice(1).map(decodeParam);
      await route.handler(req, res, params);
    } catch (error) {
      // A09: denials go to the vault's redacted audit trail as security.* events.
      logRequestError(vault.logger, error, req);
      if (!(error instanceof SecurityError) && !(error?.status >= 400 && error?.status < 500)) console.error(error);
      const { status, headers, body } = toErrorResponse(error);
      send(res, status, body, status === 413 ? { ...headers, Connection: "close" } : headers);
    }
  });
  return { server, vault, sessions };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { server } = createServer();
  server.listen(PORT, HOST, () => {
    console.log(`OWL Enabled Node Secrets App listening on http://${HOST}:${PORT}`);
    console.log("See README.md for curl examples (login, create, reveal, freeze, rotate, delete).");
  });
}
