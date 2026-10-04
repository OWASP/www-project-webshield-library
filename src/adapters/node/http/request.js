/**
 * Request accessors shared by every helper in this package. They accept a Node
 * `IncomingMessage` (plain `node:http`, Express, Connect, Fastify's `request.raw`)
 * and a Fetch API `Request` (Next.js route handlers, Hono, Workers), so a future
 * framework adapter only has to wrap these helpers, not re-implement them.
 */

/**
 * @param {{headers?: Record<string, string|string[]|undefined> | {get: (name: string) => string|null}}} req
 * @param {string} name
 * @returns {string|undefined}
 */
export function getHeader(req, name) {
  const headers = req?.headers;
  if (!headers) return undefined;
  if (typeof headers.get === "function") return headers.get(name) ?? undefined;
  const value = headers[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

export function getMethod(req) {
  return String(req?.method || "GET").toUpperCase();
}

/**
 * Path without the query string: query strings carry OAuth codes, signed-link
 * signatures and reset tokens, which must not end up in logs.
 */
export function getPath(req) {
  const raw = req?.originalUrl || req?.url || "/";
  try {
    return new URL(raw, "http://localhost").pathname;
  } catch {
    return "/";
  }
}
