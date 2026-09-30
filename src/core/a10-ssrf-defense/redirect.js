// Internal helpers shared by SafeFetcher and HTTPClient for manually followed
// redirects. Not exported from the package index.

const CREDENTIAL_HEADERS = new Set(["authorization", "proxy-authorization", "cookie", "x-csrf-token"]);
const BODY_HEADERS = new Set(["content-type", "content-length", "content-encoding", "content-language", "content-location"]);

// Accepts the same shapes fetch does (plain object, [name, value] pairs, or Headers)
// and returns the same shape without the named headers.
function withoutHeaders(headers, names) {
  if (!headers) return headers;
  if (typeof headers.forEach === "function" && typeof headers.get === "function" && typeof Headers === "function") {
    const copy = new Headers(headers);
    names.forEach((name) => copy.delete(name));
    return copy;
  }
  const entries = Array.isArray(headers) ? headers : Object.entries(headers);
  const kept = entries.filter(([name]) => !names.has(String(name).toLowerCase()));
  return Array.isArray(headers) ? kept : Object.fromEntries(kept);
}

/**
 * Returns the request init for the next hop of a redirect, following the Fetch
 * spec: credentials are dropped when the redirect leaves the current origin, and
 * a 303 (or a 301/302 after POST) becomes a bodiless GET.
 * @param {RequestInit} init
 * @param {number} status
 * @param {URL} from
 * @param {URL} to
 */
export function nextRedirectInit(init, status, from, to) {
  let next = { ...init };
  if (to.origin !== from.origin) {
    next.headers = withoutHeaders(next.headers, CREDENTIAL_HEADERS);
  }
  const method = String(next.method || "GET").toUpperCase();
  const becomesGet =
    (status === 303 && method !== "GET" && method !== "HEAD") || ((status === 301 || status === 302) && method === "POST");
  if (becomesGet) {
    next = { ...next, method: "GET", headers: withoutHeaders(next.headers, BODY_HEADERS) };
    delete next.body;
  }
  return next;
}
