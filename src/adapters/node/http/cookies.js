import { SecurityError, SecurityErrorCode } from "@owasp-webshield/core";
import { getHeader } from "./request.js";

// RFC 6265 cookie-name token characters.
const COOKIE_NAME_PATTERN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const SAME_SITE_VALUES = new Set(["strict", "lax", "none"]);

/**
 * Every value sent for `name`, in header order. More than one value means the
 * cookie was also set from another path or a parent domain (cookie tossing),
 * which callers that rely on the cookie for security should reject.
 * @returns {string[]}
 */
export function getCookieValues(req, name) {
  const header = getHeader(req, "cookie");
  if (typeof header !== "string") return [];
  const values = [];
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator === -1 || part.slice(0, separator).trim() !== name) continue;
    try {
      values.push(decodeURIComponent(part.slice(separator + 1).trim()));
    } catch {
      values.push("");
    }
  }
  return values;
}

/**
 * Serializes a `Set-Cookie` value with secure defaults (`Secure`, `SameSite=Strict`,
 * `Path=/`). `HttpOnly` defaults to true; turn it off only for a cookie the
 * browser has to read, such as a double-submit CSRF token.
 * @param {string} name
 * @param {string} value
 * @param {{path?: string, domain?: string, maxAge?: number, secure?: boolean, httpOnly?: boolean, sameSite?: "Strict"|"Lax"|"None"}} [options]
 */
export function serializeCookie(name, value, options = {}) {
  const { path = "/", domain, maxAge, secure = true, httpOnly = true, sameSite = "Strict" } = options;
  if (!COOKIE_NAME_PATTERN.test(name)) {
    throw new SecurityError(SecurityErrorCode.MISCONFIGURATION, `Invalid cookie name: ${name}`);
  }
  if (!SAME_SITE_VALUES.has(String(sameSite).toLowerCase())) {
    throw new SecurityError(SecurityErrorCode.MISCONFIGURATION, `Invalid SameSite value: ${sameSite}`);
  }
  if (String(sameSite).toLowerCase() === "none" && !secure) {
    throw new SecurityError(SecurityErrorCode.MISCONFIGURATION, "SameSite=None cookies must be Secure");
  }
  // Browsers only accept __Host- cookies that are Secure, have Path=/ and no Domain.
  if (name.startsWith("__Host-") && (!secure || path !== "/" || domain)) {
    throw new SecurityError(SecurityErrorCode.MISCONFIGURATION, "__Host- cookies must be Secure, Path=/ and have no Domain");
  }

  const parts = [`${name}=${encodeURIComponent(value)}`, `Path=${path}`];
  if (domain) parts.push(`Domain=${domain}`);
  if (Number.isFinite(maxAge)) parts.push(`Max-Age=${Math.floor(maxAge)}`);
  if (secure) parts.push("Secure");
  if (httpOnly) parts.push("HttpOnly");
  parts.push(`SameSite=${sameSite}`);
  return parts.join("; ");
}
