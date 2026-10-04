// Route handlers, middleware and next.config.js. Everything here uses only the
// Fetch API, so it doesn't import Next.js. Client components:
// @owasp-webshield/next/client; Server Components and Server Actions:
// @owasp-webshield/next/server.

export { withOwl } from "./route-handler.js";

/** @typedef {import("./route-handler.js").OwlRouteState} OwlRouteState */
/** @typedef {import("./route-handler.js").WithOwlOptions} WithOwlOptions */

export { guardCsrf } from "./middleware.js";

export { applySecurityHeaders, ensureCsrfCookie, errorResponse, issueCsrfToken, securityHeadersConfig } from "./response.js";

export { DEFAULT_BODY_LIMIT, readJsonBody } from "./body.js";

export { cookieToken } from "./session.js";

// The request-level functions, for Server Actions and anything withOwl()
// doesn't cover, so a Next.js app only needs this one import.
export {
  assertHardened,
  assertPermission,
  assertSafeOutboundUrl,
  assertValidInput,
  authenticate,
  checkPermission,
  DEFAULT_SECURITY_HEADERS,
  generateCsrfToken,
  sanitizeFields,
  statusForSecurityError,
  toErrorResponse,
  verifyCsrf
} from "@owasp-webshield/node";
