/**
 * CSRF check for `middleware.ts` (or `proxy.ts` in Next.js 16): returns a 403
 * response for a state-changing request without a valid `X-CSRF-Token`, or
 * `null` to let it through. Scope the middleware's `matcher` to your API routes
 * (`/api/:path*`): Server Actions are POSTs to page URLs that don't carry the
 * header, and Next.js already checks their `Origin` itself.
 *
 * @param {Request} request
 * @param {Parameters<typeof verifyCsrf>[1] & Parameters<typeof errorResponse>[1]} [options]
 * @returns {Promise<Response | null>}
 */
export function guardCsrf(request: Request, { logger, exposeMessages, securityHeaders, ...csrf }?: Parameters<typeof verifyCsrf>[1] & Parameters<typeof errorResponse>[1]): Promise<Response | null>;
import { verifyCsrf } from "@owasp-webshield/node";
import { errorResponse } from "./response.js";
