import { apiRoute } from "../../../../../lib/auth.js";
import { portal } from "../../../../../lib/portal.js";

/**
 * Approve, reject or pay. The service enforces the lifecycle, segregation of
 * duties and the manager approval limit (A04), so this endpoint and the
 * claim page's Server Action follow the same rules.
 */
export const POST = apiRoute(
  async (request, context, { session, params, body }) => Response.json(portal().claims.setStatus(session, params.id, body)),
  { body: { limit: 4 * 1024 } }
);
