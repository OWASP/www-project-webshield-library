import { apiRoute } from "../../../lib/auth.js";
import { portal } from "../../../lib/portal.js";

/** The claims the caller may see: their own, their team's (managers) or all (finance). */
export const GET = apiRoute(async (request, context, { session }) => Response.json(portal().claims.list(session)));

/** Submit a claim. The service validates the body and rejects unknown fields such as `status`. */
export const POST = apiRoute(
  async (request, context, { session, body }) => Response.json(portal().claims.create(session, body), { status: 201 }),
  { body: { limit: 16 * 1024 } }
);
