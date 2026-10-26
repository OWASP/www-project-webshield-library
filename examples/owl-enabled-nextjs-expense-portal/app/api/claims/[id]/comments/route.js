import { apiRoute } from "../../../../../lib/auth.js";
import { portal } from "../../../../../lib/portal.js";

/** Add a comment. Rich text is allowed and stored sanitized (A03). */
export const POST = apiRoute(
  async (request, context, { session, params, body }) => Response.json(portal().claims.addComment(session, params.id, body), { status: 201 }),
  { body: { limit: 16 * 1024 } }
);
