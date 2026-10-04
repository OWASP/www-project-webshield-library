import { apiRoute } from "../../../../lib/auth.js";
import { portal } from "../../../../lib/portal.js";

/** One claim; 404 for a claim the caller may not read, so ids can't be probed (A01). */
export const GET = apiRoute(async (request, context, { session, params }) => Response.json(portal().claims.get(session, params.id)));
