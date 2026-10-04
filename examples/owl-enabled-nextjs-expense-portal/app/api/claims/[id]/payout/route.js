import { apiRoute } from "../../../../../lib/auth.js";
import { portal } from "../../../../../lib/portal.js";

/**
 * A02/A09: the full payout account, for finance paying an approved claim. Each
 * read is decrypted on demand and written to the audit log, and the response
 * must never be cached.
 */
export const GET = apiRoute(async (request, context, { session, params }) =>
  Response.json({ iban: portal().claims.payoutAccount(session, params.id) }, { headers: { "Cache-Control": "no-store" } })
);
