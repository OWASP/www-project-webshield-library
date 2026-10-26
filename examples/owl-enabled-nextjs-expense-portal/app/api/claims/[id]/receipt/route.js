import { apiRoute } from "../../../../../lib/auth.js";
import { RECEIPT_SCHEMA } from "../../../../../lib/policy.js";
import { portal } from "../../../../../lib/portal.js";
import { downloadReceipt } from "../../../../../lib/receipts.js";

/**
 * A10: import a receipt from a URL the employee pastes. `outboundUrl` refuses
 * private, loopback and cloud-metadata targets before anything is fetched;
 * downloadReceipt() then fetches through SafeFetcher, which re-checks every
 * redirect, and keeps the file only if its bytes are a PDF, PNG or JPEG.
 */
export const POST = apiRoute(
  async (request, context, { session, params, outboundUrl }) => {
    const { claims, receiptFetcher } = portal();
    claims.get(session, params.id); // 404 before any outbound request for a claim you can't see
    const receipt = await downloadReceipt(outboundUrl.href, { fetcher: receiptFetcher });
    return Response.json(claims.attachReceipt(session, params.id, receipt), { status: 201 });
  },
  {
    body: { schema: RECEIPT_SCHEMA, allowUnknownFields: false, limit: 4 * 1024 },
    outboundUrl: { getUrl: ({ body }) => body.url, guard: portal().guard }
  }
);

/**
 * Download the receipt. It came from an arbitrary server, so it is sent as an
 * attachment with its sniffed type, `nosniff` and a sandboxing CSP: a file
 * crafted as HTML can't run script in this origin, even if opened directly.
 */
export const GET = apiRoute(async (request, context, { session, params }) => {
  const receipt = portal().claims.receipt(session, params.id);
  return new Response(receipt.bytes, {
    headers: {
      "Content-Type": receipt.contentType,
      "Content-Disposition": `attachment; filename="${receipt.filename}"`,
      "Content-Security-Policy": "default-src 'none'; sandbox",
      "Cache-Control": "private, no-store"
    }
  });
});
