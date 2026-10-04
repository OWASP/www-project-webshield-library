import { notFound } from "next/navigation";
import { SanitizedText } from "@owasp-webshield/next/client";
import { pageSession } from "../../../lib/auth.js";
import { portal } from "../../../lib/portal.js";
import { CommentForm } from "./CommentForm.js";
import { DecisionForm } from "./DecisionForm.js";
import { PayoutAccount } from "./PayoutAccount.js";
import { ReceiptImport } from "./ReceiptImport.js";

function loadClaim(session, id) {
  try {
    return portal().claims.get(session, id);
  } catch (error) {
    // A01: someone else's claim looks exactly like one that doesn't exist.
    if (error.status === 404) notFound();
    throw error;
  }
}

export default async function ClaimPage({ params }) {
  const session = await pageSession();
  const { id } = await params;
  const claim = loadClaim(session, id);
  const { allowed } = claim;

  return (
    <>
      <h1>
        Claim #{claim.id}: {claim.merchant} <span className={`badge ${claim.status}`}>{claim.status}</span>
      </h1>

      <div className="panel grid">
        <div>
          <div className="muted">Employee</div>
          {claim.ownerName} ({claim.team})
        </div>
        <div>
          <div className="muted">Amount</div>
          {claim.amount}
        </div>
        <div>
          <div className="muted">Category</div>
          {claim.category}
        </div>
        <div>
          <div className="muted">Spent on</div>
          {claim.spentOn}
        </div>
        <div style={{ gridColumn: "1 / -1" }}>
          <div className="muted">Business purpose</div>
          {/* A03: plain text; React escapes it. */}
          <p style={{ whiteSpace: "pre-wrap" }}>{claim.description}</p>
        </div>
      </div>

      {(allowed.approve || allowed.reject || allowed.pay) && (
        <div className="panel">
          <h2>Decision</h2>
          <DecisionForm id={claim.id} canApprove={allowed.approve} canReject={allowed.reject} canPay={allowed.pay} />
        </div>
      )}

      {allowed.viewBankDetails && (
        <div className="panel">
          <h2>Payout account</h2>
          <PayoutAccount id={claim.id} />
        </div>
      )}

      <div className="panel">
        <h2>Receipt</h2>
        {claim.receipt ? (
          <p>
            <a href={`/api/claims/${claim.id}/receipt`}>Download ({claim.receipt.contentType}, {Math.ceil(claim.receipt.size / 1024)} KB)</a>{" "}
            <span className="muted">
              from {claim.receipt.sourceHost} · sha256 {claim.receipt.sha256.slice(0, 12)}…
            </span>
          </p>
        ) : (
          <p className="muted">No receipt attached.</p>
        )}
        {allowed.attach && <ReceiptImport id={claim.id} />}
      </div>

      <div className="panel">
        <h2>History</h2>
        <ul>
          {claim.history.map((entry, index) => (
            <li key={index}>
              <strong>{entry.status}</strong> by {entry.by} on {new Date(entry.at).toLocaleString("en-US")}
              {entry.reason && <> — “{entry.reason}”</>}
              {entry.paidTo && <> to {entry.paidTo}</>}
            </li>
          ))}
        </ul>
      </div>

      <div className="panel">
        <h2>Comments</h2>
        {claim.comments.length === 0 && <p className="muted">No comments yet.</p>}
        {claim.comments.map((comment, index) => (
          <div key={index} className="comment">
            <div className="muted">
              {comment.author} · {new Date(comment.at).toLocaleString("en-US")}
            </div>
            {/* A03: stored sanitized, and sanitized again when rendered. */}
            <SanitizedText html={comment.body} profile="moderate" />
          </div>
        ))}
        {allowed.comment && <CommentForm id={claim.id} />}
      </div>
    </>
  );
}
