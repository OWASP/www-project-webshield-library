import Link from "next/link";
import { pageSession } from "../../lib/auth.js";
import { portal } from "../../lib/portal.js";

export default async function ClaimsPage() {
  const session = await pageSession();
  // A01: the service returns only what this user may read; there is no
  // "all claims" query for the page to forget to filter.
  const claims = portal().claims.list(session);
  const scope = session.roles.includes("finance") ? "all teams" : session.roles.includes("manager") ? `your team (${session.metadata.team})` : "you";

  return (
    <>
      <div className="actions" style={{ justifyContent: "space-between" }}>
        <h1>Claims</h1>
        <Link href="/claims/new">Submit a claim</Link>
      </div>
      <p className="muted">Showing claims from {scope}.</p>
      <div className="panel">
        {claims.length === 0 ? (
          <p className="muted">No claims yet.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th>Merchant</th>
                <th>Employee</th>
                <th>Spent on</th>
                <th>Amount</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {claims.map((claim) => (
                <tr key={claim.id}>
                  <td>
                    <Link href={`/claims/${claim.id}`}>{claim.id}</Link>
                  </td>
                  <td>{claim.merchant}</td>
                  <td>
                    {claim.ownerName} <span className="muted">({claim.team})</span>
                  </td>
                  <td>{claim.spentOn}</td>
                  <td>{claim.amount}</td>
                  <td>
                    <span className={`badge ${claim.status}`}>{claim.status}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
