import { notFound } from "next/navigation";
import { checkPermission } from "@owasp-webshield/next";
import { pageSession } from "../../lib/auth.js";
import { IMPLEMENTED_CONTROLS, portal } from "../../lib/portal.js";
import { DependencyScan } from "./DependencyScan.js";

export default async function FinancePage() {
  const session = await pageSession();
  const { owl, logs, logger, hardening, checklist } = portal();

  // A01: checked on the server for every render; hiding the nav link isn't enough.
  if (!checkPermission({ session, action: "view", resource: "audit" }, owl).allowed) {
    logger.warn("security.access_denied", { userId: session.userId, page: "/finance" });
    notFound();
  }

  const design = checklist.validate(IMPLEMENTED_CONTROLS);
  const entries = logs.slice(-100).reverse();

  return (
    <>
      <h1>Finance &amp; security</h1>

      <div className="panel">
        <h2>Security checks</h2>
        <p>
          <strong>A05 hardening:</strong> {hardening.length === 0 ? "no findings" : `${hardening.length} non-blocking finding(s)`} (the server
          refuses to start on a high-severity one).
        </p>
        {hardening.length > 0 && <pre>{JSON.stringify(hardening, null, 2)}</pre>}
        <p>
          <strong>A04 design checklist:</strong> {design.valid ? `all ${IMPLEMENTED_CONTROLS.length} controls in place` : `missing: ${design.missing.join(", ")}`}
        </p>
        <DependencyScan />
      </div>

      <div className="panel">
        <h2>Audit log</h2>
        <p className="muted">The latest 100 events. Secrets in event details are redacted by SecurityLogger before they are stored.</p>
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Level</th>
              <th>Event</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry, index) => (
              <tr key={index}>
                <td>{new Date(entry.ts).toLocaleTimeString("en-US")}</td>
                <td>{entry.level}</td>
                <td>
                  <code>{entry.event}</code>
                </td>
                <td>
                  <code>{JSON.stringify(entry.details)}</code>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
