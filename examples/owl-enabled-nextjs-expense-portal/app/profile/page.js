import { pageSession } from "../../lib/auth.js";
import { portal } from "../../lib/portal.js";
import { BankForm } from "./BankForm.js";

export default async function ProfilePage() {
  const session = await pageSession();
  const masked = portal().bankDetails.masked(session.userId);

  return (
    <>
      <h1>Payout account</h1>
      <div className="panel">
        <p>
          Approved claims are paid to: <strong>{masked ?? "no account on file yet"}</strong>
        </p>
        <BankForm />
        <p className="hint">
          Stored encrypted (AES-256-GCM). You only ever see the last four characters; finance can reveal the full number for an approved
          claim, and each reveal is logged.
        </p>
      </div>
    </>
  );
}
