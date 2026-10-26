import { pageSession } from "../../../lib/auth.js";
import { formatCents } from "../../../lib/claims.js";
import { MANAGER_APPROVAL_LIMIT_CENTS, MAX_EXPENSE_AGE_DAYS } from "../../../lib/policy.js";
import { NewClaimForm } from "./NewClaimForm.js";

export default async function NewClaimPage() {
  await pageSession();
  return (
    <>
      <h1>Submit a claim</h1>
      <div className="panel">
        <NewClaimForm />
        <p className="hint">
          Expenses from the last {MAX_EXPENSE_AGE_DAYS} days. Claims over {formatCents(MANAGER_APPROVAL_LIMIT_CENTS)} are approved by finance
          instead of your manager.
        </p>
      </div>
    </>
  );
}
