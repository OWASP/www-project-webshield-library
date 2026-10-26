"use client";

import { useActionState } from "react";
import { decideClaim } from "../../actions.js";

/**
 * Offers only the decisions the server said this user may make, but the
 * Server Action checks them all again: a hidden button is not a permission.
 */
export function DecisionForm({ id, canApprove, canReject, canPay }) {
  const [state, action, pending] = useActionState(decideClaim.bind(null, id), null);

  return (
    <form action={action}>
      {(canApprove || canReject) && (
        <div className="field">
          <label htmlFor="reason">Note to the employee (optional)</label>
          <input id="reason" name="reason" maxLength={500} />
        </div>
      )}
      <div className="actions">
        {canApprove && (
          <button type="submit" name="status" value="approved" disabled={pending}>
            Approve
          </button>
        )}
        {canReject && (
          <button type="submit" name="status" value="rejected" className="danger" disabled={pending}>
            Reject
          </button>
        )}
        {canPay && (
          <button type="submit" name="status" value="paid" disabled={pending}>
            Mark as paid
          </button>
        )}
      </div>
      {state?.error && (
        <p className="error" role="alert">
          {state.error}
        </p>
      )}
    </form>
  );
}
