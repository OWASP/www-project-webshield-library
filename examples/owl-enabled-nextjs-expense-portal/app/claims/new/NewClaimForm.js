"use client";

import { useActionState } from "react";
import { CATEGORIES } from "../../../lib/policy.js";
import { submitClaim } from "../../actions.js";

export function NewClaimForm() {
  const [state, action, pending] = useActionState(submitClaim, null);
  const today = new Date().toISOString().slice(0, 10);

  return (
    <form action={action}>
      <div className="grid">
        <div className="field">
          <label htmlFor="merchant">Merchant</label>
          <input id="merchant" name="merchant" required minLength={2} maxLength={80} />
        </div>
        <div className="field">
          <label htmlFor="amount">Amount (USD)</label>
          <input id="amount" name="amount" required inputMode="decimal" pattern="\d{1,5}(\.\d{2})?" placeholder="42.50" />
        </div>
        <div className="field">
          <label htmlFor="category">Category</label>
          <select id="category" name="category" defaultValue="travel">
            {CATEGORIES.map((category) => (
              <option key={category}>{category}</option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="spentOn">Spent on</label>
          <input id="spentOn" name="spentOn" type="date" required max={today} defaultValue={today} />
        </div>
      </div>
      <div className="field">
        <label htmlFor="description">Business purpose</label>
        <textarea id="description" name="description" required maxLength={2000} />
      </div>
      {state?.error && (
        <p className="error" role="alert">
          {state.error}
        </p>
      )}
      <button type="submit" disabled={pending}>
        {pending ? "Submitting…" : "Submit claim"}
      </button>
    </form>
  );
}
