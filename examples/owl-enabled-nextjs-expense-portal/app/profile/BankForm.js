"use client";

import { useActionState } from "react";
import { saveBankDetails } from "../actions.js";

export function BankForm() {
  const [state, action, pending] = useActionState(saveBankDetails, null);
  return (
    <form action={action}>
      <div className="field">
        <label htmlFor="iban">IBAN</label>
        <input id="iban" name="iban" required minLength={15} maxLength={42} autoComplete="off" placeholder="DE89 3704 0044 0532 0130 00" />
      </div>
      {state?.error && (
        <p className="error" role="alert">
          {state.error}
        </p>
      )}
      {state?.message && <p className="success">{state.message}</p>}
      <button type="submit" disabled={pending}>
        Save account
      </button>
    </form>
  );
}
