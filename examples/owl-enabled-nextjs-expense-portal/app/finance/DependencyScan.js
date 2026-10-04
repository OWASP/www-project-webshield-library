"use client";

import { useActionState } from "react";
import { runDependencyScan } from "../actions.js";

export function DependencyScan() {
  const [state, action, pending] = useActionState(runDependencyScan, null);
  return (
    <form action={action}>
      <div className="actions">
        <strong>A06 dependency scan:</strong>
        <button type="submit" className="secondary" disabled={pending}>
          {pending ? "Running npm audit…" : "Run scan"}
        </button>
        {state?.ok && (
          <span className={state.pass ? "success" : "error"}>
            {state.pass ? "Passes the policy" : `${state.blocked.length} high or critical finding(s)`} · {state.findings.length} finding(s) in total
          </span>
        )}
        {state?.error && <span className="error">{state.error}</span>}
      </div>
      {state?.findings?.length > 0 && <pre>{state.findings.map((f) => `${f.severity.padEnd(9)} ${f.name} ${f.currentVersion}`).join("\n")}</pre>}
    </form>
  );
}
