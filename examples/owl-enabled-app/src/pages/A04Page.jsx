import React from "react";
import { useThreatModelGuard } from "@owl/react-adapter/a04-insecure-design-guard/index.js";

export default function A04Page() {
  const guard = useThreatModelGuard({
    transitions: {
      draft: ["review"],
      review: ["approved", "rejected"]
    },
    abuseRules: [
      { id: "rate_limit", message: "Too many requests", check: (ctx) => ctx.requestsPerMinute < 100 },
      { id: "mfa_required", message: "MFA required for admin", check: (ctx) => !ctx.admin || ctx.mfa }
    ]
  });

  const transition = guard.validateTransition("draft", "approved");
  const abuse = guard.evaluateAbuseCase({ requestsPerMinute: 160, admin: true, mfa: false });

  return (
    <>
      <section className="panel">
        <h2 className="panel-title">A04 Insecure Design</h2>
        <p className="mt-2 text-sm text-slate-600">ThreatModelGuard validates state transitions and abuse-case controls.</p>
        <p className="mt-3 text-sm">Transition draft → approved: <strong>{transition.valid ? "valid" : transition.reason}</strong></p>
      </section>
      <section className="panel">
        <h3 className="panel-title">Abuse Case Findings</h3>
        <pre className="code-block mt-3">{JSON.stringify(abuse, null, 2)}</pre>
      </section>
    </>
  );
}
