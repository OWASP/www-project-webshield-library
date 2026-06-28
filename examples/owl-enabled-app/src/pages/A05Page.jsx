import React from "react";
import { useHardeningReport } from "@owl/react-adapter/a05-security-misconfiguration/index.js";

export default function A05Page() {
  const findings = useHardeningReport({
    debug: true,
    cors: { origin: "*" },
    cookies: { secure: false, sameSite: "None" }
  });

  return (
    <>
      <section className="panel md:col-span-2">
        <h2 className="panel-title">A05 Security Misconfiguration</h2>
        <p className="mt-2 text-sm text-slate-600">HardeningReporter identifies risky runtime config and gives remediation hints.</p>
        <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {findings.map((f) => (
            <article key={f.id} className="rounded-lg border border-rose-200 bg-rose-50 p-3 text-sm">
              <p className="font-semibold text-rose-700">{f.id}</p>
              <p className="mt-1 uppercase tracking-wide text-xs text-rose-600">{f.severity}</p>
              <p className="mt-2 text-rose-900">{f.recommendation}</p>
            </article>
          ))}
        </div>
      </section>
    </>
  );
}
