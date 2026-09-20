import React from "react";
// Deep, per-category imports — see App.jsx and security.js for why the
// "@owasp-core/owl-react" package root isn't used here.
import { useHardeningReport } from "@owasp-core/owl-react/a05-security-misconfiguration/index.js";
import { useDependencyRiskScanner } from "@owasp-core/owl-react/a06-vulnerable-components/index.js";
import { SecurityAlert, useSecurityMonitoring } from "@owasp-core/owl-react/a09-logging-monitoring/index.js";
import { security, SecretPolicy } from "./security";

const HARDENING_CONFIG = {
  debug: false,
  cors: { origin: "self" },
  cookies: { secure: true, sameSite: "Strict" }
};

const CHECKLIST_CONTROLS = [
  "role_based_access_control",
  "deny_override_acl",
  "csrf_protection",
  "input_sanitization",
  "ssrf_guard",
  "structured_security_logging"
];

export default function SecurityDashboard() {
  const findings = useHardeningReport(HARDENING_CONFIG);
  const { results, loading, runScan } = useDependencyRiskScanner(security.dependencyProvider);
  const { events } = useSecurityMonitoring();
  const [activity, setActivity] = React.useState([]);
  const [apiKey, setApiKey] = React.useState("");
  const [keyIssuedAt, setKeyIssuedAt] = React.useState(() => Date.now() - 45 * 60 * 1000);

  React.useEffect(() => {
    if (!events) return undefined;
    return events.on("activity", (payload) => setActivity((prev) => [payload, ...prev].slice(0, 12)));
  }, [events]);

  const checklist = security.designChecklist.validate(CHECKLIST_CONTROLS);
  const entropy = SecretPolicy.minimumEntropyBits(apiKey);
  const sufficient = SecretPolicy.isEntropySufficient(apiKey, 40);
  const rotationExceeded = SecretPolicy.isRotationWindowExceeded(keyIssuedAt, 30 * 60 * 1000);
  const keyAgeMinutes = Math.round((Date.now() - keyIssuedAt) / 60000);

  return (
    <>
      <section className="panel md:col-span-2 surface-hero">
        <p className="section-kicker">Admin only — gated by PermissionGate</p>
        <h2 className="panel-title text-xl">Security Dashboard</h2>
        <p className="mt-2 max-w-3xl text-sm text-slate-600">
          Operational security checks that a real admin panel would run: configuration
          hardening, dependency risk, design-control coverage, secret strength, and an
          audit trail of everything happening in the app.
        </p>
      </section>

      <section className="panel">
        <h3 className="panel-title">Hardening Findings (A05)</h3>
        <p className="mt-2 text-sm">useHardeningReport findings: <strong>{findings.length}</strong></p>
        <pre className="code-block mt-3">{JSON.stringify(findings, null, 2)}</pre>
      </section>

      <section className="panel">
        <h3 className="panel-title">Dependency Risk Scan (A06)</h3>
        <button className="btn" onClick={() => void runScan()} type="button" disabled={loading}>
          {loading ? "Scanning..." : "Scan Dependencies"}
        </button>
        <div className="mt-3 space-y-2">
          {results.map((item) => {
            const decision = security.componentPolicy.evaluate({
              name: item.package,
              version: item.currentVersion
            });
            return (
              <div key={item.package} className="rounded-md border border-slate-200 p-2 text-sm">
                <p>
                  <strong>{item.package}</strong> · {item.severity} · {item.currentVersion} → {item.fixedVersion}
                </p>
                <p className={decision.allowed ? "text-emerald-700" : "text-rose-700"}>
                  ComponentPolicy: {decision.allowed ? "allowed" : `blocked (${decision.reason})`}
                </p>
              </div>
            );
          })}
          {!results.length ? <p className="text-sm text-slate-500">No scan results yet.</p> : null}
        </div>
      </section>

      <section className="panel">
        <h3 className="panel-title">Design Checklist (A04)</h3>
        <p className="mt-2 text-sm">
          All required controls present: <strong>{String(checklist.valid)}</strong>
        </p>
        <ul className="mt-2 space-y-1 text-sm">
          {CHECKLIST_CONTROLS.map((control) => (
            <li key={control} className={checklist.missing.includes(control) ? "text-rose-700" : "text-emerald-700"}>
              {checklist.missing.includes(control) ? "missing" : "satisfied"} — {control.replace(/_/g, " ")}
            </li>
          ))}
        </ul>
      </section>

      <section className="panel">
        <h3 className="panel-title">Secret Strength Checker (A02)</h3>
        <p className="mt-2 text-xs text-slate-500">
          SecretPolicy is pure JS (no Node crypto), so it&apos;s safe to run directly in the browser.
        </p>
        <input
          className="input mt-2"
          placeholder="Type a candidate API key / passphrase"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
        />
        <p className="mt-2 text-sm">Estimated entropy: <strong>{entropy} bits</strong></p>
        <p className="mt-1 text-sm">
          Meets 40-bit minimum: <strong className={sufficient ? "text-emerald-700" : "text-rose-700"}>{String(sufficient)}</strong>
        </p>
        <div className="mt-3 border-t border-slate-200 pt-3">
          <p className="text-sm">Current key age: <strong>{keyAgeMinutes} min</strong></p>
          <p className="mt-1 text-sm">
            Rotation window (30 min) exceeded:{" "}
            <strong className={rotationExceeded ? "text-rose-700" : "text-emerald-700"}>{String(rotationExceeded)}</strong>
          </p>
          {rotationExceeded ? (
            <div className="mt-2">
              <SecurityAlert level="warn" message="This key is past its rotation window — issue a new one." />
            </div>
          ) : null}
          <button className="btn mt-3" type="button" onClick={() => setKeyIssuedAt(Date.now())}>
            Issue New Key
          </button>
        </div>
      </section>

      <section className="panel md:col-span-2">
        <h3 className="panel-title">Activity Timeline (A09)</h3>
        <p className="mt-2 text-xs text-slate-500">Live feed via useSecurityMonitoring's EventEmitter.</p>
        <pre className="code-block mt-3">{JSON.stringify(activity, null, 2)}</pre>
      </section>
    </>
  );
}
