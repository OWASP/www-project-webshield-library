import React from "react";
import { useHardeningReport, useSecurityMonitoring } from "@owasp-webshield/react";
import { security, SecretPolicy } from "./security";

const CHECKLIST_CONTROLS = [
  "role_based_access_control",
  "maker_checker_dual_control",
  "mfa_required_for_transfer",
  "csrf_protection",
  "input_sanitization",
  "ssrf_guarded_webhooks",
  "structured_audit_logging"
];

export default function AdminSettingsPanel() {
  const { logger, events } = useSecurityMonitoring();
  const [debugEnabled, setDebugEnabled] = React.useState(false);
  const [corsOrigin, setCorsOrigin] = React.useState("self");
  const [cookieSecure, setCookieSecure] = React.useState(true);
  const [sameSite, setSameSite] = React.useState("Strict");
  const [signingSecret, setSigningSecret] = React.useState("");
  const [secretIssuedAt, setSecretIssuedAt] = React.useState(() => Date.now() - 45 * 60 * 1000);

  const config = React.useMemo(
    () => ({ debug: debugEnabled, cors: { origin: corsOrigin }, cookies: { secure: cookieSecure, sameSite } }),
    [debugEnabled, corsOrigin, cookieSecure, sameSite]
  );
  const findings = useHardeningReport(config);

  function emitActivity(type, details = {}) {
    logger?.info(type, details);
    events?.emit("activity", { ts: new Date().toISOString(), type, actor: "current-user", details });
  }

  function onConfigChange(next) {
    emitActivity("hardening_config_changed", next);
  }

  const checklist = security.designChecklist.validate(CHECKLIST_CONTROLS);
  const entropy = SecretPolicy.minimumEntropyBits(signingSecret);
  const sufficient = SecretPolicy.isEntropySufficient(signingSecret, 60);
  const rotationExceeded = SecretPolicy.isRotationWindowExceeded(secretIssuedAt, 30 * 60 * 1000);
  const secretAgeMinutes = Math.round((Date.now() - secretIssuedAt) / 60000);

  return (
    <>
      <section className="panel md:col-span-2 surface-hero">
        <p className="section-kicker">Admin only — gated by PermissionGate</p>
        <h2 className="panel-title text-xl">Security Settings</h2>
        <p className="mt-2 max-w-3xl text-sm text-slate-600">
          Live configuration hardening, a design-control checklist, and webhook signing-secret
          strength — the kind of operational checks a real banking admin panel would run.
        </p>
      </section>

      <section className="panel">
        <h3 className="panel-title">Hardening Findings (A05)</h3>
        <p className="mt-2 text-xs text-slate-500">Toggle a setting and watch findings update live.</p>
        <div className="mt-3 space-y-3">
          <label className="flex items-center justify-between text-sm">
            <span>Debug mode</span>
            <input
              type="checkbox"
              checked={debugEnabled}
              onChange={(e) => {
                setDebugEnabled(e.target.checked);
                onConfigChange({ debug: e.target.checked });
              }}
            />
          </label>
          <label className="flex items-center justify-between text-sm">
            <span>CORS origin</span>
            <select
              className="input w-32"
              value={corsOrigin}
              onChange={(e) => {
                setCorsOrigin(e.target.value);
                onConfigChange({ cors: { origin: e.target.value } });
              }}
            >
              <option value="self">self</option>
              <option value="*">*</option>
            </select>
          </label>
          <label className="flex items-center justify-between text-sm">
            <span>Secure cookies</span>
            <input
              type="checkbox"
              checked={cookieSecure}
              onChange={(e) => {
                setCookieSecure(e.target.checked);
                onConfigChange({ cookies: { secure: e.target.checked } });
              }}
            />
          </label>
          <label className="flex items-center justify-between text-sm">
            <span>Cookie SameSite</span>
            <select
              className="input w-32"
              value={sameSite}
              onChange={(e) => {
                setSameSite(e.target.value);
                onConfigChange({ cookies: { sameSite: e.target.value } });
              }}
            >
              <option value="Strict">Strict</option>
              <option value="Lax">Lax</option>
              <option value="None">None</option>
            </select>
          </label>
        </div>
        <p className="mt-3 text-sm">findings: <strong>{findings.length}</strong></p>
        <pre className="code-block mt-3">{JSON.stringify(findings, null, 2)}</pre>
      </section>

      <section className="panel">
        <h3 className="panel-title">Design Checklist (A04)</h3>
        <p className="mt-2 text-sm">
          All required controls present: <strong>{String(checklist.valid)}</strong>
        </p>
        <ul className="mt-2 space-y-1 text-sm">
          {CHECKLIST_CONTROLS.map((control) => (
            <li key={control} className={checklist.missing.includes(control) ? "text-rose-700" : "text-emerald-700"}>
              {checklist.missing.includes(control) ? "missing" : "satisfied"} &mdash; {control.replace(/_/g, " ")}
            </li>
          ))}
        </ul>
      </section>

      <section className="panel md:col-span-2">
        <h3 className="panel-title">Webhook Signing Secret Strength (A02)</h3>
        <p className="mt-2 text-xs text-slate-500">
          <code>SecretPolicy</code> is pure JS (no Node crypto), so it&apos;s safe to run directly in
          the browser — used here to vet the secret merchant webhooks would be signed with.
        </p>
        <input
          className="input mt-2"
          placeholder="Type a candidate signing secret"
          value={signingSecret}
          onChange={(e) => setSigningSecret(e.target.value)}
        />
        <p className="mt-2 text-sm">Estimated entropy: <strong>{entropy} bits</strong></p>
        <p className="mt-1 text-sm">
          Meets 60-bit minimum: <strong className={sufficient ? "text-emerald-700" : "text-rose-700"}>{String(sufficient)}</strong>
        </p>
        <div className="mt-3 border-t border-slate-200 pt-3">
          <p className="text-sm">Current secret age: <strong>{secretAgeMinutes} min</strong></p>
          <p className="mt-1 text-sm">
            Rotation window (30 min) exceeded:{" "}
            <strong className={rotationExceeded ? "text-rose-700" : "text-emerald-700"}>{String(rotationExceeded)}</strong>
          </p>
          {rotationExceeded ? (
            <p role="alert" data-level="warn" className="mt-2">
              This signing secret is past its rotation window — issue a new one.
            </p>
          ) : null}
          <button
            className="btn mt-3"
            type="button"
            onClick={() => {
              setSecretIssuedAt(Date.now());
              emitActivity("webhook_signing_secret_rotated", {});
            }}
          >
            Issue New Secret
          </button>
        </div>
      </section>
    </>
  );
}
