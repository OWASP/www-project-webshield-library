import React from "react";
import { PermissionGate, useDependencyRiskScanner, useSafeFetcher, useSecurityMonitoring, withSecurityHeaders } from "@owasp-webshield/react";
import { security } from "./security";

const PROBE_TARGETS = [
  { label: "Probe localhost (should block)", url: "http://127.0.0.1:6379/" },
  { label: "Probe cloud metadata (should block)", url: "http://169.254.169.254/latest/meta-data/" }
];

export default function IntegrationsPanel() {
  const { results, loading, runScan } = useDependencyRiskScanner(security.dependencyProvider);
  const { logger, events } = useSecurityMonitoring();
  const safeFetcher = useSafeFetcher({}, async (url) => ({ ok: true, json: async () => ({ ok: true, url }) }));
  const [webhookUrl, setWebhookUrl] = React.useState("https://payments.merchant-example.com/callbacks/owl-bank");
  const [webhookStatus, setWebhookStatus] = React.useState("No validation run yet.");
  const [savedWebhooks, setSavedWebhooks] = React.useState([]);

  function emitActivity(type, details = {}) {
    logger?.info(type, details);
    events?.emit("activity", { ts: new Date().toISOString(), type, actor: "current-user", details });
  }

  async function validateWebhook(url) {
    try {
      const response = await safeFetcher.fetch(url);
      await response.json();
      setWebhookStatus(`Allowed target: ${url}`);
      emitActivity("webhook_validated", { target: url });
      return true;
    } catch (error) {
      setWebhookStatus(`Blocked target: ${error.message}`);
      logger?.warn("webhook_validation_blocked", { target: url, reason: error.message });
      return false;
    }
  }

  async function saveWebhook() {
    const ok = await validateWebhook(webhookUrl);
    if (!ok) return;
    try {
      await security.apiClient.request(
        "/webhooks/register",
        withSecurityHeaders({
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: webhookUrl })
        })
      );
      setSavedWebhooks((prev) => [webhookUrl, ...prev.filter((item) => item !== webhookUrl)]);
      emitActivity("webhook_registered", { target: webhookUrl });
    } catch (error) {
      setWebhookStatus(`Registration blocked: ${error.message}`);
    }
  }

  return (
    <>
      <section className="panel md:col-span-2 surface-hero">
        <p className="section-kicker">Integrations &amp; Webhooks (A06 / A10)</p>
        <h2 className="panel-title text-xl">Third-Party Integration Health</h2>
        <p className="mt-2 max-w-3xl text-sm text-slate-600">
          Vendor SDKs this bank depends on, scored against a component policy, and a merchant
          bill-pay webhook validator that refuses to save an internal or cloud-metadata target
          before it&apos;s ever fetched.
        </p>
      </section>

      <section className="panel">
        <h3 className="panel-title">Dependency Risk Scan (A06)</h3>
        <button className="btn" onClick={() => void runScan()} type="button" disabled={loading}>
          {loading ? "Scanning..." : "Scan Vendor SDKs"}
        </button>
        <div className="mt-3 space-y-2">
          {results.map((item) => {
            const decision = security.componentPolicy.evaluate({ name: item.package, version: item.currentVersion });
            return (
              <div key={item.package} className="rounded-md border border-slate-200 p-2 text-sm">
                <div className="flex items-center justify-between">
                  <p>
                    <strong>{item.package}</strong> &middot; {item.currentVersion} &rarr; {item.fixedVersion}
                  </p>
                  <span className={`severity-pill severity-${item.severity}`}>{item.severity}</span>
                </div>
                <p className={decision.allowed ? "mt-1 text-emerald-700" : "mt-1 text-rose-700"}>
                  ComponentPolicy: {decision.allowed ? "allowed" : `blocked (${decision.reason})`}
                </p>
              </div>
            );
          })}
          {!results.length ? <p className="text-sm text-slate-500">No scan results yet.</p> : null}
        </div>
      </section>

      <section className="panel">
        <h3 className="panel-title">Merchant Webhook Validator (A10)</h3>
        <p className="mt-2 text-xs text-slate-500">bill-pay / merchant callback URL</p>
        <input className="input mt-1" value={webhookUrl} onChange={(e) => setWebhookUrl(e.target.value)} />
        <div className="mt-3 flex flex-wrap gap-2">
          <button className="btn-ghost" onClick={() => void validateWebhook(webhookUrl)} type="button">
            Validate Only (SSRF guard)
          </button>
          <PermissionGate
            action="manage"
            resource="webhooks"
            fallback={<span className="chip">save requires admin (manage:webhooks)</span>}
          >
            <button className="btn" onClick={() => void saveWebhook()} type="button">
              Validate &amp; Save (CSRF-protected)
            </button>
          </PermissionGate>
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          {PROBE_TARGETS.map((probe) => (
            <button
              key={probe.url}
              className="btn-ghost hover:border-rose-200 hover:bg-rose-50 hover:text-rose-700"
              type="button"
              onClick={() => void validateWebhook(probe.url)}
            >
              {probe.label}
            </button>
          ))}
        </div>
        <p className="mt-3 text-sm">{webhookStatus}</p>
        {savedWebhooks.length ? (
          <div className="mt-3 border-t border-slate-200 pt-3">
            <p className="text-xs font-medium uppercase tracking-wide text-slate-500">Registered webhooks</p>
            <ul className="mt-2 space-y-1 text-sm">
              {savedWebhooks.map((url) => (
                <li key={url} className="font-mono text-xs text-slate-600">{url}</li>
              ))}
            </ul>
          </div>
        ) : null}
      </section>
    </>
  );
}
