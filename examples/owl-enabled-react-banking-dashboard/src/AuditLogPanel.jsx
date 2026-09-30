import React from "react";
import { useSecurityMonitoring } from "@owasp-webshield/react";
import { activityLog } from "./security";

const FILTERS = [
  { id: "all", label: "All" },
  { id: "auth", label: "Auth", match: (type) => type.startsWith("auth") || type.includes("session") },
  { id: "transfer", label: "Transfers", match: (type) => type.startsWith("transfer") },
  { id: "vault", label: "Vault", match: (type) => type.includes("account_number") || type.includes("crypto") },
  { id: "integrations", label: "Integrations", match: (type) => type.includes("webhook") },
  { id: "security", label: "Security Config", match: (type) => type.includes("hardening") || type.includes("config") }
];

export default function AuditLogPanel() {
  const { events } = useSecurityMonitoring();
  // Re-render on every new event; the log itself lives in the module-level
  // `activityLog` buffer (see security.js) so history survives tab switches.
  const [, forceUpdate] = React.useState(0);
  const [filter, setFilter] = React.useState("all");

  React.useEffect(() => {
    if (!events) return undefined;
    return events.on("activity", () => forceUpdate((n) => n + 1));
  }, [events]);

  const activeFilter = FILTERS.find((item) => item.id === filter);
  const filtered = activeFilter?.match ? activityLog.filter((entry) => activeFilter.match(entry.type)) : activityLog;

  return (
    <section className="panel md:col-span-2">
      <p className="section-kicker">Audit Log (A09)</p>
      <h2 className="panel-title text-xl">Security &amp; Transaction Activity</h2>
      <p className="mt-2 max-w-3xl text-sm text-slate-600">
        Every login, transfer state change, vault reveal, webhook validation, and config change in
        this app is written here via <code>SecurityLogger</code> and a live <code>EventEmitter</code>{" "}
        feed — nothing happens silently.
      </p>
      <div className="mt-4 flex flex-wrap gap-2">
        {FILTERS.map((item) => (
          <button
            key={item.id}
            type="button"
            className={`chip ${filter === item.id ? "border-owl-200 bg-owl-100 text-owl-900" : ""}`}
            onClick={() => setFilter(item.id)}
          >
            {item.label}
          </button>
        ))}
        <span className="chip">{filtered.length} events</span>
      </div>
      <div className="mt-4 max-h-[32rem] space-y-2 overflow-y-auto">
        {filtered.length ? (
          filtered.map((entry, index) => (
            <div key={`${entry.ts}-${index}`} className="rounded-lg border border-slate-200 bg-white p-3 text-sm">
              <div className="flex items-center justify-between gap-3">
                <span className="font-semibold text-slate-800">{entry.type}</span>
                <span className="text-xs text-slate-400">{entry.ts}</span>
              </div>
              <p className="mt-1 text-xs text-slate-500">actor: {entry.actor}</p>
              {entry.details && Object.keys(entry.details).length ? (
                <pre className="code-block mt-2">{JSON.stringify(entry.details, null, 2)}</pre>
              ) : null}
            </div>
          ))
        ) : (
          <p className="text-sm text-slate-500">No activity yet for this filter — go use the app.</p>
        )}
      </div>
    </section>
  );
}
