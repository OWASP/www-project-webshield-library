import React from "react";
import { AuthGate, OwlProvider, PermissionGate, useAuth, useAuthToken } from "@owasp-webshield/react";
import { security } from "./security";
import LoginPanel from "./LoginPanel";
import AccountsPanel from "./AccountsPanel";
import TransferWorkspace from "./TransferWorkspace";
import IntegrationsPanel from "./IntegrationsPanel";
import AuditLogPanel from "./AuditLogPanel";
import AdminSettingsPanel from "./AdminSettingsPanel";

const TABS = [
  { id: "accounts", label: "Accounts" },
  { id: "transfer", label: "Transfer" },
  { id: "integrations", label: "Integrations", gate: { action: "read", resource: "integrations" } },
  { id: "audit", label: "Audit Log", gate: { action: "read", resource: "audit" } },
  { id: "admin", label: "Admin Settings", gate: { action: "manage", resource: "security" } }
];

function ShieldMark() {
  return (
    <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-owl-600 text-white shadow-soft">
      <svg viewBox="0 0 24 24" fill="none" className="h-5 w-5">
        <path
          d="M12 2.5 4 5.5v6c0 5.2 3.4 8.6 8 10 4.6-1.4 8-4.8 8-10v-6l-8-3Z"
          stroke="currentColor"
          strokeWidth="1.6"
          strokeLinejoin="round"
        />
        <path d="M9 12.2 11.2 14.4 15.4 9.8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </span>
  );
}

// Ticks once a second so the session countdown below stays live without
// depending on OWL's own expiry timer (which only fires once, at expiry).
function useNow() {
  const [now, setNow] = React.useState(Date.now());
  React.useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);
  return now;
}

function SessionWidget() {
  const token = useAuthToken();
  const now = useNow();
  const [refreshing, setRefreshing] = React.useState(false);
  const tokens = security.tokenManager.getTokens();
  const remainingMs = tokens?.expiresAt ? tokens.expiresAt - now : 0;
  const remainingSeconds = Math.max(0, Math.ceil(remainingMs / 1000));
  const expiringSoon = token && remainingSeconds <= 20;

  async function onRefresh() {
    setRefreshing(true);
    await security.refreshSession();
    setRefreshing(false);
  }

  if (!token) return null;

  return (
    <div className="flex items-center gap-2">
      <span className={`chip ${expiringSoon ? "border-rose-200 bg-rose-50 text-rose-700" : ""}`}>
        session {remainingSeconds}s
      </span>
      <button type="button" className="btn-ghost" onClick={() => void onRefresh()} disabled={refreshing}>
        {refreshing ? "Refreshing…" : "Refresh Session"}
      </button>
    </div>
  );
}

function TopBar({ tab, setTab }) {
  const { session } = useAuth();
  const initials = (session?.userId || "?").slice(0, 2).toUpperCase();
  return (
    <header className="sticky top-0 z-10 border-b border-slate-200/70 bg-white/75 backdrop-blur-xl">
      <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-4 py-3">
        <div className="flex items-center gap-3">
          <ShieldMark />
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-owl-700">OWASP Webshield</p>
            <p className="text-sm font-medium text-slate-500">Enabled Banking Dashboard</p>
          </div>
        </div>
        <nav className="flex flex-wrap items-center gap-2">
          {TABS.map((item) =>
            item.gate ? (
              <PermissionGate key={item.id} action={item.gate.action} resource={item.gate.resource}>
                <button
                  type="button"
                  className={`chip ${tab === item.id ? "border-owl-200 bg-owl-100 text-owl-900" : ""}`}
                  onClick={() => setTab(item.id)}
                >
                  {item.label}
                </button>
              </PermissionGate>
            ) : (
              <button
                key={item.id}
                type="button"
                className={`chip ${tab === item.id ? "border-owl-200 bg-owl-100 text-owl-900" : ""}`}
                onClick={() => setTab(item.id)}
              >
                {item.label}
              </button>
            )
          )}
          <span className="mx-1 hidden h-6 w-px bg-slate-200 sm:block" />
          <SessionWidget />
          <span className="avatar">{initials}</span>
          <div className="hidden flex-col leading-tight sm:flex">
            <span className="text-sm font-semibold text-slate-800">{session?.userId}</span>
            <span className="badge-role w-fit">{session?.roles?.[0]}</span>
          </div>
          <button type="button" className="btn-ghost hover:border-rose-200 hover:bg-rose-50 hover:text-rose-700" onClick={() => security.logout()}>
            Sign out
          </button>
        </nav>
      </div>
    </header>
  );
}

function DeniedPanel({ what }) {
  return (
    <section className="panel md:col-span-2">
      <p role="alert" data-level="error">
        Your role cannot access {what}.
      </p>
    </section>
  );
}

function AppShell() {
  const [tab, setTab] = React.useState("accounts");
  const active = TABS.find((item) => item.id === tab) || TABS[0];

  let body;
  if (tab === "accounts") body = <AccountsPanel />;
  else if (tab === "transfer") body = <TransferWorkspace />;
  else if (tab === "integrations") body = <IntegrationsPanel />;
  else if (tab === "audit") body = <AuditLogPanel />;
  else body = <AdminSettingsPanel />;

  const content = active.gate ? (
    <PermissionGate action={active.gate.action} resource={active.gate.resource} fallback={<DeniedPanel what={active.label} />}>
      {body}
    </PermissionGate>
  ) : (
    body
  );

  return (
    <div className="min-h-screen">
      <TopBar tab={tab} setTab={setTab} />
      <main className="mx-auto grid max-w-6xl items-start gap-4 p-4 sm:p-6 md:grid-cols-2">{content}</main>
    </div>
  );
}

function LoginScreen() {
  return (
    <div className="flex min-h-screen items-center justify-center p-4 sm:p-6">
      <LoginPanel />
    </div>
  );
}

export default function App() {
  return (
    <OwlProvider client={security}>
      <AuthGate fallback={<LoginScreen />}>
        <AppShell />
      </AuthGate>
    </OwlProvider>
  );
}
