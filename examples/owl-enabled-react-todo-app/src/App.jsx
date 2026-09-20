import React from "react";
// Deep, per-category imports — NOT the "@owasp-core/owl-react" package root. That
// root re-exports every category, including a02 (useCryptoManager) and a08
// (useSecureHttpClient), both of which pull in files with a top-level `node:crypto`
// import that crashes on evaluation in a browser. See security.js's header comment
// and this app's README "Notes" for the full explanation.
import { ACLProvider, PermissionGate, RBACProvider } from "@owasp-core/owl-react/a01-access-control/index.js";
import { AuthGate, AuthProvider, useAuth } from "@owasp-core/owl-react/a07-auth-session/index.js";
import { SecurityProvider } from "@owasp-core/owl-react/a09-logging-monitoring/index.js";
import { security } from "./security";
import LoginPanel from "./LoginPanel";
import TodoWorkspace from "./TodoWorkspace";
import SecurityDashboard from "./SecurityDashboard";

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

function TopBar({ tab, setTab }) {
  const { session } = useAuth();
  const initials = (session?.userId || "?").slice(0, 2).toUpperCase();
  return (
    <header className="sticky top-0 z-10 border-b border-slate-200/70 bg-white/75 backdrop-blur-xl">
      <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-4 py-3">
        <div className="flex items-center gap-3">
          <ShieldMark />
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-owl-700">OWASP Web Shield</p>
            <p className="text-sm font-medium text-slate-500">Enabled React Todo App</p>
          </div>
        </div>
        <nav className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            className={`chip ${tab === "workspace" ? "border-owl-200 bg-owl-100 text-owl-900" : ""}`}
            onClick={() => setTab("workspace")}
          >
            Todo Workspace
          </button>
          <PermissionGate action="manage" resource="security">
            <button
              type="button"
              className={`chip ${tab === "security" ? "border-owl-200 bg-owl-100 text-owl-900" : ""}`}
              onClick={() => setTab("security")}
            >
              Security Dashboard
            </button>
          </PermissionGate>
          <span className="mx-1 hidden h-6 w-px bg-slate-200 sm:block" />
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

function AppShell() {
  const [tab, setTab] = React.useState("workspace");
  return (
    <div className="min-h-screen">
      <TopBar tab={tab} setTab={setTab} />
      <main className="mx-auto grid max-w-6xl items-start gap-4 p-4 sm:p-6 md:grid-cols-2">
        {tab === "security" ? (
          <PermissionGate
            action="manage"
            resource="security"
            fallback={
              <section className="panel md:col-span-2">
                <p role="alert" data-level="error">
                  Your role cannot access the Security Dashboard.
                </p>
              </section>
            }
          >
            <SecurityDashboard />
          </PermissionGate>
        ) : (
          <TodoWorkspace />
        )}
      </main>
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
    <SecurityProvider logger={security.logger} events={security.events}>
      <AuthProvider authManager={security.authManager}>
        <ACLProvider aclManager={security.aclManager}>
          <RBACProvider rbacManager={security.rbacManager}>
            <AuthGate fallback={<LoginScreen />}>
              <AppShell />
            </AuthGate>
          </RBACProvider>
        </ACLProvider>
      </AuthProvider>
    </SecurityProvider>
  );
}
