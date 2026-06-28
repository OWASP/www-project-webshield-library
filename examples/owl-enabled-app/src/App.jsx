import React from "react";
import { ACLProvider, RBACProvider } from "@owl/react-adapter/a01-access-control/index.js";
import { AuthProvider } from "@owl/react-adapter/a07-auth-session/index.js";
import { SecurityProvider } from "@owl/react-adapter/a09-logging-monitoring/index.js";
import { Link, Route, Routes } from "react-router-dom";
import { security } from "./security";
import A01Page from "./pages/A01Page";
import A02Page from "./pages/A02Page";
import A03Page from "./pages/A03Page";
import A04Page from "./pages/A04Page";
import A05Page from "./pages/A05Page";
import A06Page from "./pages/A06Page";
import A07Page from "./pages/A07Page";
import A08Page from "./pages/A08Page";
import A09Page from "./pages/A09Page";
import A10Page from "./pages/A10Page";
import IntegratedAppPage from "./pages/IntegratedAppPage";

const routes = ["a01", "a02", "a03", "a04", "a05", "a06", "a07", "a08", "a09", "a10"];

function OverviewPage() {
  return (
    <section className="panel md:col-span-2">
      <h1 className="panel-title">OWL Enabled App</h1>
      <p className="mt-2 text-sm text-slate-600">
        This reference app offers both tutorial pages (A01-A10) and one integrated TODO
        product flow showing how to apply the library in realistic day-to-day features.
      </p>
      <div className="mt-4 flex flex-wrap gap-2">
        <span className="chip bg-owl-100 text-owl-900">todo app</span>
        {routes.map((r) => (
          <span key={r} className="chip uppercase">
            {r}
          </span>
        ))}
      </div>
    </section>
  );
}

function AppLayout() {
  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-4 py-3">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-owl-700">OWASP Web Shield</p>
            <p className="text-sm text-slate-500">Reference Implementation</p>
          </div>
          <nav className="flex flex-wrap gap-2">
            <Link className="chip hover:bg-slate-200" to="/">
              overview
            </Link>
            <Link className="chip bg-owl-100 text-owl-900 hover:bg-owl-300" to="/integrated-app">
              todo app
            </Link>
            {routes.map((r) => (
              <Link key={r} className="chip hover:bg-slate-200" to={`/${r}`}>
                {r}
              </Link>
            ))}
          </nav>
        </div>
      </header>
      <main className="mx-auto grid max-w-6xl gap-4 p-4 md:grid-cols-2">
        <Routes>
          <Route path="/" element={<OverviewPage />} />
          <Route path="/integrated-app" element={<IntegratedAppPage />} />
          <Route path="/a01" element={<A01Page />} />
          <Route path="/a02" element={<A02Page />} />
          <Route path="/a03" element={<A03Page />} />
          <Route path="/a04" element={<A04Page />} />
          <Route path="/a05" element={<A05Page />} />
          <Route path="/a06" element={<A06Page />} />
          <Route path="/a07" element={<A07Page />} />
          <Route path="/a08" element={<A08Page />} />
          <Route path="/a09" element={<A09Page />} />
          <Route path="/a10" element={<A10Page />} />
        </Routes>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider authManager={security.authManager}>
      <ACLProvider aclManager={security.aclManager}>
        <RBACProvider rbacManager={security.rbacManager}>
          <SecurityProvider logger={security.logger} events={security.events}>
            <AppLayout />
          </SecurityProvider>
        </RBACProvider>
      </ACLProvider>
    </AuthProvider>
  );
}
