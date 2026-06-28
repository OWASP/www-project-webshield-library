import React from "react";
import { AuthGate, useAuth, useAuthToken } from "@owl/react-adapter/a07-auth-session/index.js";

export default function A07Page() {
  const { session, authManager, isAuthenticated } = useAuth();
  const token = useAuthToken();

  return (
    <>
      <section className="panel">
        <h2 className="panel-title">A07 Identification and Authentication Failures</h2>
        <p className="mt-2 text-sm text-slate-600">AuthProvider syncs session and token state from core managers.</p>
        <p className="mt-3 text-sm">Authenticated: <strong>{String(isAuthenticated)}</strong></p>
        <p className="mt-2 text-sm">User: <strong>{session?.userId || "none"}</strong></p>
      </section>
      <section className="panel">
        <h3 className="panel-title">Session Controls</h3>
        <p className="mt-3 text-sm break-all">Access Token: {token || "expired"}</p>
        <AuthGate fallback={<p className="mt-3 text-sm text-rose-700">No authenticated session.</p>}>
          <button className="btn mt-4" onClick={() => authManager.clearSession()} type="button">Clear Session</button>
        </AuthGate>
      </section>
    </>
  );
}
