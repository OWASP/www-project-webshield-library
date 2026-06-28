import React from "react";
import { usePermission } from "@owl/react-adapter/a01-access-control/index.js";
import { useAuth } from "@owl/react-adapter/a07-auth-session/index.js";

export default function A01Page() {
  const { session } = useAuth();
  const canRead = usePermission("read", "reports");
  const canDelete = usePermission("delete", "reports");

  return (
    <>
      <section className="panel">
        <h2 className="panel-title">A01 Broken Access Control</h2>
        <p className="mt-2 text-sm text-slate-600">Permission checks combine RBAC role grants with ACL deny-overrides.</p>
        <div className="mt-4 space-y-2 text-sm">
          <p>User: <strong>{session?.userId}</strong></p>
          <p>Role: <strong>{session?.roles?.[0]}</strong></p>
        </div>
      </section>
      <section className="panel">
        <h3 className="panel-title">Decision Matrix</h3>
        <div className="mt-3 space-y-2 text-sm">
          <p>Read reports: <span className={canRead.allowed ? "text-emerald-700" : "text-rose-700"}>{canRead.allowed ? "allowed" : "denied"}</span></p>
          <p>Delete reports: <span className={canDelete.allowed ? "text-emerald-700" : "text-rose-700"}>{canDelete.allowed ? "allowed" : "denied"}</span></p>
          <p className="text-xs text-slate-500">Delete is denied by ACL policy even when RBAC grants admin privileges.</p>
        </div>
      </section>
    </>
  );
}
