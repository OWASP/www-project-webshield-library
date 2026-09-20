import React from "react";
import { security } from "./security";

function ShieldMark() {
  return (
    <span className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-owl-600 text-white shadow-lift">
      <svg viewBox="0 0 24 24" fill="none" className="h-6 w-6">
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

function RoleCard({ title, name, description, permissions, accent, onClick }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="group flex flex-1 flex-col rounded-xl border border-slate-200 bg-white p-5 text-left shadow-soft transition duration-150 hover:-translate-y-0.5 hover:border-owl-200 hover:shadow-lift"
    >
      <div className="flex items-center justify-between">
        <span className={`avatar ${accent}`}>{name.slice(0, 2).toUpperCase()}</span>
        <span className="text-owl-600 opacity-0 transition group-hover:opacity-100">&rarr;</span>
      </div>
      <p className="mt-4 text-base font-semibold text-slate-900">{title}</p>
      <p className="text-sm text-slate-500">{name}</p>
      <ul className="mt-3 space-y-1 text-xs text-slate-500">
        {permissions.map((item) => (
          <li key={item} className="flex items-center gap-1.5">
            <span className="h-1 w-1 rounded-full bg-owl-400" />
            {item}
          </li>
        ))}
      </ul>
      <p className="mt-3 text-xs text-slate-400">{description}</p>
    </button>
  );
}

export default function LoginPanel() {
  return (
    <section className="panel surface-hero w-full max-w-2xl text-center">
      <ShieldMark />
      <p className="section-kicker mt-4">OWL Enabled React Todo App</p>
      <h1 className="panel-title mt-1 text-2xl">Sign in to continue</h1>
      <p className="mx-auto mt-2 max-w-lg text-sm text-slate-600">
        Pick a demo identity to see RBAC + ACL access control, CSRF-protected sync,
        secret-strength checks, sanitized input, threat-model transition guards, and
        SSRF-safe outbound fetches all show up inside one real task-tracking workflow.
      </p>
      <div className="mt-6 flex flex-col gap-3 sm:flex-row">
        <RoleCard
          title="Member"
          name="riley"
          accent="bg-owl-600"
          permissions={["Read tasks", "Create & edit tasks"]}
          description="Standard team member access."
          onClick={() => security.login("member")}
        />
        <RoleCard
          title="Admin"
          name="avery"
          accent="bg-slate-800"
          permissions={["Everything a Member can do", "Security Dashboard access"]}
          description="Elevated role — still can't delete tasks."
          onClick={() => security.login("admin")}
        />
      </div>
      <p className="mt-5 text-xs text-slate-500">
        Task deletion is denied for every role by an explicit ACL policy that overrides RBAC —
        demonstrating OWL&apos;s deterministic deny-override conflict resolution.
      </p>
    </section>
  );
}
