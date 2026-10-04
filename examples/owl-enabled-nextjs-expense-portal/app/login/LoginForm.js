"use client";

import { useState } from "react";
import { useSecureHttpClient } from "@owasp-webshield/next/client";

export function LoginForm() {
  // A08: sends the XSRF-TOKEN cookie (set by the proxy on this page) back as
  // X-CSRF-Token, and refuses to attach it to any other origin.
  const http = useSecureHttpClient();
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(event) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    const form = new FormData(event.currentTarget);
    const response = await http.request("/api/session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: form.get("username"), password: form.get("password") })
    });
    if (response.ok) {
      // A full page load, so every Server Component renders with the new session.
      window.location.assign("/claims");
      return;
    }
    setBusy(false);
    setError(response.data?.message || "Sign-in failed");
  }

  return (
    <form onSubmit={onSubmit}>
      <div className="field">
        <label htmlFor="username">Username</label>
        <input id="username" name="username" autoComplete="username" required maxLength={64} />
      </div>
      <div className="field">
        <label htmlFor="password">Password</label>
        <input id="password" name="password" type="password" autoComplete="current-password" required maxLength={256} />
      </div>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <button type="submit" disabled={busy}>
        {busy ? "Signing in…" : "Sign in"}
      </button>
    </form>
  );
}
