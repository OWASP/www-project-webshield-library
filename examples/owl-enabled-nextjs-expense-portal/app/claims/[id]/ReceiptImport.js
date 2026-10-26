"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { useSecureHttpClient } from "@owasp-webshield/next/client";

/** A10: the server fetches the URL, so the server decides which URLs are allowed. */
export function ReceiptImport({ id }) {
  const http = useSecureHttpClient();
  const router = useRouter();
  const [url, setUrl] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(event) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    const response = await http.request(`/api/claims/${id}/receipt`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    setBusy(false);
    if (!response.ok) {
      const { error: code, errors, message } = response.data || {};
      setError(code === "SSRF_BLOCKED" ? "That address isn't allowed (internal or private network)." : errors?.[0]?.message || message || "Import failed");
      return;
    }
    setUrl("");
    router.refresh();
  }

  return (
    <form onSubmit={onSubmit}>
      <div className="field">
        <label htmlFor="receipt-url">Import a receipt from a link</label>
        <input id="receipt-url" type="url" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://receipts.example.com/r/123.pdf" required maxLength={2048} />
        <p className="hint">PDF, PNG or JPEG, up to 2 MB, from a public https:// or http:// address.</p>
      </div>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <button type="submit" className="secondary" disabled={busy}>
        {busy ? "Importing…" : "Import receipt"}
      </button>
    </form>
  );
}
