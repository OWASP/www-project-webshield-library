"use client";

import { useState } from "react";
import { useSecureHttpClient } from "@owasp-webshield/next/client";

/**
 * A02/A09: the full account number is fetched only when finance asks for it,
 * is never part of the page HTML, and every reveal is written to the audit log.
 */
export function PayoutAccount({ id }) {
  const http = useSecureHttpClient();
  const [iban, setIban] = useState(null);
  const [error, setError] = useState(null);

  async function reveal() {
    const response = await http.request(`/api/claims/${id}/payout`);
    if (response.ok) setIban(response.data.iban ?? "Not on file");
    else setError(response.data?.message || "Not available");
  }

  if (iban) return <p><code>{iban}</code> <span className="muted">(this view was logged)</span></p>;
  return (
    <div className="actions">
      <button type="button" className="secondary" onClick={reveal}>
        Show full IBAN
      </button>
      {error && <span className="error">{error}</span>}
    </div>
  );
}
