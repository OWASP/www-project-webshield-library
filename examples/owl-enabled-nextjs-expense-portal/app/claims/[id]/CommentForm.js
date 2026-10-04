"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { useSecureHttpClient } from "@owasp-webshield/next/client";

/** Posts to the JSON API with the session's CSRF token (A08), then re-renders the page. */
export function CommentForm({ id }) {
  const http = useSecureHttpClient();
  const router = useRouter();
  const [error, setError] = useState(null);
  const [body, setBody] = useState("");

  async function onSubmit(event) {
    event.preventDefault();
    setError(null);
    const response = await http.request(`/api/claims/${id}/comments`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ body })
    });
    if (!response.ok) {
      setError(response.data?.errors?.[0]?.message || response.data?.message || "Couldn't add the comment");
      return;
    }
    setBody("");
    router.refresh();
  }

  return (
    <form onSubmit={onSubmit} style={{ marginTop: 12 }}>
      <div className="field">
        <label htmlFor="comment">Add a comment</label>
        <textarea id="comment" value={body} onChange={(event) => setBody(event.target.value)} maxLength={4000} required />
        <p className="hint">Basic formatting such as &lt;b&gt;, &lt;i&gt; and links is kept; scripts and event handlers are removed.</p>
      </div>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <button type="submit">Comment</button>
    </form>
  );
}
