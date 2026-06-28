import React from "react";
import { useAuthToken } from "@owl/react-adapter/a07-auth-session/index.js";
import { HTTPClient } from "@owl/core/src/core/a08-data-integrity/HTTPClient.js";

export default function A08Page() {
  const token = useAuthToken();
  const [responseData, setResponseData] = React.useState(null);
  const csrfManager = React.useMemo(
    () => ({
      attach: (headers) => ({
        ...headers,
        "X-CSRF-Token": "demo-csrf-token"
      })
    }),
    []
  );

  const client = React.useMemo(
    () =>
      new HTTPClient({
        baseUrl: "https://api.example.com",
        csrfManager,
        tokenProvider: () => token,
        fetchImpl: async (_url, options) => ({
          ok: true,
          status: 200,
          headers: options.headers,
          clone: () => ({ json: async () => ({ path: "/reports", headers: options.headers }) }),
          text: async () => "ok"
        })
      }),
    [csrfManager, token]
  );

  async function makeRequest() {
    const result = await client.request("/reports", {
      method: "GET",
      headers: {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY"
      }
    });
    setResponseData(result.data);
  }

  return (
    <>
      <section className="panel">
        <h2 className="panel-title">A08 Software and Data Integrity Failures</h2>
        <p className="mt-2 text-sm text-slate-600">HTTPClient adds CSRF, auth, and secure response/header controls.</p>
        <button className="btn mt-4" onClick={() => void makeRequest()} type="button">Send Secure Request</button>
      </section>
      <section className="panel">
        <h3 className="panel-title">Request Trace</h3>
        {responseData ? <pre className="code-block mt-3">{JSON.stringify(responseData, null, 2)}</pre> : <p className="mt-3 text-sm text-slate-500">Trigger a request to inspect normalized response data.</p>}
      </section>
    </>
  );
}
