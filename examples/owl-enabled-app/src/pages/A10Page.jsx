import React from "react";
import { useSafeFetcher } from "@owl/react-adapter/a10-ssrf-defense/index.js";

export default function A10Page() {
  const [result, setResult] = React.useState("No request yet");
  const safeFetcher = useSafeFetcher({}, async (url) => ({
    ok: true,
    url,
    json: async () => ({ status: "ok", url })
  }));

  async function testAllowed() {
    const response = await safeFetcher.fetch("https://example.com/data");
    const data = await response.json();
    setResult(`Allowed request to ${data.url}`);
  }

  async function testBlocked() {
    try {
      await safeFetcher.fetch("http://127.0.0.1/admin");
      setResult("Unexpected allow");
    } catch (error) {
      setResult(`Blocked as expected: ${error.message}`);
    }
  }

  return (
    <>
      <section className="panel">
        <h2 className="panel-title">A10 Server-Side Request Forgery</h2>
        <p className="mt-2 text-sm text-slate-600">SafeFetcher validates targets using SSRFGuard before any outbound call.</p>
        <div className="mt-4 flex gap-2">
          <button className="btn" onClick={() => void testAllowed()} type="button">Test Public URL</button>
          <button className="btn bg-rose-700 hover:bg-rose-600" onClick={() => void testBlocked()} type="button">Test Private URL</button>
        </div>
      </section>
      <section className="panel">
        <h3 className="panel-title">Validation Result</h3>
        <p className="mt-3 text-sm">{result}</p>
      </section>
    </>
  );
}
