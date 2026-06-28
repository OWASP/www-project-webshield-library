import React from "react";
import { SanitizedText, useInputSanitizer } from "@owl/react-adapter/a03-injection-defense/index.js";

export default function A03Page() {
  const sanitizer = useInputSanitizer("strict");
  const [input, setInput] = React.useState("<img src=x onerror=alert(1)>Hello<script>alert(2)</script>");
  const clean = sanitizer.sanitizeHTML(input);

  return (
    <>
      <section className="panel">
        <h2 className="panel-title">A03 Injection</h2>
        <p className="mt-2 text-sm text-slate-600">Input is sanitized before rendering or persistence.</p>
        <textarea className="input mt-3 h-28" value={input} onChange={(e) => setInput(e.target.value)} />
      </section>
      <section className="panel">
        <h3 className="panel-title">Sanitization Output</h3>
        <p className="mt-3 text-sm"><strong>Strict output:</strong> {clean}</p>
        <p className="mt-2 text-sm"><strong>SanitizedText component:</strong> <SanitizedText html={input} profile="strict" /></p>
      </section>
    </>
  );
}
