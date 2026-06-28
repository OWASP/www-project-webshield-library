import React from "react";
import { SecurityAlert, useSecurityMonitoring } from "@owl/react-adapter/a09-logging-monitoring/index.js";

export default function A09Page() {
  const { logger, events } = useSecurityMonitoring();
  const [messages, setMessages] = React.useState([]);

  React.useEffect(() => {
    if (!events) return undefined;
    return events.on("demo:security", (payload) => {
      setMessages((prev) => [JSON.stringify(payload), ...prev].slice(0, 5));
    });
  }, [events]);

  function raiseAlert() {
    const payload = { at: new Date().toISOString(), type: "policy_violation", actor: "demo-user" };
    events?.emit("demo:security", payload);
    logger?.warn("security alert emitted", payload);
  }

  return (
    <>
      <section className="panel">
        <h2 className="panel-title">A09 Security Logging and Monitoring Failures</h2>
        <p className="mt-2 text-sm text-slate-600">SecurityProvider gives access to an event bus and centralized logger.</p>
        <button className="btn mt-4" onClick={raiseAlert} type="button">Emit Security Event</button>
      </section>
      <section className="panel">
        <h3 className="panel-title">Latest Alerts</h3>
        {messages.length === 0 ? <p className="mt-3 text-sm text-slate-500">No alerts yet.</p> : null}
        <div className="mt-3 space-y-2">
          {messages.map((msg) => (
            <SecurityAlert key={msg} level="warn" message={msg} />
          ))}
        </div>
      </section>
    </>
  );
}
