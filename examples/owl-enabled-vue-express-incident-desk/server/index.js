import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createIncidentDeskApp } from "./app.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const production = process.argv.includes("--production");
const port = Number(process.env.PORT || (production ? 8080 : 8788));
// Loopback only by default: the demo accounts and their passwords are published in
// the README, so the server must not be reachable from the network. Set HOST=0.0.0.0
// (behind HTTPS) to expose it.
const host = process.env.HOST || "127.0.0.1";

const { app } = createIncidentDeskApp({
  distDir: production ? join(root, "dist") : null,
  sessionTtlMs: Number(process.env.SESSION_TTL_MS || 15 * 60_000),
  echoLogs: process.env.OWL_ECHO_LOGS === "true"
});

app.listen(port, host, () => {
  console.log(
    production
      ? `OWL Incident Desk on http://${host}:${port}`
      : `OWL Incident Desk API on http://${host}:${port} (the Vue dev server proxies /api here)`
  );
});
