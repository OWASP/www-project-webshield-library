import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createIncidentDeskApp } from "./app.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const production = process.argv.includes("--production");
const port = Number(process.env.PORT || (production ? 8080 : 8788));

const { app } = createIncidentDeskApp({
  distDir: production ? join(root, "dist") : null,
  sessionTtlMs: Number(process.env.SESSION_TTL_MS || 15 * 60_000),
  echoLogs: process.env.OWL_ECHO_LOGS === "true"
});

app.listen(port, () => {
  console.log(
    production
      ? `OWL Incident Desk on http://localhost:${port}`
      : `OWL Incident Desk API on http://localhost:${port} (the Vue dev server proxies /api here)`
  );
});
