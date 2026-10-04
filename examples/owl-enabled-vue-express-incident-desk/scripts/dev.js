// Starts the Express API and the Vite dev server together (npm run dev).
import { spawn } from "node:child_process";

const children = [
  spawn(process.execPath, ["--watch", "server/index.js"], { stdio: "inherit" }),
  spawn(process.execPath, ["node_modules/vite/bin/vite.js"], { stdio: "inherit" })
];

const stop = () => {
  for (const child of children) child.kill();
  process.exit();
};
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
for (const child of children) child.on("exit", (code) => code && stop());
