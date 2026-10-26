// Runs once when the server starts. The startup check needs Node.js, so it
// lives in its own file that the Edge runtime never loads.
export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") await import("./instrumentation-node.js");
}
