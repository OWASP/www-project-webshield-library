import { defineConfig } from "vite";

export default defineConfig({
  resolve: {
    // @owasp-webshield/react is a symlinked local package (npm "file:" dependency).
    // Without dedupe, Vite resolves its React import against the symlink's real
    // path (the workspace-hoisted root node_modules/react) while this app resolves
    // its own React import against its own node_modules/react, producing two React
    // instances in one bundle and a null hook-dispatcher crash at runtime.
    dedupe: ["react", "react-dom"]
  }
});
