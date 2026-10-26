import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
  plugins: [vue()],
  resolve: {
    // The @owasp-webshield/* packages are symlinked into this repo; without this
    // the Vue adapter would resolve its own copy of vue and provide/inject would break.
    dedupe: ["vue", "vue-router"]
  },
  server: {
    port: 5173,
    // The Express API (npm run dev starts both); same origin for the browser, so no CORS.
    proxy: { "/api": "http://127.0.0.1:8788" }
  }
});
