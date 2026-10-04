import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { securityHeadersConfig } from "@owasp-webshield/next";

const here = dirname(fileURLToPath(import.meta.url));

export default {
  // A05: don't advertise the framework.
  poweredByHeader: false,

  // A05: security headers and a CSP for every page. API routes are left out:
  // withOwl() gives them the stricter JSON API headers, and next.config headers
  // would otherwise replace those.
  async headers() {
    return securityHeadersConfig({}, { source: "/((?!api/).*)" });
  },

  // The OWL packages are linked from this repository (file:../..), outside this
  // folder, so Turbopack has to be allowed to read the repository root.
  turbopack: { root: resolve(here, "../..") }
};
