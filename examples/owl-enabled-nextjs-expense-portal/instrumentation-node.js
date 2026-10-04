// A05: building the portal runs assertHardened(). On a high-severity
// misconfiguration, such as OWL_DEBUG=true, the process exits: Next.js would
// otherwise stay up and answer every request with a 500, which a deploy
// pipeline can mistake for a healthy server.
import { portal } from "./lib/portal.js";

try {
  const { hardening } = portal();
  console.log(`[owl] hardening check passed (${hardening.length} non-blocking finding(s))`);
} catch (error) {
  console.error(`[owl] refusing to start: ${error.message}`);
  process.exit(1);
}
