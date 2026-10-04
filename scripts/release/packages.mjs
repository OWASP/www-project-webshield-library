import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = fileURLToPath(new URL("../..", import.meta.url));

/**
 * Every published package, in publish order. Each one's local dependencies
 * (`file:` specs) come earlier in the list; the release workflow publishes them
 * in the same order, a stage at a time.
 */
export const PACKAGES = [
  { id: "core", dir: "." },
  { id: "react", dir: "src/adapters/react" },
  { id: "vue", dir: "src/adapters/vue" },
  { id: "node", dir: "src/adapters/node" },
  { id: "express", dir: "src/adapters/express" },
  { id: "next", dir: "src/adapters/next" }
];

export function readManifest(dir) {
  return JSON.parse(readFileSync(join(ROOT, dir, "package.json"), "utf8"));
}
