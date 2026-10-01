import { cpSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const tsc = fileURLToPath(new URL("../node_modules/typescript/bin/tsc", import.meta.url));

execFileSync(process.execPath, [tsc, "--project", "tsconfig.types.json"], {
	stdio: "inherit"
});
execFileSync(process.execPath, [tsc, "--project", "tsconfig.react.types.json"], {
	stdio: "inherit"
});

cpSync("dist/react", "src/adapters/react", { recursive: true });