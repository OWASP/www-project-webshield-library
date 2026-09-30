# A06 — Vulnerable & Outdated Components

`DependencyRiskScanner` runs an async `scan()` you supply (e.g. wrapping `npm audit` or a vulnerability feed) and gates on severity; `ComponentPolicy` enforces allow/deny lists and minimum versions.

## Core API (`@owasp-webshield/core`)

```js
import { ComponentPolicy, DependencyRiskScanner } from "@owasp-webshield/core";

const scanner = new DependencyRiskScanner({
  scan: async () => [
    { name: "left-pad", severity: "high", currentVersion: "1.0.0", fixedVersion: "1.1.0" }
  ]
});

const results = await scanner.scan();
const gate = await scanner.passesPolicy("high");

const policy = new ComponentPolicy({
  allowlist: ["left-pad", "react"],
  denylist: ["unsafe-lib"],
  minVersions: { react: "18.3.1" }
});

policy.evaluate({ name: "react", version: "18.3.1" });
console.log(results, gate.pass);
```

## React Adapter (`@owasp-webshield/react`)

```jsx
import React from "react";
import { useDependencyRiskScanner } from "@owasp-webshield/react";

export function DependencyPanel({ provider }) {
  const { loading, results, error, runScan } = useDependencyRiskScanner(provider);

  React.useEffect(() => {
    runScan().catch(() => {});
  }, [runScan]);

  if (loading) return <div>Scanning...</div>;
  if (error) return <div>{error.message}</div>;
  return <pre>{JSON.stringify(results, null, 2)}</pre>;
}
```

- `runScan` is stable for a stable mounted hook instance and always uses the latest provider supplied to the hook.
- The hook state shape is `{ loading, results, error, runScan, scanner }`.
