# A05 — Security Misconfiguration

`SecurityConfigManager` validates a config object against unsafe defaults (debug mode, permissive CORS, insecure cookies); `HardeningReporter` turns the findings into actionable recommendations.

## Core API (`@owasp-webshield/core`)

```js
import { HardeningReporter, SecurityConfigManager } from "@owasp-webshield/core";

const configManager = new SecurityConfigManager({
  debug: true,
  cors: { origin: "*" },
  cookies: { secure: false, sameSite: "None" }
});

configManager.validateSchema();
const findings = configManager.detectUnsafeSettings();
const report = new HardeningReporter(configManager).generate();

console.log(findings, report);
```

## React Adapter (`@owasp-webshield/react`)

```jsx
import React from "react";
import { useHardeningReport } from "@owasp-webshield/react";

export function ConfigDashboard({ config }) {
  const findings = useHardeningReport(config);

  return (
    <ul>
      {findings.map((finding) => (
        <li key={finding.id}>{finding.recommendation}</li>
      ))}
    </ul>
  );
}
```
