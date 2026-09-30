# A04 — Insecure Design

`ThreatModelGuard` enforces valid state transitions and abuse-case rules; `DesignChecklist` tracks whether required security controls have been acknowledged for a feature.

## Core API (`@owasp-webshield/core`)

```js
import { DesignChecklist, ThreatModelGuard } from "@owasp-webshield/core";

const guard = new ThreatModelGuard({
  transitions: { draft: ["review"], review: ["approved"] },
  abuseRules: [
    { id: "mfa", message: "MFA required", check: (context) => context.mfaVerified === true },
    { id: "rate-limit", message: "Too many attempts", check: (context) => context.attempts < 5 }
  ]
});

guard.validateTransition("draft", "review");
guard.evaluateAbuseCase({ mfaVerified: false, attempts: 7 });

const checklist = new DesignChecklist(["2fa", "audit-log", "csrf"]);
checklist.validate(["2fa", "audit-log"]);
```

## React Adapter (`@owasp-webshield/react`)

```jsx
import React from "react";
import { useThreatModelGuard } from "@owasp-webshield/react";

export function WorkflowActions() {
  const guard = useThreatModelGuard({ transitions: { draft: ["review"], review: ["approved"] } });
  const transition = guard.validateTransition("draft", "review");

  return <button disabled={!transition.valid}>Submit for review</button>;
}
```
