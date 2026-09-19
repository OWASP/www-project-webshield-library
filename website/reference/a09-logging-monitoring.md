# A09 — Security Logging & Monitoring Failures

`SecurityLogger` redacts sensitive fields (and JWT-shaped values, by pattern) before anything reaches a sink; `EventEmitter` is a small typed pub/sub used to wire security events across a codebase.

## Core API (`@owasp-core/owl`)

```js
import { EventEmitter, SecurityLogger } from "@owasp-core/owl";

const events = new EventEmitter();
const logger = new SecurityLogger({
  sink: (entry) => {
    console.log(entry.level, entry.event, entry.details);
  }
});

const unsubscribe = events.on("auth:changed", (payload) => {
  logger.info("auth.changed", payload);
});

events.emit("auth:changed", {
  userId: "u1",
  authorization: "Bearer abc",
  password: "secret"
});

logger.warn("security.warning", { token: "abc", keep: "value" });
logger.error("security.error", { cookie: "session=1" });
unsubscribe();
```

::: tip Circular references and depth limits
`redact()` detects cycles and enforces a maximum recursion depth, so logging an object with a circular reference can't cause a stack-overflow denial of service. See [CHANGELOG](/changelog) for the 1.0.3 fix.
:::

## React Adapter (`@owasp-core/owl-react`)

```jsx
import React from "react";
import {
  SecurityAlert,
  SecurityContext,
  SecurityProvider,
  useSecurityMonitoring
} from "@owasp-core/owl-react";

function SecurityStatus() {
  const { logger, events } = useSecurityMonitoring();
  const securityContext = React.useContext(SecurityContext);

  React.useEffect(() => {
    logger?.info("security.status.rendered", { hasEvents: Boolean(events) });
  }, [logger, events]);

  return (
    <div>
      <div>{securityContext.logger ? "monitoring-enabled" : "monitoring-disabled"}</div>
      <SecurityAlert level="warn" message="Review recent security events" />
    </div>
  );
}

export function MonitoringExample({ logger, events }) {
  return (
    <SecurityProvider logger={logger} events={events}>
      <SecurityStatus />
    </SecurityProvider>
  );
}
```

- `useSecurityMonitoring()` is safe to call without a provider and returns `{ logger: null, events: null }`.
- `SecurityAlert` is a simple presentational component that renders a `role="alert"` container with a `data-level` attribute.
