# Typed Errors

Every module throws the same typed error surface: `SecurityError`, carrying a stable `SecurityErrorCode`.

```js
import { SecurityError, SecurityErrorCode } from "@owasp-js/owl";

throw new SecurityError(SecurityErrorCode.ACCESS_DENIED, "Report access denied", {
  action: "read",
  resource: "reports"
});
```

Catching by code lets you handle specific failure modes without string-matching messages:

```js
import { SecurityError, SecurityErrorCode } from "@owasp-js/owl";

try {
  client.request("/profile", { method: "GET" });
} catch (error) {
  if (error instanceof SecurityError && error.code === SecurityErrorCode.CREDENTIAL_LEAK_BLOCKED) {
    // handle a blocked cross-origin credentialed request
  }
  throw error;
}
```

Common codes you'll see across modules include `ACCESS_DENIED` (A01), `CREDENTIAL_LEAK_BLOCKED` (A08), and SSRF-related blocks (A10) — each `SecurityError` also carries a `details` object with the context needed to log or act on the failure.
