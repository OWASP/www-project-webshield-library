# @owasp-core/owl-react

React adapter for [OWL (OWASP Web Shield Library)](https://owasp.org/www-project-webshield-library/) — category-aligned providers, hooks, and guard components for [`@owasp-core/owl`](https://www.npmjs.com/package/@owasp-core/owl), covering every OWASP Top 10 category (A01–A10).

## Installation

```bash
npm install @owasp-core/owl @owasp-core/owl-react
```

`@owasp-core/owl` is a peer dependency in spirit (declared as a regular dependency here so a bare `npm install @owasp-core/owl-react` works), and `react`/`react-dom` `>=18` are required peer dependencies.

## Quick start

```jsx
import React from "react";
import {
  AuthProvider,
  ACLProvider,
  RBACProvider,
  AuthGate,
  PermissionGate
} from "@owasp-core/owl-react";

export function App({ authManager, aclManager, rbacManager }) {
  return (
    <AuthProvider authManager={authManager}>
      <ACLProvider aclManager={aclManager}>
        <RBACProvider rbacManager={rbacManager}>
          <AuthGate fallback={<div>Please sign in</div>}>
            <PermissionGate action="read" resource="reports" fallback={<div>Forbidden</div>}>
              <div>Secure Content</div>
            </PermissionGate>
          </AuthGate>
        </RBACProvider>
      </ACLProvider>
    </AuthProvider>
  );
}
```

## Module map

| Category | Exports |
|---|---|
| A01 Access Control | `ACLProvider`, `RBACProvider`, `useACL`, `usePermission`, `PermissionGate` |
| A02 Crypto Integrity | `useCryptoManager` ([Node-only](https://owasp.org/www-project-webshield-library/faq#can-i-use-owl-in-a-browser-bundle) for real encryption — safe to import in a browser build, but its methods throw there) |
| A03 Injection Defense | `useInputSanitizer`, `SanitizedText` |
| A04 Insecure Design Guard | `useThreatModelGuard` |
| A05 Security Misconfiguration | `useHardeningReport` |
| A06 Vulnerable Components | `useDependencyRiskScanner` |
| A07 Auth Session | `AuthProvider`, `useAuth`, `useAuthToken`, `AuthGate` |
| A08 Data Integrity | `useSecureHttpClient`, `withSecurityHeaders` |
| A09 Logging Monitoring | `SecurityProvider`, `useSecurityMonitoring`, `SecurityAlert` |
| A10 SSRF Defense | `useSafeFetcher` |

Each category is also available as a deep import (e.g. `@owasp-core/owl-react/a01-access-control/index.js`) if you only need one.

## Documentation

- [Full React adapter usage guide](https://github.com/OWASP/www-project-webshield-library/blob/main/docs/react-adapter-usage.md)
- [API reference](https://github.com/OWASP/www-project-webshield-library/blob/main/docs/api-reference.md)
- [Runnable example (owl-enabled-react-todo-app)](https://github.com/OWASP/www-project-webshield-library/tree/main/examples/owl-enabled-react-todo-app)
- [FAQ](https://owasp.org/www-project-webshield-library/faq)

## License

Apache-2.0 — see the [main repository](https://github.com/OWASP/www-project-webshield-library) for the full license text and contribution guidelines.
