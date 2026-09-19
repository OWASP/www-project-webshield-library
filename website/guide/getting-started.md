# Getting Started

OWL ships as two packages:

| Package | Purpose |
|---|---|
| [`@owasp-core/owl`](https://www.npmjs.com/package/@owasp-core/owl) | Framework-agnostic core — every A01–A10 module, usable from plain Node.js or any framework. |
| [`@owasp-core/owl-react`](https://www.npmjs.com/package/@owasp-core/owl-react) | React adapter — providers, hooks, and guard components built on top of the core. |

## Installation

::: code-group

```bash [npm]
npm install @owasp-core/owl
```

```bash [pnpm]
pnpm add @owasp-core/owl
```

```bash [yarn]
yarn add @owasp-core/owl
```

:::

If you're building a React app, also install the adapter:

```bash
npm install @owasp-core/owl-react
```

::: warning Browser bundling
`@owasp-core/owl`'s crypto and SSRF modules (`CryptoManager`, `SSRFGuard`, `SafeFetcher`) use Node's built-in `node:crypto` and `node:dns/promises`. Bundling them into a browser app with Vite/webpack requires polyfilling those built-ins, or avoiding those specific modules client-side. See the [FAQ](/faq#can-i-use-owl-in-a-browser-bundle) for details.
:::

## Quick Start

A minimal access-control example using `TokenManager`, `AuthManager`, `RBACManager`, and `ACLManager` together:

```js
import {
  TokenManager,
  AuthManager,
  RBACManager,
  ACLManager,
  PermissionChecker
} from "@owasp-core/owl";

const tokenManager = new TokenManager();
tokenManager.setTokens({ accessToken: "jwt", expiresAt: Date.now() + 3600000 });

const authManager = new AuthManager({ tokenManager });
authManager.setSession({ userId: "u1", roles: ["admin"] });

const rbac = new RBACManager();
rbac.defineRole("admin", ["read:invoice", "update:invoice"]);

const acl = new ACLManager();
acl.setPolicy("invoice", "delete", "deny");

const permissions = new PermissionChecker({ rbacManager: rbac, aclManager: acl });
console.log(permissions.check({ role: "admin", action: "read", resource: "invoice" }));
```

From here:

- Building a React app? Continue to [React Adapter Setup](/guide/react-setup).
- Want the full picture of which module covers which OWASP category? See the [Module Map](/guide/module-map).
- Looking for a specific class or hook? Jump straight into the [API Reference](/reference/a01-access-control).

## Runnable examples

The repository ships several runnable examples you can clone and run directly:

| Example | Description |
|---|---|
| [Core Node demo](https://github.com/OWASP/www-project-webshield-library/tree/main/examples/core-node-demo) | Plain Node script — `node index.js`, no build step |
| [React adapter demo](https://github.com/OWASP/www-project-webshield-library/tree/main/examples/react-adapter-demo) | Vite app exercising the React hooks and providers |
| [OWL enabled app](https://github.com/OWASP/www-project-webshield-library/tree/main/examples/owl-enabled-app) | Full multi-page reference app with one page per OWASP category |
