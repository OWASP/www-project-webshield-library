---
title: GettingStarted
displaytext: Getting Started
layout: null
tab: true
order: 2
tags: owasp javascript react security-library top10
---

## Getting Started

<p align="center">
  <img src="https://img.shields.io/badge/node-%3E%3D20-brightgreen" alt="Node 20+" />
  &nbsp;
  <img src="https://img.shields.io/badge/type-ESM%20%2B%20CJS-informational" alt="ESM + CJS" />
  &nbsp;
  <img src="https://img.shields.io/badge/react-%3E%3D18-61DAFB?logo=react" alt="React 18+" />
</p>

---

### Requirements

| Requirement | Version |
|---|---|
| Node.js | `>= 20` |
| React (adapter only) | `>= 18` |
| Package manager | npm, pnpm, or yarn |

---

### Install

```bash
# Install dependencies
npm install

# Verify the quality gate passes
npm run check
```

---

### Core Usage — 5-minute example

```js
import {
  ACLManager,
  AuthManager,
  PermissionChecker,
  RBACManager,
  TokenManager
} from "@owl/core";

// 1. Set up auth and token management
const tokenManager = new TokenManager();
tokenManager.setTokens({ accessToken: "jwt", expiresAt: Date.now() + 3_600_000 });

const authManager = new AuthManager({ tokenManager });
authManager.setSession({ userId: "u1", roles: ["admin"] });

// 2. Define role permissions
const rbac = new RBACManager();
rbac.defineRole("admin", ["read:invoice", "update:invoice"]);

// 3. Add ACL policy overrides
const acl = new ACLManager();
acl.setPolicy("invoice", "delete", "deny");

// 4. Check combined permission (deny-overrides)
const checker = new PermissionChecker({ rbacManager: rbac, aclManager: acl });
console.log(checker.check({ role: "admin", action: "read", resource: "invoice" }));
// → { allowed: true, reason: "allowed", metadata: { ... } }
```

---

### React Adapter — Provider Composition

```jsx
import { AuthProvider, ACLProvider, RBACProvider, AuthGate, PermissionGate }
  from "@owl/react-adapter";

export function AppShell({ authManager, aclManager, rbacManager, children }) {
  return (
    <AuthProvider authManager={authManager}>
      <ACLProvider aclManager={aclManager}>
        <RBACProvider rbacManager={rbacManager}>
          <AuthGate fallback={<div>Sign in required</div>}>
            <PermissionGate action="read" resource="reports"
              fallback={<div>Access denied</div>}>
              {children}
            </PermissionGate>
          </AuthGate>
        </RBACProvider>
      </ACLProvider>
    </AuthProvider>
  );
}
```

---

### Run the Examples

**Core Node demo (no build required)**
```bash
node examples/core-node-demo/index.js
```

**React Vite demo**
```bash
cd examples/react-adapter-demo
npm install && npm run dev
```

**Full multi-page reference app**
```bash
cd examples/owl-enabled-app
npm install && npm run dev
```

---

### Available Scripts

```bash
npm run check    # lint + test (full quality gate)
npm run test     # Jest unit tests only
npm run lint     # ESLint only
npm run build    # Build ESM + CJS outputs
```

---

### CI/CD Baseline

```yaml
- name: Install
  run: npm ci

- name: Quality gate
  run: npm run check

- name: Build
  run: npm run build
```

---

### Further Reading

| Resource | Description |
|---|---|
| [docs/api-reference.md](https://github.com/OWASP/www-project-webshield-library/blob/main/docs/api-reference.md) | Complete API with copyable examples |
| [docs/framework.md](https://github.com/OWASP/www-project-webshield-library/blob/main/docs/framework.md) | Adoption patterns and bootstrap guide |
| [docs/architecture.md](https://github.com/OWASP/www-project-webshield-library/blob/main/docs/architecture.md) | Module layout and design decisions |
| [docs/troubleshooting.md](https://github.com/OWASP/www-project-webshield-library/blob/main/docs/troubleshooting.md) | Common issues and resolutions |
