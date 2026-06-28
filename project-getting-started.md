---
title: Getting Started
layout: null
tab: true
order: 2
tags: owasp javascript react security-library top10
---

## Setup

Requirements: Node.js 20+ recommended.

```bash
npm install
```

## Quality Gate

```bash
npm run check
```

## Build

```bash
npm run build
```

## Example Usage

```js
import { RBACManager, ACLManager, PermissionChecker } from "@owl/core";

const rbac = new RBACManager();
rbac.defineRole("admin", ["read:report", "update:report"]);

const acl = new ACLManager();
acl.setPolicy("report", "delete", "deny");

const checker = new PermissionChecker({ rbacManager: rbac, aclManager: acl });
const decision = checker.check({ role: "admin", action: "read", resource: "report" });
console.log(decision);
```

## CI/CD Baseline

```yaml
- name: Install
  run: npm ci

- name: Lint
  run: npm run lint

- name: Test
  run: npm run test

- name: Build
  run: npm run build
```

## Useful Docs

- [README.md](README.md)
- [docs/architecture.md](docs/architecture.md)
- [docs/framework.md](docs/framework.md)
- [docs/troubleshooting.md](docs/troubleshooting.md)
