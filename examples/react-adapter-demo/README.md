# OWL React Adapter Demo

Runnable Vite example showing how to wire the React adapter around live core managers.

## Run

From this folder:

```bash
npm install
npm run dev
```

## What it demonstrates

- Provider composition with `SecurityProvider`, `AuthProvider`, `ACLProvider`, and `RBACProvider`
- Guard components with `AuthGate` and `PermissionGate`
- Hook usage for auth, permissions, secure HTTP, sanitization, threat modeling, dependency scanning, monitoring, and safe fetch
- Async token provider support in `useSecureHttpClient`

The demo uses local mocks so it runs without backend services.