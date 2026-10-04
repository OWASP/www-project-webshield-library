# @owasp-webshield/vue

Vue 3 adapter for [OWL (OWASP Webshield Library)](https://owasp.org/www-project-webshield-library/). It provides a plugin, category-aligned composables and guard components for [`@owasp-webshield/core`](https://www.npmjs.com/package/@owasp-webshield/core), covering every OWASP Top 10 category (A01–A10). It also adds a sanitizing `v-safe-html` directive and a Vue Router guard.

## Installation

```bash
npm install @owasp-webshield/core @owasp-webshield/vue
```

Requires `vue` 3.3 or later. `vue-router` 4 or later is needed only for `createOwlRouterGuard()`.

## Quick start

```js
// main.js
import { createApp } from "vue";
import { createOwlClient } from "@owasp-webshield/core";
import { createOwl, vSafeHtml } from "@owasp-webshield/vue";
import App from "./App.vue";

const owl = createOwl({
  client: createOwlClient({ roles: { viewer: { permissions: ["read:reports"] } } })
});

createApp(App).use(owl).directive("safe-html", vSafeHtml).mount("#app");
```

```vue
<!-- Reports.vue -->
<script setup>
import { AuthGate, PermissionGate, useAuth } from "@owasp-webshield/vue";
const { session } = useAuth();
defineProps({ report: Object });
</script>

<template>
  <AuthGate>
    <PermissionGate action="read" resource="reports">
      <h1>Reports for {{ session.userId }}</h1>
      <div v-safe-html="report.summary"></div>
      <template #fallback>You can't view reports.</template>
    </PermissionGate>
    <template #fallback>Please sign in.</template>
  </AuthGate>
</template>
```

Auth state is reactive. Logging in, logging out, a token refresh or a token expiring updates `useAuth()`, `usePermission()` and the gates without a reload.

## Module map

| Category | Exports |
|---|---|
| A01 Access Control | `usePermission`, `useACL`, `PermissionGate` |
| A02 Crypto Integrity | `useCryptoManager` ([Node-only](https://owasp.org/www-project-webshield-library/faq#can-i-use-owl-in-a-browser-bundle) for real encryption: safe to import in a browser build, but its methods throw there) |
| A03 Injection Defense | `useInputSanitizer`, `SanitizedText`, `vSafeHtml` |
| A04 Insecure Design Guard | `useThreatModelGuard` |
| A05 Security Misconfiguration | `useHardeningReport` |
| A06 Vulnerable Components | `useDependencyRiskScanner` |
| A07 Auth Session | `useAuth`, `useAuthToken`, `AuthGate` |
| A08 Data Integrity | `useSecureHttpClient`, `withSecurityHeaders` |
| A09 Logging Monitoring | `useSecurityMonitoring`, `SecurityAlert` |
| A10 SSRF Defense | `useSafeFetcher` |
| Setup | `createOwl`, `provideOwl`, `useOwl` |
| Routing | `createOwlRouterGuard` |

Composable arguments can be plain values, refs or getters. Composables that build a core object (`useSecureHttpClient`, `useSafeFetcher`, `useInputSanitizer`, ...) return a `ComputedRef` that is rebuilt when a reactive argument changes.

## `v-safe-html`

A drop-in replacement for `v-html`, which is Vue's most common XSS sink. The value goes through `InputSanitizer` before it is inserted:

```vue
<div v-safe-html="comment.body"></div>                 <!-- strict: text only -->
<div v-safe-html:moderate="post.body"></div>           <!-- formatting tags, safe links and images -->
<div v-safe-html="{ html: post.body, profile: 'moderate', allowedClasses: ['note'] }"></div>
```

Turn on `eslint-plugin-vue`'s `vue/no-v-html` rule so that new `v-html` uses get flagged. During server-side rendering, the directive needs Vue 3.4.36 or later; older versions render an empty element on the server and fill it in on the client.

## Router guard

```js
import { createOwlRouterGuard } from "@owasp-webshield/vue";

const routes = [
  { path: "/account", component: Account, meta: { requiresAuth: true } },
  { path: "/reports/:id", component: Report,
    meta: { permission: { action: "read", resource: (to) => `report:${to.params.id}` } } }
];

router.beforeEach(createOwlRouterGuard(owl, { loginRoute: "/login", forbiddenRoute: "/403" }));
```

## Security notes

- `AuthGate`, `PermissionGate` and the router guard only decide what the UI shows. The server must still authorize every request; see [`@owasp-webshield/express`](https://www.npmjs.com/package/@owasp-webshield/express).
- With server-side rendering (Nuxt, `createSSRApp`), call `createOwl()` inside the app factory so every request gets its own managers. A module-level instance would share one user's session with every other request.
- `useSecureHttpClient()` sends the server's `XSRF-TOKEN` cookie as `X-CSRF-Token`, which matches `@owasp-webshield/express`'s defaults. It never makes up a CSRF token in the browser.

## Documentation

- [Full Vue adapter usage guide](https://github.com/OWASP/www-project-webshield-library/blob/main/docs/vue-adapter-usage.md)
- [API reference](https://github.com/OWASP/www-project-webshield-library/blob/main/docs/api-reference.md)
- [FAQ](https://owasp.org/www-project-webshield-library/faq)

## License

Apache-2.0. See the [main repository](https://github.com/OWASP/www-project-webshield-library) for the full license text and contribution guidelines.
