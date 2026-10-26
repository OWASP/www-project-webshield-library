# Vue Adapter Setup

Install the adapter alongside the core package:

```bash
npm install @owasp-webshield/core @owasp-webshield/vue
```

It needs Vue 3.3 or later, and Vue Router 4 or later only if you use the router guard. The adapter mirrors the React adapter: every OWASP category has a matching composable, plus guard components, a plugin in place of `<OwlProvider>`, and two Vue-only additions.

## Install the plugin

`createOwlClient()` (core) builds the managers from one config object, and `createOwl()` turns them into a plugin:

```js
// main.js
import { createApp } from "vue";
import { createOwlClient } from "@owasp-webshield/core";
import { createOwl, vSafeHtml } from "@owasp-webshield/vue";
import App from "./App.vue";

const owl = createOwl({
  client: createOwlClient({
    roles: {
      viewer: { permissions: ["read:articles"] },
      editor: { permissions: ["update:articles"], inherits: ["viewer"] }
    },
    acl: [{ resource: "articles", action: "delete", effect: "deny" }]
  })
});

createApp(App).use(owl).directive("safe-html", vSafeHtml).mount("#app");
```

Auth state is reactive: signing in, signing out, a token refresh or a token expiring updates every composable and gate without a reload. With server-side rendering, call `createOwl()` inside the app factory so each request gets its own managers.

## Use composables and gates

```vue
<script setup>
import { useRoute } from "vue-router";
import { AuthGate, PermissionGate, useAuthToken, usePermission, useSecureHttpClient } from "@owasp-webshield/vue";

const route = useRoute();
const token = useAuthToken();

// Recomputes when the route or the session changes.
const canEdit = usePermission("update", () => `article:${route.params.id}`);

// Sends the XSRF-TOKEN cookie as X-CSRF-Token and the access token as a Bearer header.
const http = useSecureHttpClient({ baseUrl: "/api", tokenProvider: () => token.value });
</script>

<template>
  <AuthGate>
    <button v-if="canEdit.allowed">Edit</button>
    <PermissionGate action="delete" resource="articles">
      <button>Delete</button>
      <template #fallback>Deleting is disabled.</template>
    </PermissionGate>
    <template #fallback>Please sign in.</template>
  </AuthGate>
</template>
```

| Category | Exports |
|---|---|
| A01 | `usePermission`, `useACL`, `PermissionGate` |
| A02 | `useCryptoManager` (Node-only for real encryption; a throwing stub in browsers) |
| A03 | `useInputSanitizer`, `SanitizedText`, `vSafeHtml` |
| A04 | `useThreatModelGuard` |
| A05 | `useHardeningReport` |
| A06 | `useDependencyRiskScanner` |
| A07 | `useAuth`, `useAuthToken`, `AuthGate` |
| A08 | `useSecureHttpClient`, `withSecurityHeaders` |
| A09 | `useSecurityMonitoring`, `SecurityAlert` |
| A10 | `useSafeFetcher` |
| Setup and routing | `createOwl`, `provideOwl`, `useOwl`, `installOwlRouterGuard`, `createOwlRouterGuard` |

Composable arguments can be plain values, refs or getters. Composables that build a core object return a `ComputedRef` that is rebuilt when a reactive argument changes.

## Replace `v-html` with `v-safe-html`

`v-html` is Vue's most common XSS sink. `v-safe-html` takes the same value and sanitizes it first:

```vue
<div v-safe-html="comment.body"></div>          <!-- strict: text only -->
<div v-safe-html:moderate="post.body"></div>    <!-- formatting tags, safe links and images -->
<div v-safe-html="{ html: post.body, profile: 'moderate', allowedClasses: ['note'] }"></div>
```

It also sanitizes during server-side rendering (Vue 3.4.36+). Turn on `eslint-plugin-vue`'s `vue/no-v-html` rule to catch new `v-html` uses.

## Protect routes

```js
import { installOwlRouterGuard } from "@owasp-webshield/vue";

const routes = [
  { path: "/account", component: Account, meta: { requiresAuth: true } },
  { path: "/articles/:id/edit", component: Edit,
    meta: { permission: { action: "update", resource: (to) => `article:${to.params.id}` } } }
];

installOwlRouterGuard(router, owl, { loginRoute: "/login", forbiddenRoute: "/403" });
```

It checks every navigation, and also leaves an open page when the session ends, the token expires or the permission is lost. Gates and guards only decide what the UI shows; the server must still authorize every request (see [Node & Express Setup](/guide/server-setup)).

## Runnable example

[OWL Enabled Vue + Express Incident Desk](https://github.com/OWASP/www-project-webshield-library/tree/main/examples/owl-enabled-vue-express-incident-desk) is a full-stack app built this way. The complete guide is in the repository: [Vue adapter usage](https://github.com/OWASP/www-project-webshield-library/blob/main/docs/vue-adapter-usage.md).
