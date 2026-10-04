# Vue Adapter Usage Example

## Goal

Show how to wire `@owasp-webshield/vue` (the plugin, composables, components, `v-safe-html` and
the router guard) around real `@owasp-webshield/core` managers in a Vue 3 app.

## Setup: `createOwlClient` + `createOwl`

`createOwlClient()` (core) builds the managers from one config object, and `createOwl()` (Vue
adapter) turns them into a plugin. This replaces the React adapter's `<OwlProvider>`.

```js
// security.js
import { createOwlClient } from "@owasp-webshield/core";
import { createOwl } from "@owasp-webshield/vue";

export function createSecurity() {
  const client = createOwlClient({
    roles: {
      viewer: { permissions: ["read:articles"] },
      editor: { permissions: ["update:articles"], inherits: ["viewer"] }
    },
    acl: [{ resource: "articles", action: "delete", effect: "deny" }]
  });
  return { client, owl: createOwl({ client }) };
}
```

```js
// main.js
import { createApp } from "vue";
import { vSafeHtml } from "@owasp-webshield/vue";
import App from "./App.vue";
import { router } from "./router.js";
import { createSecurity } from "./security.js";

const { owl } = createSecurity();

createApp(App)
  .use(owl)
  .use(router)
  .directive("safe-html", vSafeHtml)
  .mount("#app");
```

`createOwl()` also accepts individual managers (`authManager`, `rbacManager`, `aclManager`,
`logger`, `events`), and these override the same managers in `client`. The plugin subscribes to
the auth and token events once, and unsubscribes when the app unmounts.

### Different managers for part of the tree

`provideOwl()` provides its own managers to the calling component's subtree, for example an
embedded admin console signed in separately. Its subscriptions end when that component unmounts.

```js
import { provideOwl } from "@owasp-webshield/vue";

export default {
  setup() {
    provideOwl({ client: adminClient });
  }
};
```

### Server-side rendering

Call `createSecurity()` inside the app factory so every request gets its own managers. A
module-level client would share one user's session with every other request rendered by the same
server process. During SSR the plugin schedules no token-expiry timers.

## Signing in

The adapter reads state from the core managers, so sign-in code calls them directly. The
composables and components update on their own.

```js
async function signIn(credentials) {
  const { accessToken, refreshToken, expiresAt, user } = await api.login(credentials);
  client.tokenManager.setTokens({ accessToken, refreshToken, expiresAt });
  client.authManager.setSession({ userId: user.id, roles: user.roles });
}

function signOut() {
  client.authManager.clearSession(); // also clears the tokens
}
```

`isAuthenticated` also turns false on its own when the access token's `expiresAt` passes.

## Use composables and components in features

```vue
<script setup>
import { useRoute } from "vue-router";
import {
  AuthGate,
  PermissionGate,
  SecurityAlert,
  useAuthToken,
  usePermission,
  useSecureHttpClient
} from "@owasp-webshield/vue";

defineProps({ article: { type: Object, required: true } });

const route = useRoute();
const token = useAuthToken();

// A01: recomputes when the route or the session changes.
const canEdit = usePermission("update", () => `article:${route.params.id}`);

// A08: sends the XSRF-TOKEN cookie as X-CSRF-Token and the access token as a Bearer header.
const http = useSecureHttpClient({ baseUrl: "/api", tokenProvider: () => token.value });

async function save(article) {
  await http.value.request(`/articles/${article.id}`, { method: "PUT", body: JSON.stringify(article) });
}
</script>

<template>
  <AuthGate>
    <article>
      <div v-safe-html:moderate="article.body"></div>
      <button v-if="canEdit.allowed" @click="save(article)">Save</button>
    </article>

    <PermissionGate action="delete" resource="articles">
      <button>Delete</button>
      <template #fallback>
        <SecurityAlert message="Deleting articles is disabled." level="info" />
      </template>
    </PermissionGate>

    <template #fallback>Please sign in.</template>
  </AuthGate>
</template>
```

### Composables

| Category | Composable | Returns |
|---|---|---|
| A01 | `usePermission(action, resource)` | `ComputedRef<{ allowed, reason }>`; allowed if any of the session's roles grants it, with ACL deny-overrides |
| A01 | `useACL()` | the `ACLManager` |
| A02 | `useCryptoManager(options)` | `ComputedRef<CryptoManager>` (methods throw in browser builds) |
| A03 | `useInputSanitizer(profile, options)` | `ComputedRef<InputSanitizer>` |
| A04 | `useThreatModelGuard(config)` | `ComputedRef<ThreatModelGuard>` |
| A05 | `useHardeningReport(config)` | `ComputedRef` of findings |
| A06 | `useDependencyRiskScanner(provider)` | `{ loading, results, error, runScan, scanner }`; overlapping scans don't overwrite newer results |
| A07 | `useAuth()` | `{ authManager, session, isAuthenticated }` (read-only refs) |
| A07 | `useAuthToken()` | read-only `Ref<string \| null>` |
| A08 | `useSecureHttpClient(options)` | `ComputedRef<HTTPClient>` |
| A09 | `useSecurityMonitoring()` | `{ logger, events }` |
| A10 | `useSafeFetcher(config, fetchImpl)` | `ComputedRef<SafeFetcher>` |

Arguments can be plain values, refs or getters (`() => ...`). Composables that build a core
object rebuild it when a reactive argument changes. A plain object argument is read once.
`fetchImpl` is the exception: pass the function itself, or a ref holding it, because a function
argument is never called as a getter.

`usePermission()` recomputes when the session or its arguments change. A rule changed at runtime
with `aclManager.setPolicy()` takes effect on the next change, the same as the React adapter's
`usePermission()`.

### Components

| Component | Purpose |
|---|---|
| `<AuthGate>` | Default slot when signed in, `#fallback` slot otherwise |
| `<PermissionGate action resource>` | Default slot when permitted, `#fallback` slot otherwise |
| `<SanitizedText :html profile allowed-classes>` | Renders sanitized HTML in a `<span>` |
| `<SecurityAlert message level>` | `role="alert"` element; the message is rendered as text |

## Replace `v-html` with `v-safe-html`

`v-html` inserts its value as raw HTML, which makes it Vue's most common XSS sink. `v-safe-html`
takes the same value and runs it through `InputSanitizer` first.

| Usage | Result |
|---|---|
| `v-safe-html="value"` | Strict profile: text only, entities encoded |
| `v-safe-html:moderate="value"` | Formatting tags plus safe links and images; `javascript:` URLs and event handlers removed |
| `v-safe-html="{ html, profile, allowedClasses }"` | Explicit profile, keeping only the listed class names |

It re-sanitizes when the value changes, and leaves the DOM alone when the result is unchanged.
To catch new `v-html` uses, enable the lint rule:

```js
// eslint.config.js
import pluginVue from "eslint-plugin-vue";

export default [...pluginVue.configs["flat/recommended"], { rules: { "vue/no-v-html": "error" } }];
```

Server-side rendering of `v-safe-html` needs Vue 3.4.36 or later. Older versions render an empty
element on the server and fill it in on the client.

## Protect routes

```js
// router.js
import { createRouter, createWebHistory } from "vue-router";
import { createOwlRouterGuard } from "@owasp-webshield/vue";

export function createAppRouter(owl) {
  const router = createRouter({
    history: createWebHistory(),
    routes: [
      { path: "/login", component: Login },
      { path: "/403", component: Forbidden },
      { path: "/account", component: Account, meta: { requiresAuth: true } },
      {
        path: "/articles",
        component: Articles,
        meta: { permission: { action: "read", resource: "articles" } },
        children: [
          {
            path: ":id/edit",
            component: EditArticle,
            meta: { permission: { action: "update", resource: (to) => `article:${to.params.id}` } }
          }
        ]
      }
    ]
  });
  router.beforeEach(createOwlRouterGuard(owl, { loginRoute: "/login", forbiddenRoute: "/403" }));
  return router;
}
```

- Meta on a parent route applies to its children. A route with a `permission` also requires a
  session.
- Signed-out users go to `loginRoute` with `?redirect=<path>`. After sign-in, send them back with
  `router.push(route.query.redirect)`, never `location.href = ...`, so the value can only be a
  path within the app.
- A denied navigation goes to `forbiddenRoute`, or is cancelled when there isn't one, and is logged
  as `navigation.denied` through the client's `SecurityLogger`.

## Notes

- `AuthGate`, `PermissionGate`, `usePermission()` and the router guard only decide what the UI
  shows. The server must still authenticate and authorize every request; see
  [Node & Express integration](./node-api-integration.md).
- The CSRF defaults (`XSRF-TOKEN` cookie, `X-CSRF-Token` header) match
  `@owasp-webshield/express`, so the two work together without configuration.
- Real encryption (`useCryptoManager`) needs Node. In a browser bundle its methods throw.
- Supported versions: Vue 3.3+, and Vue Router 4+ for the guard.
