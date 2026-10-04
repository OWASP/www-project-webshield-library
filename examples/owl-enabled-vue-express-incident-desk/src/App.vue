<script setup>
import { computed } from "vue";
import { useRouter } from "vue-router";
import { AuthGate, PermissionGate, useAuth, useAuthToken } from "@owasp-webshield/vue";
import { signOut, useApi } from "./api.js";
import { client } from "./owl.js";

const api = useApi();
const router = useRouter();
const { session } = useAuth();
const token = useAuthToken();

const expiresAt = computed(() => {
  // Re-read when the token changes (login, logout, expiry).
  if (!token.value) return null;
  const at = client.tokenManager.getTokens()?.expiresAt;
  return at ? new Date(at).toLocaleTimeString() : null;
});

// The router guard only leaves protected pages when the session ends, so go to
// the login page explicitly (the user may be on a public page such as /403).
async function onSignOut() {
  await signOut(api);
  await router.push("/login");
}
</script>

<template>
  <header class="topbar">
    <RouterLink to="/incidents" class="brand">🦉 OWL Incident Desk</RouterLink>
    <AuthGate>
      <nav>
        <RouterLink to="/incidents">Incidents</RouterLink>
        <PermissionGate action="create" resource="incidents">
          <RouterLink to="/incidents/new" id="nav-new">Report incident</RouterLink>
        </PermissionGate>
        <PermissionGate action="view" resource="audit">
          <RouterLink to="/admin" id="nav-admin">Admin</RouterLink>
        </PermissionGate>
      </nav>
      <div class="who">
        <span id="who-name">{{ session?.metadata?.name }}</span>
        <small v-if="expiresAt" id="who-expiry">session until {{ expiresAt }}</small>
        <button id="sign-out" class="secondary" @click="onSignOut">Sign out</button>
      </div>
    </AuthGate>
  </header>
  <main class="page">
    <RouterView />
  </main>
</template>
