<script setup>
import { ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { SecurityAlert } from "@owasp-webshield/vue";
import { signIn, useApi } from "../api.js";

const api = useApi();
const route = useRoute();
const router = useRouter();
const username = ref("");
const password = ref("");
const error = ref("");
const busy = ref(false);

// Only follow ?redirect= to a path inside this app: "//evil.example" and
// "/\evil.example" are protocol-relative URLs to another site.
function safeRedirect(value) {
  return typeof value === "string" && value.startsWith("/") && !value.startsWith("//") && !value.startsWith("/\\")
    ? value
    : "/incidents";
}

async function submit() {
  busy.value = true;
  error.value = "";
  try {
    await signIn(api, username.value, password.value);
    await router.replace(safeRedirect(route.query.redirect));
  } catch (caught) {
    error.value = caught.message;
  } finally {
    busy.value = false;
    password.value = "";
  }
}
</script>

<template>
  <section class="card narrow">
    <h1 id="page-title">Sign in</h1>
    <p v-if="route.query.redirect" class="muted" id="redirect-note">Sign in to continue to {{ route.query.redirect }}.</p>
    <form @submit.prevent="submit">
      <label>Username <input id="username" v-model="username" autocomplete="username" required /></label>
      <label>Password <input id="password" v-model="password" type="password" autocomplete="current-password" required /></label>
      <SecurityAlert v-if="error" id="login-error" :message="error" level="error" />
      <button id="sign-in" type="submit" :disabled="busy">{{ busy ? "Signing in…" : "Sign in" }}</button>
    </form>
    <details class="demo">
      <summary>Demo accounts</summary>
      <ul>
        <li><code>alice</code> / <code>owl-demo-reporter</code>: reporter</li>
        <li><code>riley</code> / <code>owl-demo-responder</code>: responder</li>
        <li><code>ada</code> / <code>owl-demo-admin</code>: admin</li>
      </ul>
    </details>
  </section>
</template>
