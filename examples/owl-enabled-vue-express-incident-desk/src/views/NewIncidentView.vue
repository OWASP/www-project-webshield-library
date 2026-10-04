<script setup>
import { computed, reactive, ref } from "vue";
import { useRouter } from "vue-router";
import { SecurityAlert } from "@owasp-webshield/vue";
import { INCIDENT_SCHEMA, SEVERITIES } from "../../shared/policy.js";
import { useApi } from "../api.js";

const api = useApi();
const router = useRouter();
const form = reactive({ title: "", severity: "medium", description: "" });
const fieldErrors = ref({});
const error = ref("");
const busy = ref(false);
const limits = computed(() => ({ title: INCIDENT_SCHEMA.title.maxLength, description: INCIDENT_SCHEMA.description.maxLength }));

async function submit() {
  busy.value = true;
  error.value = "";
  fieldErrors.value = {};
  try {
    const incident = await api.post("/incidents", { ...form });
    await router.push(`/incidents/${incident.id}`);
  } catch (caught) {
    // A03: the API's per-field errors, shown next to each field.
    fieldErrors.value = Object.fromEntries(caught.fieldErrors.map((e) => [e.field, e.message]));
    error.value = caught.fieldErrors.length ? "" : caught.message;
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <section class="card">
    <h1 id="page-title">Report an incident</h1>
    <form @submit.prevent="submit" novalidate>
      <label>
        Title
        <input id="title" v-model="form.title" :maxlength="limits.title" />
        <small v-if="fieldErrors.title" class="field-error" id="error-title">{{ fieldErrors.title }}</small>
      </label>
      <label>
        Severity
        <select id="severity" v-model="form.severity">
          <option v-for="severity in SEVERITIES" :key="severity" :value="severity">{{ severity }}</option>
        </select>
        <small v-if="fieldErrors.severity" class="field-error">{{ fieldErrors.severity }}</small>
      </label>
      <div class="split">
        <label>
          Description (basic HTML: &lt;b&gt;, &lt;i&gt;, &lt;a&gt;, lists…)
          <textarea id="description" v-model="form.description" rows="9" :maxlength="limits.description"></textarea>
          <small v-if="fieldErrors.description" class="field-error" id="error-description">{{ fieldErrors.description }}</small>
        </label>
        <div>
          <span class="label">Preview</span>
          <!-- A03: sanitized before it touches the DOM, exactly as the server will store it. -->
          <div id="preview" class="preview" v-safe-html:moderate="form.description"></div>
        </div>
      </div>
      <SecurityAlert v-if="error" id="form-error" :message="error" level="error" />
      <button id="submit" type="submit" :disabled="busy">Report incident</button>
    </form>
  </section>
</template>
