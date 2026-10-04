<script setup>
import { onMounted, ref } from "vue";
import { PermissionGate, SecurityAlert } from "@owasp-webshield/vue";
import { useApi } from "../api.js";

const api = useApi();
const audit = ref([]);
const report = ref(null);
const scan = ref(null);
const scanning = ref(false);
const webhookUrl = ref("https://");
const webhookResult = ref(null);
const error = ref("");

async function loadAudit() {
  audit.value = await api.get("/admin/audit");
}

onMounted(async () => {
  try {
    [report.value] = await Promise.all([api.get("/admin/security-report"), loadAudit()]);
  } catch (caught) {
    error.value = caught.message;
  }
});

async function runScan() {
  scanning.value = true;
  try {
    scan.value = await api.post("/admin/dependency-scan");
  } catch (caught) {
    error.value = caught.message;
  } finally {
    scanning.value = false;
  }
}

async function testWebhook() {
  webhookResult.value = null;
  try {
    const result = await api.post("/admin/webhook-test", { url: webhookUrl.value });
    webhookResult.value = { ok: true, text: `Delivered (HTTP ${result.status})` };
  } catch (caught) {
    webhookResult.value = { ok: false, text: `${caught.code || "error"}: ${caught.message}` };
  }
  await loadAudit();
}
</script>

<template>
  <section>
    <h1 id="page-title">Admin</h1>
    <SecurityAlert v-if="error" :message="error" level="error" />

    <div class="grid">
      <section class="card" id="security-report">
        <h2>A05 hardening report</h2>
        <p v-if="report && !report.hardening.length" id="hardening-ok">✅ No unsafe settings at startup.</p>
        <ul v-else-if="report">
          <li v-for="finding in report.hardening" :key="finding.id">{{ finding.severity }}: {{ finding.id }}</li>
        </ul>
        <h2>A04 design checklist</h2>
        <p v-if="report" id="checklist">
          {{ report.designChecklist.valid ? "✅" : "⚠️" }} {{ report.designChecklist.required.length }} controls implemented
        </p>
      </section>

      <section class="card" id="dependency-scan">
        <h2>A06 dependency scan</h2>
        <p class="muted">Runs <code>npm audit</code> for this app; findings rated high or critical fail the policy.</p>
        <button id="run-scan" :disabled="scanning" @click="runScan">{{ scanning ? "Scanning…" : "Run scan" }}</button>
        <template v-if="scan">
          <p id="scan-result">{{ scan.passes ? "✅ Passes" : "❌ Fails" }}: {{ scan.findings.length }} finding(s)</p>
          <ul>
            <li v-for="finding in scan.blocked" :key="finding.package">{{ finding.package }} ({{ finding.severity }})</li>
          </ul>
        </template>
      </section>

      <PermissionGate action="manage" resource="integrations">
        <section class="card" id="webhook">
          <h2>A10 webhook test</h2>
          <p class="muted">Sends a test event. Private, loopback and cloud-metadata addresses are refused.</p>
          <form class="inline" @submit.prevent="testWebhook">
            <input id="webhook-url" v-model="webhookUrl" />
            <button id="webhook-send" type="submit">Send test</button>
          </form>
          <SecurityAlert
            v-if="webhookResult"
            id="webhook-result"
            :message="webhookResult.text"
            :level="webhookResult.ok ? 'info' : 'error'"
          />
        </section>
      </PermissionGate>
    </div>

    <section class="card" id="audit">
      <div class="row">
        <h2>A09 audit log <small class="muted">(redacted by SecurityLogger)</small></h2>
        <button class="secondary" id="refresh-audit" @click="loadAudit">Refresh</button>
      </div>
      <table>
        <thead><tr><th>Time</th><th>Level</th><th>Event</th><th>Details</th></tr></thead>
        <tbody>
          <tr v-for="(entry, index) in audit" :key="index" :class="entry.level">
            <td>{{ new Date(entry.ts).toLocaleTimeString() }}</td>
            <td>{{ entry.level }}</td>
            <td><code>{{ entry.event }}</code></td>
            <td><code class="details">{{ JSON.stringify(entry.details) }}</code></td>
          </tr>
        </tbody>
      </table>
    </section>
  </section>
</template>
