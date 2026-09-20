import { SecretsVault } from "./vault.js";

function section(title) {
  console.log(`\n=== ${title} ===`);
}

async function main() {
  const vault = new SecretsVault();

  section("A05 — Hardening check at boot");
  const findings = vault.runHardeningCheck();
  console.log(findings.length ? findings : "No misconfiguration findings — secure defaults in effect.");

  section("A04 — Design checklist self-audit");
  const checklist = vault.runDesignChecklist([
    "role_based_access_control",
    "per_secret_deny_override",
    "aes_256_gcm_encryption_at_rest",
    "secret_strength_check",
    "csrf_protection",
    "ssrf_guard",
    "redacted_structured_logging",
    "dependency_risk_scanning"
  ]);
  console.log(`All required controls present: ${checklist.valid}`, checklist.missing.length ? { missing: checklist.missing } : "");

  section("A07 — Sessions for two demo users");
  console.log("admin  -> avery (role: admin)");
  console.log("viewer -> riley (role: viewer)");

  section("A02/A03 — Creating secrets (validated, sanitized, encrypted)");
  const dbPassword = vault.createSecret({
    role: "contributor",
    name: "DB_PASSWORD",
    value: "Tr0ub4dor&3-xkcd-strength!",
    description: "Primary Postgres password"
  });
  console.log("Created DB_PASSWORD:", dbPassword);

  const weakApiKey = vault.createSecret({
    role: "contributor",
    name: "LEGACY_API_KEY",
    value: "12345",
    description: "Legacy vendor API key <script>alert(1)</script>"
  });
  console.log("Created LEGACY_API_KEY:", weakApiKey, "(sanitized description strips the script tag)");

  section("A01 — RBAC: viewer cannot reveal secrets");
  try {
    vault.revealSecret({ role: "viewer", name: "DB_PASSWORD" });
    console.log("UNEXPECTED: viewer was allowed to reveal a secret");
  } catch (error) {
    console.log(`Blocked as expected: ${error.code} — ${error.message}`);
  }

  section("A02/A09 — Admin reveals a secret (value is redacted in the log line)");
  const revealed = vault.revealSecret({ role: "admin", name: "DB_PASSWORD" });
  console.log(`Decrypted value handed back to caller: ${revealed}`);
  console.log("(check the [info] secret.revealed log above — secretValue prints as [REDACTED])");

  section("A01 — Per-secret deny-override: freeze LEGACY_API_KEY, then try to reveal it");
  vault.freezeSecret({ role: "admin", name: "LEGACY_API_KEY", frozen: true });
  try {
    vault.revealSecret({ role: "admin", name: "LEGACY_API_KEY" });
    console.log("UNEXPECTED: admin revealed a frozen secret");
  } catch (error) {
    console.log(`Blocked as expected even for admin: ${error.code} — ${error.details?.reason}`);
  }
  vault.freezeSecret({ role: "admin", name: "LEGACY_API_KEY", frozen: false });
  console.log("Unfrozen — reveal now succeeds:", vault.revealSecret({ role: "admin", name: "LEGACY_API_KEY" }));

  section("A04 — Rotating DB_PASSWORD");
  const rotated = vault.rotateSecret({ role: "admin", name: "DB_PASSWORD", newValue: "N3w-Str0nger-Passw0rd!!" });
  console.log("Rotated:", rotated);

  section("A02 — Rotation-window check across the vault");
  for (const entry of vault.listSecrets({ role: "viewer" })) {
    console.log(`${entry.name}: age=${Math.round(entry.ageMs / 1000)}s, rotationOverdue=${entry.rotationOverdue}, status=${entry.status}`);
  }

  section("A06 — Real npm-audit dependency scan (against the repo root)");
  try {
    const scan = await vault.runDependencyScan("high");
    console.log(`Passes "high" severity gate: ${scan.pass}`);
    console.log(`Findings at or above threshold: ${scan.blocked.length}`);
    if (scan.blocked.length) console.log(scan.blocked.slice(0, 5));
  } catch (error) {
    console.log(`Dependency scan unavailable in this environment: ${error.message}`);
  }

  section("A08/A10 — Outbound webhook notification, guarded by SSRFGuard");
  const safeNotification = await vault.notifyWebhook("https://hooks.example.com/incidents", {
    event: "secret_rotated",
    name: "DB_PASSWORD"
  });
  console.log("Delivered to public endpoint:", safeNotification);

  try {
    await vault.notifyWebhook("http://169.254.169.254/latest/meta-data/", { event: "should_be_blocked" });
    console.log("UNEXPECTED: SSRF guard allowed a cloud metadata target");
  } catch (error) {
    console.log(`Blocked as expected: ${error.code} — ${error.message}`);
  }

  section("A09 — Full audit trail");
  console.log(JSON.stringify(vault.auditLog, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
