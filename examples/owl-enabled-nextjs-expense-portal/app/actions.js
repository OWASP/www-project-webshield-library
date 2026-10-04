"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { assertValidInput, checkPermission } from "@owasp-webshield/next";
import { CSRF_COOKIE, getSession, runAction, SESSION_COOKIE } from "../lib/auth.js";
import { BANK_SCHEMA, CLAIM_SCHEMA } from "../lib/policy.js";
import { portal } from "../lib/portal.js";

// Server Actions are public POST endpoints: anyone can call one with any
// arguments, whether or not the page showing the form is protected. Each one
// below gets the session from the cookie (runAction) and lets the claims
// service check the permission. Next.js rejects calls from another origin.

const formFields = (formData, schema) => Object.fromEntries(Object.keys(schema).map((key) => [key, formData.get(key) ?? undefined]));

export async function submitClaim(_previous, formData) {
  const result = await runAction(async (session) => ({ claim: portal().claims.create(session, formFields(formData, CLAIM_SCHEMA)) }));
  if (result.ok) redirect(`/claims/${result.claim.id}`);
  return result;
}

export async function decideClaim(id, _previous, formData) {
  return runAction(async (session) => {
    const reason = formData.get("reason");
    portal().claims.setStatus(session, String(id), { status: formData.get("status"), ...(reason ? { reason } : {}) });
    return { message: "Saved." };
  });
}

export async function saveBankDetails(_previous, formData) {
  return runAction(async (session) => {
    const { iban } = assertValidInput(formFields(formData, BANK_SCHEMA), BANK_SCHEMA, { allowUnknownFields: false });
    const masked = portal().bankDetails.save(session.userId, iban);
    // A09: the account number itself never reaches the log.
    portal().logger.info("bank_details.updated", { userId: session.userId });
    return { message: `Saved. Payouts go to ${masked}.` };
  });
}

/** A06: one `npm audit` run of this app; findings at "high" or above fail the policy. */
export async function runDependencyScan() {
  return runAction(async (session) => {
    if (!checkPermission({ session, action: "run", resource: "security-checks" }, portal().owl).allowed) {
      throw Object.assign(new Error("No such page"), { status: 404 });
    }
    const { pass, blocked, results } = await portal().scanner.passesPolicy("high");
    portal().logger.info("security.dependency_scan", { by: session.userId, pass, findings: results.length });
    return { pass, blocked, findings: results.slice(0, 50) };
  });
}

export async function signOut() {
  const session = await getSession();
  if (session) {
    portal().sessions.destroy(session.metadata.token);
    portal().logger.info("auth.logout", { userId: session.userId });
  }
  // Expired with the same attributes they were set with: a browser ignores a
  // __Host- cookie (even a deletion) that isn't Secure with Path=/.
  const jar = await cookies();
  jar.set(SESSION_COOKIE, "", { path: "/", secure: true, httpOnly: true, sameSite: "lax", maxAge: 0 });
  jar.set(CSRF_COOKIE, "", { path: "/", secure: true, httpOnly: false, sameSite: "lax", maxAge: 0 });
  redirect("/login");
}
