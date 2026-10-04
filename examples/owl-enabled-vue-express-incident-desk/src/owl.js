import { createOwlClient } from "@owasp-webshield/core";
import { createOwl } from "@owasp-webshield/vue";
import { ROLES } from "../shared/policy.js";

// The same roles the API enforces (shared/policy.js), so the UI's gates match.
// TokenManager keeps the access token in memory only: a reload signs the user
// out, and no script can read the token from localStorage.
export const client = createOwlClient({ roles: ROLES });

export const owl = createOwl({ client });
