import { useAuthToken, useSecureHttpClient } from "@owasp-webshield/vue";
import { client } from "./owl.js";

export class ApiError extends Error {
  constructor(status, body) {
    super(body?.message || `Request failed (${status})`);
    this.status = status;
    this.code = body?.error;
    // Per-field validation errors from the API: [{ field, code, message }]
    this.fieldErrors = Array.isArray(body?.errors) ? body.errors : [];
  }
}

/**
 * The API client. `useSecureHttpClient` (A08) sends the access token as a
 * Bearer header and the XSRF-TOKEN cookie as X-CSRF-Token, and refuses to
 * attach either to another origin.
 */
export function useApi() {
  const token = useAuthToken();
  const http = useSecureHttpClient({ tokenProvider: () => token.value });

  async function request(method, path, body) {
    const response = await http.value.request(`/api${path}`, {
      method,
      headers: body === undefined ? {} : { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    // The server ended the session (expired, signed out elsewhere): drop it here
    // too, and installOwlRouterGuard sends the user to the login page.
    if (response.status === 401 && token.value) client.authManager.clearSession();
    if (!response.ok) throw new ApiError(response.status, response.data);
    return response.data;
  }

  return {
    get: (path) => request("GET", path),
    post: (path, body) => request("POST", path, body ?? {}),
    patch: (path, body) => request("PATCH", path, body),
    put: (path, body) => request("PUT", path, body),
    del: (path) => request("DELETE", path)
  };
}

export async function signIn(api, username, password) {
  const { accessToken, expiresAt, user } = await api.post("/session", { username, password });
  client.tokenManager.setTokens({ accessToken, expiresAt });
  client.authManager.setSession({ userId: user.id, roles: user.roles, metadata: { name: user.name } });
}

export async function signOut(api) {
  try {
    await api.del("/session");
  } finally {
    client.authManager.clearSession();
  }
}
