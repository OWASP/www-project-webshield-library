import React from "react";
import {
  ACLProvider,
  AuthGate,
  AuthProvider,
  PermissionGate,
  RBACProvider,
  SecurityAlert,
  SecurityProvider,
  SanitizedText,
  useAuth,
  useAuthToken,
  useDependencyRiskScanner,
  useHardeningReport,
  useInputSanitizer,
  usePermission,
  useSafeFetcher,
  useSecureHttpClient,
  useSecurityMonitoring,
  useThreatModelGuard,
  withSecurityHeaders
} from "../../../src/adapters/react/index.js";
import { security } from "./security.js";

function Dashboard() {
  const { session, isAuthenticated } = useAuth();
  const accessToken = useAuthToken();
  const permission = usePermission("update", "articles");
  const sanitizer = useInputSanitizer("moderate");
  const threatModel = useThreatModelGuard({
    transitions: { draft: ["review"], review: ["approved"] }
  });
  const hardeningReport = useHardeningReport({
    debug: false,
    cors: { origin: "self" },
    cookies: { secure: true, sameSite: "Strict" }
  });
  const { loading, results, error, runScan } = useDependencyRiskScanner({
    scan: async () => [
      {
        name: "markdown-parser",
        severity: "medium",
        currentVersion: "2.1.0",
        fixedVersion: "2.1.3"
      }
    ]
  });
  const client = useSecureHttpClient({
    baseUrl: "https://api.example.com",
    tokenProvider: async () => security.tokenManager.getAccessToken(),
    fetchImpl: async (url, options) => ({
      ok: true,
      status: 200,
      headers: new Headers(),
      clone: () => ({
        json: async () => ({
          url,
          headers: options.headers,
          items: [{ id: 1, title: "Review policy" }]
        })
      }),
      text: async () => "ok"
    })
  });
  const safeFetcher = useSafeFetcher(
    { allowProtocols: ["https:"] },
    async (url) => ({ ok: true, json: async () => ({ mirroredFrom: url }) })
  );
  const monitoring = useSecurityMonitoring();
  const [requestState, setRequestState] = React.useState(null);

  React.useEffect(() => {
    runScan().catch(() => {});
  }, [runScan]);

  async function loadArticles() {
    const response = await client.request(
      "/articles",
      withSecurityHeaders({ method: "GET", headers: { "X-Feature": "react-demo" } })
    );
    await safeFetcher.fetch("https://cdn.example.com/articles.json");
    monitoring.logger?.info("articles.loaded", {
      userId: session?.userId,
      itemCount: Array.isArray(response.data.items) ? response.data.items.length : 0
    });
    setRequestState(response.data);
  }

  const sanitizedPreview = sanitizer.sanitizeHTML(
    '<p onclick="alert(1)">Allowed <strong>content preview</strong>.</p>'
  );
  const transition = threatModel.validateTransition("draft", "review");

  return (
    <div
      style={{
        maxWidth: 960,
        margin: "0 auto",
        padding: 24,
        fontFamily: '"Segoe UI", sans-serif',
        color: "#0f172a"
      }}
    >
      <h1>OWL React Adapter Demo</h1>
      <p>Signed in: {isAuthenticated ? "yes" : "no"}</p>
      <p>User: {session?.userId}</p>
      <p>Token preview: {accessToken ? `${accessToken.slice(0, 10)}...` : "none"}</p>
      <p>Permission: {permission.allowed ? "can update articles" : permission.reason}</p>
      <p>Threat model: {transition.valid ? "draft can move to review" : transition.reason}</p>
      <p>Hardening findings: {hardeningReport.length}</p>
      <p>Dependency scan: {loading ? "loading" : `${results.length} result(s)`}</p>
      {error ? <SecurityAlert level="error" message={error.message} /> : null}
      <button disabled={!permission.allowed} onClick={loadArticles}>
        Load articles
      </button>
      <div style={{ marginTop: 16 }}>
        <h2>Sanitized preview</h2>
        <div>{sanitizedPreview}</div>
        <SanitizedText profile="strict" html={'<p onclick="alert(1)">Strict preview</p>'} />
      </div>
      <div style={{ marginTop: 16 }}>
        <h2>Latest request</h2>
        <pre>{JSON.stringify(requestState, null, 2)}</pre>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <SecurityProvider logger={security.logger} events={security.events}>
      <AuthProvider authManager={security.authManager}>
        <ACLProvider aclManager={security.aclManager}>
          <RBACProvider rbacManager={security.rbacManager}>
            <AuthGate fallback={<SecurityAlert level="warn" message="Sign in required" />}>
              <PermissionGate
                action="read"
                resource="articles"
                fallback={<SecurityAlert level="error" message="Access denied" />}
              >
                <Dashboard />
              </PermissionGate>
            </AuthGate>
          </RBACProvider>
        </ACLProvider>
      </AuthProvider>
    </SecurityProvider>
  );
}