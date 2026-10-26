"use client";

// The React adapter, marked as a client module so App Router Server Components
// can render its providers and gates. Named exports only: Next.js rejects
// `export *` in a "use client" module, so the A01–A10 namespaces aren't here;
// import them from @owasp-webshield/react inside your own client components.
export {
  ACLContext,
  ACLProvider,
  AuthContext,
  AuthGate,
  AuthProvider,
  OwlProvider,
  PermissionGate,
  RBACContext,
  RBACProvider,
  SanitizedText,
  SecurityAlert,
  SecurityContext,
  SecurityProvider,
  useACL,
  useAuth,
  useAuthToken,
  useCryptoManager,
  useDependencyRiskScanner,
  useHardeningReport,
  useInputSanitizer,
  usePermission,
  useSafeFetcher,
  useSecureHttpClient,
  useSecurityMonitoring,
  useThreatModelGuard,
  withSecurityHeaders
} from "@owasp-webshield/react";
