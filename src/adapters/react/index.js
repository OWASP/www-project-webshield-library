export {
	ACLContext,
	ACLProvider,
	PermissionGate,
	RBACContext,
	RBACProvider,
	useACL,
	usePermission
} from "./a01-access-control/index.js";

export { useCryptoManager } from "./a02-crypto-integrity/index.js";

export { SanitizedText, useInputSanitizer } from "./a03-injection-defense/index.js";

export { useThreatModelGuard } from "./a04-insecure-design-guard/index.js";

export { useHardeningReport } from "./a05-security-misconfiguration/index.js";

export { useDependencyRiskScanner } from "./a06-vulnerable-components/index.js";

export {
	AuthContext,
	AuthGate,
	AuthProvider,
	useAuth,
	useAuthToken
} from "./a07-auth-session/index.js";

export { useSecureHttpClient, withSecurityHeaders } from "./a08-data-integrity/index.js";

export {
	SecurityAlert,
	SecurityContext,
	SecurityProvider,
	useSecurityMonitoring
} from "./a09-logging-monitoring/index.js";

export { useSafeFetcher } from "./a10-ssrf-defense/index.js";

export * as A01AccessControl from "./a01-access-control/index.js";
export * as A02CryptoIntegrity from "./a02-crypto-integrity/index.js";
export * as A03InjectionDefense from "./a03-injection-defense/index.js";
export * as A04InsecureDesignGuard from "./a04-insecure-design-guard/index.js";
export * as A05SecurityMisconfiguration from "./a05-security-misconfiguration/index.js";
export * as A06VulnerableComponents from "./a06-vulnerable-components/index.js";
export * as A07AuthSession from "./a07-auth-session/index.js";
export * as A08DataIntegrity from "./a08-data-integrity/index.js";
export * as A09LoggingMonitoring from "./a09-logging-monitoring/index.js";
export * as A10SSRFDefense from "./a10-ssrf-defense/index.js";