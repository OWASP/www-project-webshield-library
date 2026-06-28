import React from "react";

export const AuthContext = React.createContext(null);

export function AuthProvider({ authManager, children }) {
	const [session, setSession] = React.useState(authManager?.getSession() || null);

	React.useEffect(() => {
		if (!authManager) return undefined;
		return authManager.events.on("auth:changed", setSession);
	}, [authManager]);

	const value = React.useMemo(
		() => ({
			authManager,
			session,
			isAuthenticated: Boolean(authManager?.isAuthenticated())
		}),
		[authManager, session]
	);

	return React.createElement(AuthContext.Provider, { value }, children);
}

export function useAuth() {
	const context = React.useContext(AuthContext);
	if (!context) {
		throw new Error("useAuth must be used within AuthProvider");
	}
	return context;
}

export function useAuthToken() {
	const { authManager } = useAuth();
	const [token, setToken] = React.useState(authManager?.tokenManager.getAccessToken() || null);

	React.useEffect(() => {
		if (!authManager) return undefined;
		return authManager.tokenManager.events.on("token:changed", () => {
			setToken(authManager.tokenManager.getAccessToken());
		});
	}, [authManager]);

	return token;
}

export function AuthGate({ fallback = null, children }) {
	const { isAuthenticated } = useAuth();
	return isAuthenticated ? React.createElement(React.Fragment, null, children) : fallback;
}