import React from "react";

export const AuthContext = React.createContext(null);

export function AuthProvider({ authManager, children }) {
	const [session, setSession] = React.useState(authManager?.getSession() || null);
	const [accessToken, setAccessToken] = React.useState(authManager?.tokenManager.getAccessToken() || null);

	React.useEffect(() => {
		setSession(authManager?.getSession() || null);
		setAccessToken(authManager?.tokenManager.getAccessToken() || null);

		if (!authManager) return undefined;

		let expiryTimer = null;

		const syncAuthState = () => {
			setSession(authManager.getSession());
			setAccessToken(authManager.tokenManager.getAccessToken());
		};

		const scheduleExpiry = () => {
			if (expiryTimer) {
				clearTimeout(expiryTimer);
				expiryTimer = null;
			}

			const tokens = authManager.tokenManager.getTokens();
			if (!tokens?.expiresAt) return;

			const msUntilExpiry = tokens.expiresAt - Date.now();
			if (msUntilExpiry <= 0) {
				syncAuthState();
				return;
			}

			expiryTimer = setTimeout(syncAuthState, msUntilExpiry);
		};

		const handleTokenChange = () => {
			syncAuthState();
			scheduleExpiry();
		};

		scheduleExpiry();

		const unsubscribeAuth = authManager.events.on("auth:changed", syncAuthState);
		const unsubscribeChanged = authManager.tokenManager.events.on("token:changed", handleTokenChange);
		const unsubscribeCleared = authManager.tokenManager.events.on("token:cleared", handleTokenChange);
		const unsubscribeRotated = authManager.tokenManager.events.on("token:rotated", handleTokenChange);

		return () => {
			unsubscribeAuth();
			unsubscribeChanged();
			unsubscribeCleared();
			unsubscribeRotated();
			if (expiryTimer) {
				clearTimeout(expiryTimer);
			}
		};
	}, [authManager]);

	const value = React.useMemo(
		() => ({
			authManager,
			session,
			isAuthenticated: Boolean(session && accessToken)
		}),
		[authManager, session, accessToken]
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
		setToken(authManager?.tokenManager.getAccessToken() || null);

		if (!authManager) return undefined;

		const syncToken = () => {
			setToken(authManager.tokenManager.getAccessToken());
		};

		const unsubscribeChanged = authManager.tokenManager.events.on("token:changed", syncToken);
		const unsubscribeCleared = authManager.tokenManager.events.on("token:cleared", syncToken);

		return () => {
			unsubscribeChanged();
			unsubscribeCleared();
		};
	}, [authManager]);

	return token;
}

export function AuthGate({ fallback = null, children }) {
	const { isAuthenticated } = useAuth();
	return isAuthenticated ? React.createElement(React.Fragment, null, children) : fallback;
}