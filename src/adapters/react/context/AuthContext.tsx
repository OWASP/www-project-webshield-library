import React, {
  createContext,
  useState,
  useCallback,
  useEffect,
  ReactNode,
} from 'react';
import {
  AuthState,
  AuthContextType,
  LoginCredentials,
  RegisterData,
  User,
  AuthToken,
} from '../types';

const createDefaultStorageAdapter = () => {
  if (typeof sessionStorage === 'undefined') {
    const store = new Map<string, string>();
    return {
      getItem: (key: string) => store.get(key) ?? null,
      setItem: (key: string, value: string) => store.set(key, value),
      removeItem: (key: string) => store.delete(key),
    };
  }
  return {
    getItem: (key: string) => sessionStorage.getItem(key),
    setItem: (key: string, value: string) => sessionStorage.setItem(key, value),
    removeItem: (key: string) => sessionStorage.removeItem(key),
  };
};

const STORAGE_KEY = 'webshield_auth_token';

function saveToken(token: AuthToken): void {
  const adapter = createDefaultStorageAdapter();
  adapter.setItem(STORAGE_KEY, JSON.stringify(token));
}

function loadToken(): AuthToken | null {
  try {
    const adapter = createDefaultStorageAdapter();
    const raw = adapter.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as AuthToken) : null;
  } catch {
    return null;
  }
}

function clearToken(): void {
  const adapter = createDefaultStorageAdapter();
  adapter.removeItem(STORAGE_KEY);
}

function isTokenExpired(token: AuthToken): boolean {
  return Date.now() >= token.issuedAt + token.expiresIn;
}

export const AuthContext = createContext<AuthContextType | undefined>(undefined);

export interface AuthProviderProps {
  children: ReactNode;
  apiBaseUrl: string;
  onAuthError?: (error: Error) => void;
  tokenRefreshInterval?: number;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({
  children,
  apiBaseUrl,
  onAuthError,
  tokenRefreshInterval = 5 * 60 * 1000,
}) => {
  const [authState, setAuthState] = useState<AuthState>({
    isAuthenticated: false,
    isLoading: true,
    user: null,
    token: null,
    error: null,
  });

  const fetchCurrentUser = useCallback(
    async (token: AuthToken): Promise<void> => {
      const response = await fetch(`${apiBaseUrl}/auth/me`, {
        headers: {
          Authorization: `${token.type} ${token.accessToken}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch user: ${response.statusText}`);
      }

      const user: User = await response.json();
      setAuthState((prev) => ({
        ...prev,
        user,
        isAuthenticated: true,
        isLoading: false,
        error: null,
      }));
    },
    [apiBaseUrl]
  );

  useEffect(() => {
    const init = async () => {
      try {
        const stored = loadToken();
        if (stored && !isTokenExpired(stored)) {
          setAuthState((prev) => ({ ...prev, token: stored }));
          await fetchCurrentUser(stored);
        } else {
          clearToken();
          setAuthState((prev) => ({ ...prev, isLoading: false }));
        }
      } catch (err) {
        const error = err instanceof Error ? err : new Error('Auth init failed');
        clearToken();
        setAuthState((prev) => ({ ...prev, isLoading: false, error }));
        onAuthError?.(error);
      }
    };
    init();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Periodic token refresh check
  useEffect(() => {
    if (!authState.token || !authState.isAuthenticated) return;
    const interval = setInterval(async () => {
      const token = loadToken();
      if (!token) return;
      const timeLeft = token.issuedAt + token.expiresIn - Date.now();
      if (timeLeft < 5 * 60 * 1000 && token.refreshToken) {
        try {
          const res = await fetch(`${apiBaseUrl}/auth/refresh`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ refreshToken: token.refreshToken }),
          });
          if (res.ok) {
            const newToken: AuthToken = await res.json();
            saveToken(newToken);
            setAuthState((prev) => ({
              ...prev,
              token: newToken,
              lastRefresh: new Date(),
            }));
          }
        } catch {
          // silently skip; main refresh will handle it
        }
      }
    }, tokenRefreshInterval);
    return () => clearInterval(interval);
  }, [apiBaseUrl, authState.token, authState.isAuthenticated, tokenRefreshInterval]);

  const login = useCallback(
    async (credentials: LoginCredentials): Promise<void> => {
      setAuthState((prev) => ({ ...prev, isLoading: true, error: null }));
      try {
        const response = await fetch(`${apiBaseUrl}/auth/login`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
          },
          credentials: 'include',
          body: JSON.stringify(credentials),
        });

        if (!response.ok) {
          throw new Error(`Login failed: ${response.statusText}`);
        }

        const data: { token: AuthToken; user: User } = await response.json();
        saveToken(data.token);
        setAuthState({
          token: data.token,
          user: data.user,
          isAuthenticated: true,
          isLoading: false,
          error: null,
          lastRefresh: new Date(),
        });
      } catch (err) {
        const error = err instanceof Error ? err : new Error('Login failed');
        setAuthState((prev) => ({ ...prev, isLoading: false, error }));
        onAuthError?.(error);
        throw error;
      }
    },
    [apiBaseUrl, onAuthError]
  );

  const logout = useCallback(async (): Promise<void> => {
    try {
      const token = loadToken();
      if (token) {
        await fetch(`${apiBaseUrl}/auth/logout`, {
          method: 'POST',
          headers: {
            Authorization: `${token.type} ${token.accessToken}`,
            'Content-Type': 'application/json',
          },
          credentials: 'include',
        }).catch(() => {/* ignore logout endpoint errors */});
      }
    } finally {
      clearToken();
      setAuthState({
        isAuthenticated: false,
        isLoading: false,
        user: null,
        token: null,
        error: null,
      });
    }
  }, [apiBaseUrl]);

  const refreshToken = useCallback(async (): Promise<void> => {
    const token = loadToken();
    if (!token?.refreshToken) {
      throw new Error('No refresh token available');
    }

    const response = await fetch(`${apiBaseUrl}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ refreshToken: token.refreshToken }),
    });

    if (!response.ok) {
      await logout();
      throw new Error('Token refresh failed');
    }

    const newToken: AuthToken = await response.json();
    saveToken(newToken);
    setAuthState((prev) => ({ ...prev, token: newToken, lastRefresh: new Date() }));
  }, [apiBaseUrl, logout]);

  const register = useCallback(
    async (data: RegisterData): Promise<void> => {
      const response = await fetch(`${apiBaseUrl}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      if (!response.ok) {
        throw new Error(`Registration failed: ${response.statusText}`);
      }
    },
    [apiBaseUrl]
  );

  const updateUser = useCallback(
    async (updates: Partial<User>): Promise<void> => {
      const token = loadToken();
      if (!token) throw new Error('Not authenticated');

      const response = await fetch(`${apiBaseUrl}/auth/me`, {
        method: 'PATCH',
        headers: {
          Authorization: `${token.type} ${token.accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(updates),
      });

      if (!response.ok) {
        throw new Error(`Update failed: ${response.statusText}`);
      }

      const updatedUser: User = await response.json();
      setAuthState((prev) => ({ ...prev, user: updatedUser }));
    },
    [apiBaseUrl]
  );

  const value: AuthContextType = {
    ...authState,
    login,
    logout,
    refreshToken,
    register,
    updateUser,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};
