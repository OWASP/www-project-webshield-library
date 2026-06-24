/**
 * AuthManager - Core authentication manager
 * Handles login, logout, token refresh, and user state management
 */

import { TokenManager } from './TokenManager';
import { EventEmitter } from '../events/EventEmitter';
import {
  AuthConfig,
  AuthToken,
  LoginRequest,
  LoginResponse,
  User,
  StorageAdapter,
} from './types';

/**
 * Default storage adapter using localStorage
 */
const createDefaultStorageAdapter = (): StorageAdapter => {
  if (typeof localStorage === 'undefined') {
    // Fallback for non-browser environments
    const store = new Map<string, string>();
    return {
      getItem: async (key: string) => store.get(key) ?? null,
      setItem: async (key: string, value: string) => { store.set(key, value); },
      removeItem: async (key: string) => { store.delete(key); },
    };
  }

  return {
    getItem: async (key: string) => localStorage.getItem(key),
    setItem: async (key: string, value: string) => localStorage.setItem(key, value),
    removeItem: async (key: string) => localStorage.removeItem(key),
  };
};

export class AuthManager {
  private config: AuthConfig;
  private tokenManager: TokenManager;
  private currentUser: User | null = null;
  private currentToken: AuthToken | null = null;
  private isInitialized = false;
  private refreshInterval: NodeJS.Timeout | null = null;
  private apiClient: any = null;
  public events: EventEmitter;

  constructor(config: AuthConfig) {
    this.config = {
      tokenRefreshThreshold: 5 * 60 * 1000,
      storageAdapter: createDefaultStorageAdapter(),
      ...config,
    };

    this.tokenManager = new TokenManager(this.config.storageAdapter!);
    this.events = new EventEmitter();
  }

  /**
   * Initialize AuthManager - load stored token and user
   */
  async initialize(): Promise<void> {
    if (this.isInitialized) {
      return;
    }

    try {
      const token = await this.tokenManager.getToken();

      if (token && !this.tokenManager.isTokenExpired(token)) {
        this.currentToken = token;
        // Decode user info from token if available
        const decoded = this.tokenManager.decodeToken(token.accessToken);
        if (decoded && decoded.user) {
          this.currentUser = decoded.user;
        }

        // Start automatic token refresh
        this.startTokenRefreshInterval();

        this.events.emit('auth:initialized', { user: this.currentUser });
      }

      this.isInitialized = true;
    } catch (error) {
      console.error('Error initializing auth:', error);
      this.isInitialized = true;
      this.events.emit('auth:error', { error });
    }
  }

  /**
   * Login user with credentials
   */
  async login(credentials: LoginRequest): Promise<void> {
    try {
      // Validate credentials
      if (!credentials.password) {
        throw new Error('Password is required');
      }

      if (!credentials.email && !credentials.username) {
        throw new Error('Email or username is required');
      }

      this.events.emit('auth:login:start');

      // Make login request (requires API implementation)
      const response = await this.makeLoginRequest(credentials);

      // Store token and user
      this.currentToken = response.token;
      this.currentUser = response.user;

      await this.tokenManager.saveToken(response.token);

      // Start token refresh interval
      this.startTokenRefreshInterval();

      this.events.emit('auth:login', { user: this.currentUser, token: this.currentToken });
    } catch (error) {
      this.events.emit('auth:login:error', { error });
      throw error;
    }
  }

  /**
   * Logout user
   */
  async logout(): Promise<void> {
    try {
      this.stopTokenRefreshInterval();
      await this.tokenManager.clearToken();

      this.currentUser = null;
      this.currentToken = null;

      this.events.emit('auth:logout');
    } catch (error) {
      console.error('Error logging out:', error);
      this.events.emit('auth:error', { error });
    }
  }

  /**
   * Refresh authentication token
   */
  async refreshToken(): Promise<void> {
    try {
      if (!this.currentToken || !this.currentToken.refreshToken) {
        throw new Error('No refresh token available');
      }

      this.events.emit('auth:token:refresh:start');

      // Make refresh request (requires API implementation)
      const newToken = await this.makeRefreshRequest(this.currentToken.refreshToken);

      this.currentToken = newToken;
      await this.tokenManager.saveToken(newToken);

      // Notify listeners of refresh
      this.tokenManager.notifyTokenRefresh();

      this.events.emit('auth:token:refreshed', { token: newToken });
      this.config.onTokenRefreshed?.();
    } catch (error) {
      this.events.emit('auth:token:refresh:error', { error });
      throw error;
    }
  }

  /**
   * Get current authenticated user
   */
  getCurrentUser(): User | null {
    return this.currentUser;
  }

  /**
   * Get current authentication token
   */
  getCurrentToken(): AuthToken | null {
    return this.currentToken;
  }

  /**
   * Check if user is authenticated
   */
  isAuthenticated(): boolean {
    return (
      this.currentUser !== null &&
      this.currentToken !== null &&
      !this.tokenManager.isTokenExpired(this.currentToken)
    );
  }

  /**
   * Update user information
   */
  async updateUser(userUpdate: Partial<User>): Promise<void> {
    if (!this.currentUser) {
      throw new Error('No user authenticated');
    }

    this.currentUser = { ...this.currentUser, ...userUpdate };
    this.events.emit('auth:user:updated', { user: this.currentUser });
  }

  /**
   * Start automatic token refresh interval
   */
  private startTokenRefreshInterval(): void {
    if (!this.currentToken) {
      return;
    }

    this.stopTokenRefreshInterval();

    const timeUntilRefresh =
      this.tokenManager.getTimeUntilExpiry(this.currentToken) -
      (this.config.tokenRefreshThreshold || 0);

    if (timeUntilRefresh > 0) {
      this.refreshInterval = setTimeout(() => {
        this.refreshToken().catch((error) => {
          console.error('Auto token refresh failed:', error);
          if (this.config.onTokenExpired) {
            this.config.onTokenExpired();
          }
        });
      }, timeUntilRefresh);
    }
  }

  /**
   * Stop automatic token refresh interval
   */
  private stopTokenRefreshInterval(): void {
    if (this.refreshInterval) {
      clearTimeout(this.refreshInterval);
      this.refreshInterval = null;
    }
  }

  /**
   * Make login API request
   * TODO: Implement actual API call or accept custom implementation
   */
  private async makeLoginRequest(credentials: LoginRequest): Promise<LoginResponse> {
    // This is a placeholder - actual implementation would call an API
    // For testing, return a mock response
    const mockToken: AuthToken = {
      accessToken: 'mock-token-' + Math.random(),
      expiresIn: 3600 * 1000, // 1 hour
      type: 'Bearer',
      issuedAt: Date.now(),
      refreshToken: 'mock-refresh-token',
    };

    const mockUser: User = {
      id: 'user-1',
      email: credentials.email || '',
      username: credentials.username || '',
      roles: [],
      permissions: [],
    };

    return {
      token: mockToken,
      user: mockUser,
    };
  }

  /**
   * Make token refresh API request
   * TODO: Implement actual API call or accept custom implementation
   */
  private async makeRefreshRequest(refreshToken: string): Promise<AuthToken> {
    // This is a placeholder - actual implementation would call an API
    const newToken: AuthToken = {
      accessToken: 'mock-token-' + Math.random(),
      expiresIn: 3600 * 1000, // 1 hour
      type: 'Bearer',
      issuedAt: Date.now(),
      refreshToken: 'mock-refresh-token',
    };

    return newToken;
  }

  /**
   * Destroy auth manager and cleanup
   */
  destroy(): void {
    this.stopTokenRefreshInterval();
    this.events.removeAllListeners();
  }
}
