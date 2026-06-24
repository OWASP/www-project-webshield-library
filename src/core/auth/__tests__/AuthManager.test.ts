/**
 * AuthManager Tests
 */

import { AuthManager } from '../AuthManager';
import { AuthConfig, StorageAdapter, LoginRequest } from '../types';

describe('AuthManager', () => {
  let authManager: AuthManager;
  let mockStorage: StorageAdapter;
  let store: Map<string, string>;

  beforeEach(() => {
    store = new Map();
    mockStorage = {
      getItem: async (key: string) => store.get(key) ?? null,
      setItem: async (key: string, value: string) => store.set(key, value),
      removeItem: async (key: string) => store.delete(key),
    };

    const config: AuthConfig = {
      apiBaseUrl: 'http://localhost:3000',
      storageAdapter: mockStorage,
    };

    authManager = new AuthManager(config);
  });

  afterEach(() => {
    authManager.destroy();
  });

  describe('Initialization', () => {
    it('should initialize without errors', async () => {
      await expect(authManager.initialize()).resolves.not.toThrow();
    });

    it('should not initialize twice', async () => {
      await authManager.initialize();
      await authManager.initialize(); // Should return early without error

      expect(authManager.getCurrentUser()).toBeNull();
    });
  });

  describe('Authentication State', () => {
    it('should not be authenticated initially', async () => {
      await authManager.initialize();
      expect(authManager.isAuthenticated()).toBe(false);
    });

    it('should have null user initially', async () => {
      await authManager.initialize();
      expect(authManager.getCurrentUser()).toBeNull();
    });

    it('should have null token initially', async () => {
      await authManager.initialize();
      expect(authManager.getCurrentToken()).toBeNull();
    });
  });

  describe('Login', () => {
    it('should login with email and password', async () => {
      const credentials: LoginRequest = {
        email: 'test@example.com',
        password: 'password123',
      };

      const loginSpy = jest.fn();
      authManager.events.on('auth:login', loginSpy);

      await authManager.login(credentials);

      expect(loginSpy).toHaveBeenCalled();
      expect(authManager.isAuthenticated()).toBe(true);
      expect(authManager.getCurrentUser()).not.toBeNull();
      expect(authManager.getCurrentToken()).not.toBeNull();
    });

    it('should login with username and password', async () => {
      const credentials: LoginRequest = {
        username: 'testuser',
        password: 'password123',
      };

      await authManager.login(credentials);

      expect(authManager.isAuthenticated()).toBe(true);
    });

    it('should emit login:start event', async () => {
      const startSpy = jest.fn();
      authManager.events.on('auth:login:start', startSpy);

      await authManager.login({
        email: 'test@example.com',
        password: 'password123',
      });

      expect(startSpy).toHaveBeenCalled();
    });

    it('should reject login without password', async () => {
      const credentials: any = {
        email: 'test@example.com',
      };

      await expect(authManager.login(credentials)).rejects.toThrow('Password is required');
    });

    it('should reject login without email or username', async () => {
      const credentials: any = {
        password: 'password123',
      };

      await expect(authManager.login(credentials)).rejects.toThrow(
        'Email or username is required'
      );
    });

    it('should emit login:error on failure', async () => {
      const errorSpy = jest.fn();
      authManager.events.on('auth:login:error', errorSpy);

      try {
        await authManager.login({ password: '' } as any);
      } catch {
        // Expected
      }

      expect(errorSpy).toHaveBeenCalled();
    });
  });

  describe('Logout', () => {
    it('should logout user', async () => {
      await authManager.login({
        email: 'test@example.com',
        password: 'password123',
      });

      const logoutSpy = jest.fn();
      authManager.events.on('auth:logout', logoutSpy);

      await authManager.logout();

      expect(logoutSpy).toHaveBeenCalled();
      expect(authManager.isAuthenticated()).toBe(false);
      expect(authManager.getCurrentUser()).toBeNull();
      expect(authManager.getCurrentToken()).toBeNull();
    });

    it('should clear stored token on logout', async () => {
      await authManager.login({
        email: 'test@example.com',
        password: 'password123',
      });

      await authManager.logout();

      const storedToken = await mockStorage.getItem('@owasp/auth_token');
      expect(storedToken).toBeNull();
    });
  });

  describe('User Management', () => {
    it('should update user information', async () => {
      await authManager.login({
        email: 'test@example.com',
        password: 'password123',
      });

      const updateSpy = jest.fn();
      authManager.events.on('auth:user:updated', updateSpy);

      await authManager.updateUser({
        username: 'newusername',
      });

      expect(updateSpy).toHaveBeenCalled();
      expect(authManager.getCurrentUser()?.username).toBe('newusername');
    });

    it('should reject update without authentication', async () => {
      await expect(authManager.updateUser({ username: 'test' })).rejects.toThrow(
        'No user authenticated'
      );
    });
  });

  describe('Event Emitter', () => {
    it('should have event emitter', () => {
      expect(authManager.events).toBeDefined();
      expect(authManager.events.on).toBeDefined();
      expect(authManager.events.emit).toBeDefined();
    });

    it('should emit initialization event', async () => {
      const spy = jest.fn();
      authManager.events.on('auth:initialized', spy);

      await authManager.initialize();

      expect(spy).toHaveBeenCalled();
    });
  });

  describe('Token Refresh', () => {
    it('should have refresh token capability', async () => {
      await authManager.login({
        email: 'test@example.com',
        password: 'password123',
      });

      const token = authManager.getCurrentToken();
      expect(token?.refreshToken).toBeDefined();
    });
  });
});
