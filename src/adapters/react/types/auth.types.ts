export interface User {
  id: string;
  email: string;
  username?: string;
  roles: Role[];
  permissions: string[];
  lastLogin?: Date;
  loginAttempts?: number;
}

export interface Role {
  id: string;
  name: string;
  permissions: string[];
  hierarchy?: number;
}

export interface AuthToken {
  accessToken: string;
  refreshToken?: string;
  expiresIn: number;
  issuedAt: number;
  type: 'Bearer' | 'Basic' | 'Custom';
}

export interface AuthState {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: User | null;
  token: AuthToken | null;
  error: Error | null;
  lastRefresh?: Date;
}

export interface LoginCredentials {
  email?: string;
  username?: string;
  password: string;
}

export interface RegisterData {
  email: string;
  username: string;
  password: string;
  confirmPassword: string;
}

export interface AuthContextType extends AuthState {
  login(credentials: LoginCredentials): Promise<void>;
  logout(): Promise<void>;
  refreshToken(): Promise<void>;
  register(data: RegisterData): Promise<void>;
  updateUser(user: Partial<User>): Promise<void>;
}

export interface AuthProviderProps {
  children: React.ReactNode;
  apiBaseUrl: string;
  onAuthError?: (error: Error) => void;
  tokenRefreshInterval?: number;
}
