import { useAuth } from './useAuth';
import { AuthToken } from '../types';

export interface UseAuthTokenResult {
  token: AuthToken | null;
  isExpired: boolean;
  needsRefresh: boolean;
  refresh(): Promise<void>;
}

export function useAuthToken(): UseAuthTokenResult {
  const { token, refreshToken } = useAuth();

  const now = Date.now();
  const isExpired = token ? now >= token.issuedAt + token.expiresIn : false;
  const needsRefresh = token
    ? !isExpired && token.issuedAt + token.expiresIn - now < 5 * 60 * 1000
    : false;

  return { token, isExpired, needsRefresh, refresh: refreshToken };
}
