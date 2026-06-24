import React, {
  createContext,
  useState,
  useCallback,
  useEffect,
  ReactNode,
} from 'react';
import { SecurityContextType, SecurityViolation } from '../types';

export const SecurityContext = createContext<SecurityContextType | undefined>(
  undefined
);

export interface SecurityProviderProps {
  children: ReactNode;
  onViolation?: (violation: SecurityViolation) => void;
}

const COOKIE_NAME = '_webshield_csrf';

function readCSRFCookie(): string | null {
  if (typeof document === 'undefined') return null;
  const match = document.cookie
    .split(';')
    .map((c) => c.trim())
    .find((c) => c.startsWith(`${COOKIE_NAME}=`));
  return match ? decodeURIComponent(match.split('=')[1]) : null;
}

function generateToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export const SecurityProvider: React.FC<SecurityProviderProps> = ({
  children,
  onViolation,
}) => {
  const [csrfToken, setCsrfToken] = useState<string | null>(null);

  useEffect(() => {
    let token = readCSRFCookie();
    if (!token) {
      token = generateToken();
      if (typeof document !== 'undefined') {
        document.cookie = `${COOKIE_NAME}=${token}; Path=/; SameSite=Strict`;
      }
    }
    setCsrfToken(token);
  }, []);

  const reportViolation = useCallback(
    (violation: SecurityViolation) => {
      // Avoid leaking sensitive context in production
      console.warn(`[WebShield] Security violation: ${violation.type} - ${violation.message}`);
      onViolation?.(violation);
    },
    [onViolation]
  );

  const value: SecurityContextType = {
    isSecure:
      typeof window !== 'undefined'
        ? window.location.protocol === 'https:'
        : true,
    csrfToken,
    reportViolation,
  };

  return (
    <SecurityContext.Provider value={value}>
      {children}
    </SecurityContext.Provider>
  );
};
