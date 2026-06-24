import React, { ReactNode, useEffect } from 'react';
import { SecurityProvider } from '../../context/SecurityContext';

export interface CSRFProtectionProps {
  children: ReactNode;
  /** Automatically intercept fetch for state-changing requests (default: true) */
  interceptFetch?: boolean;
}

const CSRF_HEADER = 'X-CSRF-Token';
const CSRF_COOKIE = '_webshield_csrf';

function getCsrfCookie(): string | null {
  if (typeof document === 'undefined') return null;
  const match = document.cookie
    .split(';')
    .map((c) => c.trim())
    .find((c) => c.startsWith(`${CSRF_COOKIE}=`));
  return match ? decodeURIComponent(match.split('=')[1]) : null;
}

function installFetchInterceptor(): () => void {
  if (typeof window === 'undefined') return () => {/* noop */};

  const MUTATING = new Set(['POST', 'PUT', 'DELETE', 'PATCH']);
  const originalFetch = window.fetch.bind(window);

  window.fetch = function patchedFetch(input, init = {}) {
    const method = ((init.method ?? 'GET') as string).toUpperCase();
    if (MUTATING.has(method)) {
      const token = getCsrfCookie();
      if (token) {
        const headers = new Headers(init.headers);
        if (!headers.has(CSRF_HEADER)) {
          headers.set(CSRF_HEADER, token);
        }
        init = { ...init, headers };
      }
    }
    return originalFetch(input, init);
  };

  return () => {
    window.fetch = originalFetch;
  };
}

/**
 * Wraps the app in SecurityProvider (which generates/reads the CSRF cookie)
 * and optionally monkey-patches fetch to inject the token header automatically.
 */
export const CSRFProtection: React.FC<CSRFProtectionProps> = ({
  children,
  interceptFetch = true,
}) => {
  useEffect(() => {
    if (!interceptFetch) return;
    const restore = installFetchInterceptor();
    return restore;
  }, [interceptFetch]);

  return <SecurityProvider>{children}</SecurityProvider>;
};
