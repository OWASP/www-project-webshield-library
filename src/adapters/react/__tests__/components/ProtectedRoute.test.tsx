import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { ProtectedRoute } from '../../components/auth/ProtectedRoute';
import { AuthContext } from '../../context/AuthContext';
import { AuthContextType } from '../../types';

const mockAuthContext = (
  overrides: Partial<AuthContextType> = {}
): AuthContextType => ({
  isAuthenticated: false,
  isLoading: false,
  user: null,
  token: null,
  error: null,
  login: jest.fn(),
  logout: jest.fn(),
  refreshToken: jest.fn(),
  register: jest.fn(),
  updateUser: jest.fn(),
  ...overrides,
});

const wrap = (ctx: AuthContextType, ui: React.ReactElement) => (
  <AuthContext.Provider value={ctx}>{ui}</AuthContext.Provider>
);

describe('ProtectedRoute', () => {
  it('shows loading state', () => {
    render(
      wrap(
        mockAuthContext({ isLoading: true }),
        <ProtectedRoute>
          <div>Protected</div>
        </ProtectedRoute>
      )
    );
    expect(screen.getByText('Loading...')).toBeInTheDocument();
    expect(screen.queryByText('Protected')).not.toBeInTheDocument();
  });

  it('shows fallback when not authenticated', () => {
    render(
      wrap(
        mockAuthContext(),
        <ProtectedRoute fallback={<div>Login required</div>}>
          <div>Protected</div>
        </ProtectedRoute>
      )
    );
    expect(screen.getByText('Login required')).toBeInTheDocument();
    expect(screen.queryByText('Protected')).not.toBeInTheDocument();
  });

  it('renders children when authenticated', () => {
    const user = {
      id: '1',
      email: 'user@example.com',
      roles: [],
      permissions: [],
    };
    render(
      wrap(
        mockAuthContext({ isAuthenticated: true, user }),
        <ProtectedRoute>
          <div>Protected Content</div>
        </ProtectedRoute>
      )
    );
    expect(screen.getByText('Protected Content')).toBeInTheDocument();
  });

  it('blocks access when required role is missing', () => {
    const user = {
      id: '1',
      email: 'user@example.com',
      roles: [{ id: 'r1', name: 'viewer', permissions: [] }],
      permissions: [],
    };
    render(
      wrap(
        mockAuthContext({ isAuthenticated: true, user }),
        <ProtectedRoute
          requiredRoles={['admin']}
          fallback={<div>Forbidden</div>}
        >
          <div>Admin Area</div>
        </ProtectedRoute>
      )
    );
    expect(screen.getByText('Forbidden')).toBeInTheDocument();
    expect(screen.queryByText('Admin Area')).not.toBeInTheDocument();
  });

  it('allows access when required role is present', () => {
    const user = {
      id: '1',
      email: 'admin@example.com',
      roles: [{ id: 'r1', name: 'admin', permissions: [] }],
      permissions: [],
    };
    render(
      wrap(
        mockAuthContext({ isAuthenticated: true, user }),
        <ProtectedRoute requiredRoles={['admin']}>
          <div>Admin Area</div>
        </ProtectedRoute>
      )
    );
    expect(screen.getByText('Admin Area')).toBeInTheDocument();
  });

  it('blocks access when required permission is missing', () => {
    const user = {
      id: '1',
      email: 'user@example.com',
      roles: [],
      permissions: ['read'],
    };
    render(
      wrap(
        mockAuthContext({ isAuthenticated: true, user }),
        <ProtectedRoute
          requiredPermissions={['write']}
          fallback={<div>No Permission</div>}
        >
          <div>Write Area</div>
        </ProtectedRoute>
      )
    );
    expect(screen.getByText('No Permission')).toBeInTheDocument();
  });

  it('calls onUnauthorized when unauthenticated', () => {
    const onUnauthorized = jest.fn();
    render(
      wrap(
        mockAuthContext(),
        <ProtectedRoute onUnauthorized={onUnauthorized}>
          <div>Protected</div>
        </ProtectedRoute>
      )
    );
    expect(onUnauthorized).toHaveBeenCalled();
  });
});
