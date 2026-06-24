import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { WithRBAC } from '../../components/access-control/WithRBAC';
import { WithACL } from '../../components/access-control/WithACL';
import { RBACContext } from '../../context/RBACContext';
import { ACLContext } from '../../context/ACLContext';
import { RBACContextType, ACLContextType } from '../../types';

const mockRBAC = (overrides: Partial<RBACContextType> = {}): RBACContextType => ({
  currentRoles: [],
  hasRole: jest.fn().mockReturnValue(false),
  hasPermission: jest.fn().mockReturnValue(false),
  hasAllPermissions: jest.fn().mockReturnValue(false),
  hasAnyPermission: jest.fn().mockReturnValue(false),
  ...overrides,
});

const mockACL = (overrides: Partial<ACLContextType> = {}): ACLContextType => ({
  checkPermission: jest.fn().mockReturnValue(false),
  hasAccess: jest.fn().mockReturnValue(false),
  canModify: jest.fn().mockReturnValue(false),
  canDelete: jest.fn().mockReturnValue(false),
  canShare: jest.fn().mockReturnValue(false),
  grantPermission: jest.fn(),
  revokePermission: jest.fn(),
  getResourcePermissions: jest.fn().mockReturnValue([]),
  ...overrides,
});

describe('WithRBAC', () => {
  it('renders children when role is satisfied', () => {
    render(
      <RBACContext.Provider
        value={mockRBAC({ hasRole: jest.fn().mockReturnValue(true) })}
      >
        <WithRBAC roles="admin">
          <div>Admin Content</div>
        </WithRBAC>
      </RBACContext.Provider>
    );
    expect(screen.getByText('Admin Content')).toBeInTheDocument();
  });

  it('renders fallback when role is not satisfied', () => {
    render(
      <RBACContext.Provider value={mockRBAC()}>
        <WithRBAC roles="admin" fallback={<div>No Access</div>}>
          <div>Admin Content</div>
        </WithRBAC>
      </RBACContext.Provider>
    );
    expect(screen.getByText('No Access')).toBeInTheDocument();
    expect(screen.queryByText('Admin Content')).not.toBeInTheDocument();
  });

  it('calls onDenied when access is denied', () => {
    const onDenied = jest.fn();
    render(
      <RBACContext.Provider value={mockRBAC()}>
        <WithRBAC roles="admin" onDenied={onDenied}>
          <div>Content</div>
        </WithRBAC>
      </RBACContext.Provider>
    );
    expect(onDenied).toHaveBeenCalled();
  });

  it('renders children with no constraints', () => {
    render(
      <RBACContext.Provider value={mockRBAC()}>
        <WithRBAC>
          <div>Public Content</div>
        </WithRBAC>
      </RBACContext.Provider>
    );
    expect(screen.getByText('Public Content')).toBeInTheDocument();
  });
});

describe('WithACL', () => {
  it('renders children when permission is satisfied', () => {
    render(
      <ACLContext.Provider
        value={mockACL({ checkPermission: jest.fn().mockReturnValue(true) })}
      >
        <WithACL resource="doc-1" permission="read">
          <div>Doc Content</div>
        </WithACL>
      </ACLContext.Provider>
    );
    expect(screen.getByText('Doc Content')).toBeInTheDocument();
  });

  it('renders fallback when permission is denied', () => {
    render(
      <ACLContext.Provider value={mockACL()}>
        <WithACL resource="doc-1" permission="write" fallback={<div>Denied</div>}>
          <div>Write Content</div>
        </WithACL>
      </ACLContext.Provider>
    );
    expect(screen.getByText('Denied')).toBeInTheDocument();
    expect(screen.queryByText('Write Content')).not.toBeInTheDocument();
  });

  it('calls onDenied when permission is denied', () => {
    const onDenied = jest.fn();
    render(
      <ACLContext.Provider value={mockACL()}>
        <WithACL resource="doc-1" permission="delete" onDenied={onDenied}>
          <div>Content</div>
        </WithACL>
      </ACLContext.Provider>
    );
    expect(onDenied).toHaveBeenCalled();
  });
});
