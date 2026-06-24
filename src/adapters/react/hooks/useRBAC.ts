import { useContext } from 'react';
import { RBACContext } from '../context/RBACContext';
import { RBACContextType } from '../types';

export function useRBAC(): RBACContextType {
  const context = useContext(RBACContext);
  if (!context) {
    throw new Error('useRBAC must be used within RBACProvider');
  }
  return context;
}
