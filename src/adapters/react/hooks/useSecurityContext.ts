import { useContext } from 'react';
import { SecurityContext } from '../context/SecurityContext';
import { SecurityContextType } from '../types';

export function useSecurityContext(): SecurityContextType {
  const context = useContext(SecurityContext);
  if (!context) {
    throw new Error('useSecurityContext must be used within SecurityProvider');
  }
  return context;
}
