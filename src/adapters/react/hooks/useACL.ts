import { useContext } from 'react';
import { ACLContext } from '../context/ACLContext';
import { ACLContextType } from '../types';

export function useACL(): ACLContextType {
  const context = useContext(ACLContext);
  if (!context) {
    throw new Error('useACL must be used within ACLProvider');
  }
  return context;
}
