import { createContext, useContext } from 'react';
import type { Problem } from '../api/problem';

export interface Principal {
  kind: 'user' | 'service';
  id: string;
  username: string | null;
  roles: string[];
  reauth_at: string | null;
}
export type AuthState =
  | { status: 'loading' }
  | { status: 'anonymous' }
  | { status: 'unavailable'; problem: Problem }
  | { status: 'authenticated'; principal: Principal };
export interface AuthContextValue {
  state: AuthState;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
}
export const AuthContext = createContext<AuthContextValue | null>(null);
export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error('AuthProvider is missing');
  return context;
}
