import { useCallback, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { api, UNAUTHENTICATED_EVENT } from '../api/client';
import { mapProblem } from '../api/problem';
import { AuthContext } from './auth-context';
import type { AuthState, Principal } from './auth-context';

interface AuthResponse { principal: Principal }

async function getIdentity(): Promise<Principal | null> {
  const { data } = await api.get<AuthResponse>('/auth/me');
  return data.principal.kind === 'user' ? data.principal : null;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({ status: 'loading' });
  const refresh = useCallback(async () => {
    try {
      const principal = await getIdentity();
      setState(principal ? { status: 'authenticated', principal } : { status: 'anonymous' });
    } catch (error) {
      const problem = mapProblem(error);
      setState(problem.status === 401 ? { status: 'anonymous' } : { status: 'unavailable', problem });
    }
  }, []);
  useEffect(() => {
    let active = true;
    const onUnauthenticated = () => { if (active) setState({ status: 'anonymous' }); };
    window.addEventListener(UNAUTHENTICATED_EVENT, onUnauthenticated);
    void getIdentity().then((principal) => {
      if (active) setState(principal ? { status: 'authenticated', principal } : { status: 'anonymous' });
    }).catch((error: unknown) => {
      if (!active) return;
      const problem = mapProblem(error);
      setState(problem.status === 401 ? { status: 'anonymous' } : { status: 'unavailable', problem });
    });
    return () => { active = false; window.removeEventListener(UNAUTHENTICATED_EVENT, onUnauthenticated); };
  }, []);
  const login = useCallback(async (username: string, password: string) => {
    await api.post('/auth/login', { username, password });
    const principal = await getIdentity();
    if (!principal) throw new Error('A user session is required');
    setState({ status: 'authenticated', principal });
  }, []);
  const logout = useCallback(async () => {
    await api.post('/auth/logout');
    setState({ status: 'anonymous' });
  }, []);
  const value = useMemo(() => ({ state, login, logout, refresh }), [state, login, logout, refresh]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
