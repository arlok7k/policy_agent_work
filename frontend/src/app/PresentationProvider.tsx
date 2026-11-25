import { useEffect, useMemo } from 'react';
import type { ReactNode } from 'react';
import type { Presentation } from '../api/types';
import { useGet } from '../api/useGet';
import { useI18n } from '../i18n/context';
import { useAuth } from './auth-context';
import { PresentationContext } from './presentation-context';

const fallback: Presentation = { display_name: 'SMART SOC', default_direction: 'rtl' };
export function PresentationProvider({ children }: { children: ReactNode }) {
  const { state: auth } = useAuth();
  const { applyDefaultDirection } = useI18n();
  const { state, reload } = useGet<Presentation>(auth.status === 'authenticated' ? '/presentation' : null);
  const presentation = state.status === 'ready' ? state.data : fallback;
  useEffect(() => { if (state.status === 'ready') applyDefaultDirection(state.data.default_direction); }, [state, applyDefaultDirection]);
  const value = useMemo(() => ({ presentation, refreshPresentation: reload, unavailable: state.status === 'error' }), [presentation, reload, state.status]);
  return <PresentationContext.Provider value={value}>{children}</PresentationContext.Provider>;
}
