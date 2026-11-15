import { createContext, useContext } from 'react';
import type { Presentation } from '../api/types';
export interface PresentationContextValue { presentation: Presentation; refreshPresentation: () => void; unavailable: boolean }
export const PresentationContext = createContext<PresentationContextValue | null>(null);
export function usePresentation(): PresentationContextValue {
  const value = useContext(PresentationContext);
  if (!value) throw new Error('PresentationProvider is missing');
  return value;
}
