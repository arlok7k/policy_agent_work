import { createContext, useContext } from 'react';
import type { Direction, Language, MessageKey } from './messages';
export interface I18nValue {
  language: Language;
  direction: Direction;
  setLanguage: (language: Language) => void;
  setDirection: (direction: Direction) => void;
  applyDefaultDirection: (direction: Direction) => void;
  t: (key: MessageKey) => string;
}
export const I18nContext = createContext<I18nValue | null>(null);
export function useI18n(): I18nValue {
  const value = useContext(I18nContext);
  if (!value) throw new Error('I18nProvider is missing');
  return value;
}
