import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { I18nContext } from './context';
import { messages } from './messages';
import type { Direction, Language, MessageKey } from './messages';

function preference<T extends string>(key: string, allowed: readonly T[], fallback: T): T {
  try {
    const value = localStorage.getItem(key);
    return allowed.find((candidate) => candidate === value) ?? fallback;
  } catch { return fallback; }
}
export function I18nProvider({ children }: { children: ReactNode }) {
  const [language, setLanguage] = useState<Language>(() => preference('soc.language', ['en', 'ar'], 'en'));
  const [direction, setDirectionState] = useState<Direction>(() => preference('soc.direction', ['ltr', 'rtl'], 'rtl'));
  const hasUserDirection = useRef(preference('soc.direction', ['ltr', 'rtl', 'none'], 'none') !== 'none');
  const setDirection = useCallback((next: Direction) => {
    hasUserDirection.current = true;
    setDirectionState(next);
    try { localStorage.setItem('soc.direction', next); } catch { /* Preferences are optional. */ }
  }, []);
  const applyDefaultDirection = useCallback((next: Direction) => {
    if (!hasUserDirection.current) setDirectionState(next);
  }, []);
  useEffect(() => {
    document.documentElement.lang = language;
    document.documentElement.dir = direction;
    try { localStorage.setItem('soc.language', language); }
    catch { /* A disabled preference store must not block the application. */ }
  }, [language, direction]);
  const value = useMemo(() => ({ language, direction, setLanguage, setDirection, applyDefaultDirection,
    t: (key: MessageKey) => messages[language][key],
  }), [language, direction, setDirection, applyDefaultDirection]);
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}
