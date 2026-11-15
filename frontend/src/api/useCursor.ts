import { useState } from 'react';

export function useCursor() {
  const [history, setHistory] = useState<(string | null)[]>([null]);
  const cursor = history[history.length - 1] ?? null;
  return {
    cursor,
    canPrevious: history.length > 1,
    previous: () => setHistory((items) => items.length > 1 ? items.slice(0, -1) : items),
    next: (next: string) => setHistory((items) => [...items, next]),
    reset: () => setHistory([null]),
  };
}
