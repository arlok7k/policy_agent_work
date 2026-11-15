import { useCallback, useEffect, useState } from 'react';
import { api } from './client';
import { mapProblem } from './problem';
import type { Problem } from './problem';

export type Loadable<T> =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'error'; problem: Problem }
  | { status: 'ready'; data: T };

/** Ignore stale responses when navigating, paginating, refreshing or unmounting. */
export function useGet<T>(path: string | null): { state: Loadable<T>; reload: () => void } {
  const [generation, setGeneration] = useState(0);
  const [snapshot, setSnapshot] = useState<{ key: string; state: Loadable<T> } | null>(null);
  const key = `${generation}:${path ?? ''}`;
  useEffect(() => {
    if (!path) return;
    let active = true;
    void api.get<T>(path).then(({ data }) => {
      if (active) setSnapshot({ key, state: { status: 'ready', data } });
    }).catch((error: unknown) => {
      if (active) setSnapshot({ key, state: { status: 'error', problem: mapProblem(error) } });
    });
    return () => { active = false; };
  }, [key, path]);
  const reload = useCallback(() => setGeneration((value) => value + 1), []);
  return { state: !path ? { status: 'idle' } : snapshot?.key === key ? snapshot.state : { status: 'loading' }, reload };
}
