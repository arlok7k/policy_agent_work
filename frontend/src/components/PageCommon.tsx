import { AlertCircle, RefreshCw } from 'lucide-react';
import type { ReactNode } from 'react';
import type { Loadable } from '../api/useGet';
import type { Problem } from '../api/problem';

export function PageHeader({ eyebrow, title, description, action }: {
  eyebrow: string; title: string; description: string; action?: ReactNode;
}) {
  return <div className="page-heading"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1>
    <p className="page-description">{description}</p></div>{action && <div className="page-heading-action">{action}</div>}</div>;
}
export function ProblemNotice({ problem }: { problem: Problem }) {
  return <div className="form-error notice" role="alert"><AlertCircle size={16} aria-hidden="true" />
    <span>{problem.message}{problem.correlationId && <small> Reference: {problem.correlationId}</small>}</span></div>;
}
export function DataState<T>({ state, children, retry }: { state: Loadable<T>; children: (data: T) => ReactNode; retry?: () => void }) {
  if (state.status === 'idle' || state.status === 'loading') return <div className="loading-state" role="status"><span className="spinner" />Loading data…</div>;
  if (state.status === 'error') return <div><ProblemNotice problem={state.problem} />{retry && <button className="button button-quiet mt-3" onClick={retry}><RefreshCw size={14} /> Retry</button>}</div>;
  return <>{children(state.data)}</>;
}
export { Badge, Pagination, Table } from './ui/Primitives';
export function Empty({ children }: { children: ReactNode }) { return <div className="empty-state">{children}</div>; }
