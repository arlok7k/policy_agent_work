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
export function Badge({ value }: { value: string }) {
  const normalized = value.toLowerCase();
  const tone = ['critical', 'high', 'failed', 'rejected', 'engaged'].includes(normalized) ? 'danger'
    : ['medium', 'pending_approval', 'paused', 'warning'].includes(normalized) ? 'warning'
    : ['low', 'executed', 'open', 'active', 'disengaged', 'resolved'].includes(normalized) ? 'success'
    : 'neutral';
  return <span className={`badge badge-${tone}`}><span className="badge-dot" />{value.replaceAll('_', ' ')}</span>;
}
export function Pagination({ canPrevious, canNext, previous, next, label = 'Pagination' }: {
  canPrevious: boolean; canNext: boolean; previous: () => void; next: () => void; label?: string;
}) {
  return <nav className="pagination" aria-label={label}><button className="button button-quiet" disabled={!canPrevious} onClick={previous}>Previous</button>
    <button className="button button-quiet" disabled={!canNext} onClick={next}>Next</button></nav>;
}
export function Empty({ children }: { children: ReactNode }) { return <div className="empty-state">{children}</div>; }
