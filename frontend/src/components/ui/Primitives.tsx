import { X } from 'lucide-react';
import { useEffect, useId, useRef, useState } from 'react';
import type { KeyboardEvent, ReactNode } from 'react';
import { ToastContext } from './toast-context';
import type { ToastKind } from './toast-context';

export function Table({ caption, children }: { caption: string; children: ReactNode }) {
  return <div className="table-wrap"><table><caption className="sr-only">{caption}</caption>{children}</table></div>;
}
export function Badge({ value }: { value: string }) {
  const normalized = value.toLowerCase();
  const tone = ['critical', 'high', 'failed', 'rejected', 'engaged'].includes(normalized) ? 'danger'
    : ['medium', 'pending_approval', 'paused', 'warning'].includes(normalized) ? 'warning'
    : ['low', 'executed', 'open', 'active', 'disengaged', 'resolved'].includes(normalized) ? 'success'
    : 'neutral';
  return <span className={`badge badge-${tone}`}><span className="badge-dot" aria-hidden="true" />{value.replaceAll('_', ' ')}</span>;
}
export function Pagination({ canPrevious, canNext, previous, next, label = 'Pagination' }: {
  canPrevious: boolean; canNext: boolean; previous: () => void; next: () => void; label?: string;
}) {
  return <nav className="pagination" aria-label={label}><button type="button" className="button button-quiet" disabled={!canPrevious} onClick={previous}>Previous</button>
    <button type="button" className="button button-quiet" disabled={!canNext} onClick={next}>Next</button></nav>;
}

/** Native modal dialog plus cyclic keyboard focus; the trigger regains focus on close. */
export function Dialog({ open, title, onClose, children }: {
  open: boolean; title: string; onClose: () => void; children: ReactNode;
}) {
  const element = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  useEffect(() => {
    const dialog = element.current;
    if (!open || !dialog) return;
    const previous = document.activeElement;
    dialog.showModal();
    return () => {
      if (dialog.open) dialog.close();
      if (previous instanceof HTMLElement && previous.isConnected) previous.focus();
    };
  }, [open]);
  function containFocus(event: KeyboardEvent<HTMLDialogElement>) {
    if (event.key !== 'Tab') return;
    const dialog = event.currentTarget;
    const elements = [...dialog.querySelectorAll<HTMLElement>('a[href], button, input, select, textarea, [tabindex], [contenteditable="true"]')]
      .filter((item) => (item.tabIndex >= 0 || (item.isContentEditable && !item.hasAttribute('tabindex')))
        && !item.matches(':disabled') && !item.closest('[hidden], [inert]') && item.getClientRects().length > 0);
    const first = elements[0];
    const last = elements.at(-1);
    if (!first || !last) { event.preventDefault(); return; }
    const current = document.activeElement;
    if (event.shiftKey && (current === first || !dialog.contains(current))) {
      event.preventDefault(); last.focus();
    } else if (!event.shiftKey && (current === last || !dialog.contains(current))) {
      event.preventDefault(); first.focus();
    }
  }
  return <dialog ref={element} className="dialog" aria-labelledby={titleId} onKeyDown={containFocus} onCancel={(event) => { event.preventDefault(); onClose(); }}>
    <div className="dialog-heading"><h2 id={titleId}>{title}</h2><button className="icon-button" type="button" aria-label="Close dialog" onClick={onClose}><X size={18} /></button></div>
    <div className="dialog-content">{children}</div>
  </dialog>;
}

interface FieldAttributes { id: string; 'aria-describedby': string | undefined; 'aria-invalid': true | undefined }
export function FormField({ id, label, hint, error, children }: {
  id: string; label: string; hint?: string; error?: string; children: (props: FieldAttributes) => ReactNode;
}) {
  const hintId = hint ? `${id}-hint` : undefined;
  const errorId = error ? `${id}-error` : undefined;
  const describedBy = [hintId, errorId].filter(Boolean).join(' ') || undefined;
  return <div className="form-field"><label htmlFor={id}>{label}</label>{children({ id, 'aria-describedby': describedBy, 'aria-invalid': error ? true : undefined })}
    {hint && <small className="form-hint" id={hintId}>{hint}</small>}{error && <small className="field-error" id={errorId}>{error}</small>}</div>;
}

interface ToastMessage { id: number; kind: ToastKind; message: string }
export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const nextId = useRef(0);
  function notify(message: string, kind: ToastKind = 'info') {
    const id = ++nextId.current;
    setToasts((items) => [...items, { id, message, kind }]);
  }
  return <ToastContext.Provider value={notify}>{children}<div className="toast-stack" aria-label="Notifications">
    {toasts.map((toast) => <div key={toast.id} className={`toast toast-${toast.kind}`} role={toast.kind === 'error' ? 'alert' : 'status'}>
      <span>{toast.message}</span><button type="button" className="icon-button" aria-label="Dismiss notification" onClick={() => setToasts((items) => items.filter((item) => item.id !== toast.id))}><X size={15} /></button>
    </div>)}
  </div></ToastContext.Provider>;
}
