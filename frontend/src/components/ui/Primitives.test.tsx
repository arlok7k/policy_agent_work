import { fireEvent, render, screen } from '@testing-library/react';
import { useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { Badge, Dialog, FormField, Pagination, Table, ToastProvider } from './Primitives';
import { useToast } from './toast-context';

function ModalExample() {
  const [open, setOpen] = useState(false);
  return <><button onClick={() => setOpen(true)}>Open review</button>
    <Dialog open={open} title="Review action" onClose={() => setOpen(false)}><p>Review consequences.</p><button onClick={() => setOpen(false)}>Done</button></Dialog></>;
}
function ToastExample() {
  const notify = useToast();
  return <button onClick={() => notify('Saved successfully', 'success')}>Save</button>;
}
describe('reusable accessible primitives', () => {
  it('names tables and exposes badge text independent of color', () => {
    render(<Table caption="Security alerts"><thead><tr><th>Severity</th></tr></thead><tbody><tr><td><Badge value="high" /></td></tr></tbody></Table>);
    expect(screen.getByRole('table', { name: 'Security alerts' })).toBeInTheDocument();
    expect(screen.getByText('high')).toBeInTheDocument();
  });
  it('disables unavailable pagination and calls the next action', () => {
    const previous = vi.fn(); const next = vi.fn();
    render(<Pagination label="Alert pages" canPrevious={false} canNext previous={previous} next={next} />);
    expect(screen.getByRole('navigation', { name: 'Alert pages' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Previous' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(next).toHaveBeenCalledOnce(); expect(previous).not.toHaveBeenCalled();
  });
  it('labels native dialogs and closes with Escape while returning focus', () => {
    render(<ModalExample />);
    const trigger = screen.getByRole('button', { name: 'Open review' });
    trigger.focus(); fireEvent.click(trigger);
    const dialog = screen.getByRole('dialog', { name: 'Review action' });
    expect(dialog).toHaveAttribute('open');
    fireEvent(dialog, new Event('cancel', { bubbles: true, cancelable: true }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });
  it('cycles keyboard focus within the modal in both directions', () => {
    const rects = vi.spyOn(HTMLElement.prototype, 'getClientRects').mockReturnValue({ length: 1 } as DOMRectList);
    try {
      render(<ModalExample />);
      fireEvent.click(screen.getByRole('button', { name: 'Open review' }));
      const dialog = screen.getByRole('dialog', { name: 'Review action' });
      const close = screen.getByRole('button', { name: 'Close dialog' });
      const done = screen.getByRole('button', { name: 'Done' });
      done.focus(); fireEvent.keyDown(dialog, { key: 'Tab' });
      expect(close).toHaveFocus();
      fireEvent.keyDown(dialog, { key: 'Tab', shiftKey: true });
      expect(done).toHaveFocus();
    } finally { rects.mockRestore(); }
  });
  it('associates form labels, hints and validation errors with controls', () => {
    render(<FormField id="indicator" label="Indicator" hint="Use an IP address" error="Required">{(field) => <input {...field} />}</FormField>);
    const input = screen.getByRole('textbox', { name: 'Indicator' });
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(input).toHaveAccessibleDescription('Use an IP address Required');
  });
  it('announces and dismisses a toast without hiding the message', () => {
    render(<ToastProvider><ToastExample /></ToastProvider>);
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(screen.getByRole('status')).toHaveTextContent('Saved successfully');
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss notification' }));
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
  });
});
