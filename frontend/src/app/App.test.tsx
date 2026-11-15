import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api, UNAUTHENTICATED_EVENT } from '../api/client';
import { Redacted } from '../test/Redacted';
import { App } from './App';

vi.mock('../api/client', () => ({
  api: { get: vi.fn(), post: vi.fn() },
  UNAUTHENTICATED_EVENT: 'soc:unauthenticated',
}));
const principal = { kind: 'user', id: 'user-1', username: 'analyst', roles: ['analyst'], reauth_at: null };
const unauthorized = { isAxiosError: true, response: { status: 401, data: {} } };
function mount(path: string) { return render(<MemoryRouter initialEntries={[path]}><App /></MemoryRouter>); }

beforeEach(() => { vi.resetAllMocks(); localStorage.clear(); });

describe('authentication and navigation shell', () => {
  it('redirects an unauthenticated protected route to login', async () => {
    vi.mocked(api.get).mockRejectedValue(unauthorized);
    mount('/alerts');
    expect(await screen.findByRole('heading', { name: 'Welcome back' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Sign in' })).toBeInTheDocument();
    expect(api.get).toHaveBeenCalledWith('/auth/me');
  });
  it('uses me after login, restores the requested route and responds to expiry', async () => {
    const password = Redacted.random();
    let meCount = 0;
    vi.mocked(api.get).mockImplementation(((path: string) => {
      if (path === '/auth/me') return ++meCount === 1 ? Promise.reject(unauthorized) : Promise.resolve({ data: { principal } });
      if (path === '/presentation') return Promise.resolve({ data: { display_name: 'SMART SOC', default_direction: 'rtl' } });
      if (path === '/alerts') return Promise.resolve({ data: { items: [], next_cursor: null } });
      return Promise.reject(new Error(`Unexpected request: ${path}`));
    }) as typeof api.get);
    vi.mocked(api.post).mockResolvedValue({ data: { principal } });
    mount('/alerts');
    fireEvent.change(await screen.findByLabelText('Username'), { target: { value: 'analyst' } });
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: password.reveal() } });
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByRole('heading', { name: 'Alerts' })).toBeInTheDocument();
    expect(vi.mocked(api.get).mock.calls.filter(([path]) => path === '/auth/me')).toHaveLength(2);
    window.dispatchEvent(new Event(UNAUTHENTICATED_EVENT));
    expect(await screen.findByRole('heading', { name: 'Welcome back' })).toBeInTheDocument();
  });
  it('provides administration navigation and switches RTL/LTR and language', async () => {
    vi.mocked(api.get).mockImplementation(((path: string) => Promise.resolve({ data: path === '/auth/me'
      ? { principal } : { display_name: 'SMART SOC', default_direction: 'rtl' } })) as typeof api.get);
    mount('/policies');
    expect(await screen.findByText('Governance Plane — built in P9')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Administration' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Settings' })).toHaveAttribute('href', '/settings');
    expect(document.documentElement.dir).toBe('rtl');
    fireEvent.click(screen.getByRole('button', { name: 'Switch layout to left-to-right' }));
    await waitFor(() => expect(document.documentElement.dir).toBe('ltr'));
    fireEvent.click(screen.getByRole('button', { name: 'Change language' }));
    expect(screen.getByRole('heading', { name: 'الإدارة' })).toBeInTheDocument();
    expect(document.documentElement.lang).toBe('ar');
  });
  it('distinguishes a service outage from an anonymous session', async () => {
    vi.mocked(api.get).mockRejectedValue({ isAxiosError: true, response: { status: 503, data: {} } });
    mount('/alerts');
    expect(await screen.findByRole('heading', { name: 'Unable to check your session' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Welcome back' })).not.toBeInTheDocument();
  });
});
