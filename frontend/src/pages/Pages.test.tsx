import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { App } from '../app/App';

vi.mock('../api/client', () => ({
  api: { get: vi.fn(), post: vi.fn(), patch: vi.fn() },
  UNAUTHENTICATED_EVENT: 'soc:unauthenticated',
}));
const analyst = { kind: 'user', id: 'analyst-1', username: 'analyst', roles: ['analyst'], reauth_at: null };
const senior = { ...analyst, id: 'senior-1', username: 'senior', roles: ['senior_analyst'] };
const admin = { ...analyst, id: 'admin-1', username: 'admin', roles: ['admin'] };
const alert = { id: 'alert-1', source: 'wazuh', rule_id: '<img src=x onerror=alert(1)>', severity: 'high', agent: '004',
  src_ip: '8.8.8.8', dst_ip: null, raw: { message: '<script>window.xss = true</script>' }, status: 'open', created_at: '2026-01-01T00:00:00Z' };
const action = { id: 'action-1', incident_id: 'incident-1', action_type: 'isolate_host', target: { agent_id: '004', ip: '8.8.8.8' },
  params: {}, level: 3, approval_mode: 'manual', status: 'pending_approval', requested_by: 'other-user', decided_by: null,
  ttl_seconds: null, ttl_expires_at: null, rollback_request_status: null, created_at: '2026-01-01T00:00:00Z' };
const command = { id: 1, action_id: 'action-2', phase: 'execute', connector: 'simulated_wazuh', command: 'firewall_drop',
  target: { agent_id: '004', ip: '8.8.8.8' }, params: {}, initiator: 'user:other', simulated: true, executed_at: '2026-01-01T00:00:00Z' };
const settings = { display_name: 'Blue team', default_direction: 'ltr', updated_at: '2026-01-01T00:00:00Z' };
function setup(identity = analyst) {
  vi.mocked(api.get).mockImplementation(((path: string) => {
    const routes: Record<string, unknown> = {
      '/auth/me': { principal: identity },
      '/presentation': { display_name: 'Blue team', default_direction: 'rtl' },
      '/alerts/alert-1': alert,
      '/alerts': { items: [alert], next_cursor: null },
      '/incidents/incident-1': { id: 'incident-1', title: 'Investigation', description: null, status: 'open', alert_ids: ['alert-1'], created_at: alert.created_at, updated_at: alert.created_at },
      '/incidents/incident-1/evidence': { items: [], next_cursor: null },
      '/response/actions': { items: [action], next_cursor: null },
      '/response/commands': { items: [command], next_before_id: null },
      '/response/catalog': { items: [] },
      '/response/kill-switch': { engaged: false, changed_by: null, changed_at: alert.created_at },
      '/settings': settings,
    };
    if (!(path in routes)) return Promise.reject(new Error(`Unexpected request: ${path}`));
    return Promise.resolve({ data: routes[path] });
  }) as typeof api.get);
}
function mount(path: string) { render(<MemoryRouter initialEntries={[path]}><App /></MemoryRouter>); }
beforeEach(() => { vi.resetAllMocks(); localStorage.clear(); });

describe('API-backed host pages', () => {
  it('renders hostile alert fields as inert text and investigates via the API', async () => {
    setup();
    vi.mocked(api.post).mockResolvedValue({ data: { incident: { id: 'incident-1' } } });
    mount('/alerts/alert-1');
    expect(await screen.findByRole('heading', { name: alert.rule_id })).toBeInTheDocument();
    expect(screen.getByText(/<script>window.xss/)).toBeInTheDocument();
    expect(document.querySelector('img')).not.toBeInTheDocument();
    expect(document.querySelector('script')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Investigate alert' }));
    expect(await screen.findByRole('heading', { name: 'Incident details' })).toBeInTheDocument();
    expect(api.post).toHaveBeenCalledWith('/alerts/alert-1/investigate', {});
  });
  it('shows real command records but hides approval and switch controls from an analyst', async () => {
    setup(); mount('/response');
    expect(await screen.findByText('firewall_drop')).toBeInTheDocument();
    expect(screen.getByText('isolate host')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Engage Kill Switch' })).not.toBeInTheDocument();
  });
  it('requires confirmation before a senior analyst sends an approval', async () => {
    setup(senior); vi.mocked(api.post).mockResolvedValue({ data: action }); mount('/response');
    fireEvent.click(await screen.findByRole('button', { name: 'Approve' }));
    expect(screen.getByRole('group', { name: 'Confirm response action' })).toBeInTheDocument();
    expect(api.post).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Confirm approve' }));
    await waitFor(() => expect(api.post).toHaveBeenCalledWith('/response/actions/action-1/approve', {}));
  });
  it('saves only presentation settings as an administrator', async () => {
    setup(admin); vi.mocked(api.patch).mockResolvedValue({ data: settings }); mount('/settings');
    const name = await screen.findByLabelText('Display name');
    fireEvent.change(name, { target: { value: 'Blue team' } });
    fireEvent.change(screen.getByLabelText('Default layout direction'), { target: { value: 'ltr' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save settings' }));
    expect(await screen.findByText('Presentation settings saved and audited.')).toBeInTheDocument();
    expect(api.patch).toHaveBeenCalledWith('/settings', { display_name: 'Blue team', default_direction: 'ltr' });
    expect(document.documentElement.dir).toBe('ltr');
  });
});
