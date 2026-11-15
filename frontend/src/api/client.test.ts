import type { AxiosAdapter, InternalAxiosRequestConfig } from 'axios';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Redacted } from '../test/Redacted';
import { api } from './client';
import { mapProblem } from './problem';

const originalAdapter = api.defaults.adapter;
afterEach(() => {
  if (originalAdapter) api.defaults.adapter = originalAdapter;
  else delete api.defaults.adapter;
  vi.restoreAllMocks();
});

describe('same-origin API client', () => {
  it('injects the CSRF cookie only on mutations and never changes the API base', async () => {
    const secret = Redacted.random();
    vi.spyOn(document, 'cookie', 'get').mockReturnValue(`soc_dev_csrf=${secret.reveal()}`);
    const requests: InternalAxiosRequestConfig[] = [];
    const adapter: AxiosAdapter = (config) => {
      requests.push(config);
      return Promise.resolve({ data: {}, status: 200, statusText: 'OK', headers: {}, config });
    };
    api.defaults.adapter = adapter;
    await api.get('/auth/me');
    await api.post('/auth/logout');
    expect(requests[0]?.headers.has('X-CSRF-Token')).toBe(false);
    expect(requests[1]?.headers.get('X-CSRF-Token') === secret.reveal()).toBe(true);
    expect(requests.every((request) => request.baseURL === '/api')).toBe(true);
  });
  it('rejects cross-origin and path traversal targets before dispatch', async () => {
    const adapter = vi.fn();
    api.defaults.adapter = adapter;
    await expect(api.get('https://elsewhere.invalid/anything')).rejects.toThrow('Only same-origin API paths');
    await expect(api.get('/../outside')).rejects.toThrow('Only same-origin API paths');
    await expect(api.get('//elsewhere.invalid/path')).rejects.toThrow('Only same-origin API paths');
    expect(adapter).not.toHaveBeenCalled();
  });
  it('maps problem responses without exposing untrusted detail', () => {
    const result = mapProblem({ isAxiosError: true, response: { status: 403, data: {
      detail: 'untrusted server content', correlation_id: 'abc-123',
    } } });
    expect(result.status).toBe(403);
    expect(result.message).toContain('permission');
    expect(result.message).not.toContain('untrusted');
    expect(result.correlationId).toBe('abc-123');
    expect(mapProblem(new Error('secret exception detail')).message).not.toContain('secret');
  });
});
