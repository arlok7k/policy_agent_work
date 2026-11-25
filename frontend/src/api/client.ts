import axios from 'axios';

export const UNAUTHENTICATED_EVENT = 'soc:unauthenticated';
const safeMethods = new Set(['get', 'head', 'options']);
const secureCsrfCookie = '__Host-soc_csrf';
const developmentCsrfCookie = 'soc_dev_csrf';

function cookieValue(name: string): string | null {
  const item = document.cookie.split('; ').find((part) => part.startsWith(`${name}=`));
  if (!item) return null;
  try { return decodeURIComponent(item.slice(name.length + 1)); } catch { return null; }
}

/** Cookie-authenticated, same-origin API only; no credentials are stored by JS. */
export const api = axios.create({ baseURL: '/api', withCredentials: true, timeout: 20000 });
api.interceptors.request.use((config) => {
  const path = config.url ?? '';
  if (!path.startsWith('/') || path.startsWith('//') || path.includes('\\')) {
    throw new Error('Only same-origin API paths are allowed');
  }
  const resolved = new URL(`/api${path}`, window.location.origin);
  if (resolved.origin !== window.location.origin || !resolved.pathname.startsWith('/api/')) {
    throw new Error('Only same-origin API paths are allowed');
  }
  config.baseURL = '/api';
  if (!safeMethods.has((config.method ?? 'get').toLowerCase())) {
    const names = window.location.protocol === 'http:'
      ? [developmentCsrfCookie, secureCsrfCookie] : [secureCsrfCookie, developmentCsrfCookie];
    const token = names.map(cookieValue).find((value) => value !== null);
    if (token) config.headers.set('X-CSRF-Token', token);
  }
  return config;
});
api.interceptors.response.use(undefined, (error: unknown) => {
  if (axios.isAxiosError(error) && error.response?.status === 401
      && error.config?.url !== '/auth/login') {
    window.dispatchEvent(new Event(UNAUTHENTICATED_EVENT));
  }
  return Promise.reject(error);
});
