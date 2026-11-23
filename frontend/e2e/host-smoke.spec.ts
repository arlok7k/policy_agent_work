import { createHmac, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { connect, isIP } from 'node:net';
import { expect, test } from '@playwright/test';
import type { APIRequestContext, BrowserContext, Page, Request } from '@playwright/test';
import { Redacted } from '../src/test/Redacted';
import { protect, requiredSecret, withRedactedErrors } from './redaction';

interface Alert { id: string; rule_id: string }
interface Incident { id: string; alert_ids: string[] }
interface Action { id: string; status: string; requested_by: string; decided_by: string | null }
interface Command { action_id: string; command: string; phase: string; simulated: boolean }
interface Endpoint { host: string; port: number }

async function json<T>(response: { json(): Promise<unknown> }): Promise<T> { return await response.json() as T; }

function validateTarget(): string {
  const target = process.env.SOC_BASE_URL;
  if (process.env.SOC_E2E_DISPOSABLE !== '1' || target !== 'http://nginx:8080') {
    throw new Error('Smoke tests require the disposable Compose edge client and http://nginx:8080');
  }
  return new URL(target).origin;
}

function monitorBrowser(context: BrowserContext, origin: string, violations: string[]): void {
  context.on('request', (request: Request) => {
    const address = new URL(request.url());
    const type = request.resourceType();
    const sameOrigin = address.origin === origin;
    const api = address.pathname.startsWith('/api/');
    const document = type === 'document' && request.method() === 'GET';
    const asset = request.method() === 'GET'
      && (address.pathname.startsWith('/assets/') || address.pathname === '/favicon.ico')
      && ['script', 'stylesheet', 'image', 'font', 'other'].includes(type);
    if (!sameOrigin || !(api || document || asset)) {
      // Do not log query strings or request headers, which may contain secrets.
      violations.push(`${request.method()} ${type} ${address.origin}${address.pathname}`);
    }
  });
  const watchPage = (page: Page) => page.on('websocket', () => violations.push('Unexpected WebSocket'));
  for (const page of context.pages()) watchPage(page);
  context.on('page', watchPage);
}

function endpoints(): Record<string, Endpoint> {
  const raw = process.env.SOC_E2E_INTERNAL_ENDPOINTS;
  if (!raw) throw new Error('Missing internal endpoint inventory for the isolation check');
  const values = JSON.parse(raw) as Record<string, { host?: unknown; port?: unknown }>;
  const result: Record<string, Endpoint> = {};
  for (const [name, port] of [['postgres', 5432], ['redis-broker', 6379], ['redis-cache', 6379]] as const) {
    const value = values[name];
    if (!value || typeof value.host !== 'string' || isIP(value.host) !== 4 || value.port !== port) {
      throw new Error(`Invalid or missing internal endpoint for ${name}`);
    }
    result[name] = { host: value.host, port };
  }
  return result;
}

async function canConnect(endpoint: Endpoint): Promise<boolean> {
  return await new Promise<boolean>((resolve) => {
    const socket = connect({ host: endpoint.host, port: endpoint.port });
    const finish = (connected: boolean) => { socket.destroy(); resolve(connected); };
    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
    socket.setTimeout(1500, () => finish(false));
  });
}

async function login(page: Page, username: string, password: Redacted): Promise<void> {
  await page.goto('/login');
  await page.getByLabel('Username').fill(username);
  await page.getByLabel('Password').fill(password.reveal());
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
}

async function checkDevelopmentCookies(context: BrowserContext): Promise<Redacted> {
  const cookies = await context.cookies();
  const session = cookies.find((cookie) => cookie.name === 'soc_dev_session');
  const csrf = cookies.find((cookie) => cookie.name === 'soc_dev_csrf');
  if (!session || !csrf) throw new Error('Expected separate development session and CSRF cookies');
  protect(session.value);
  const token = protect(csrf.value);
  for (const cookie of [session, csrf]) {
    expect({ domain: cookie.domain, path: cookie.path, secure: cookie.secure, sameSite: cookie.sameSite })
      .toEqual({ domain: 'nginx', path: '/', secure: false, sameSite: 'Strict' });
    expect(cookie.expires).toBeGreaterThan(0);
  }
  expect(session.httpOnly).toBe(true);
  expect(csrf.httpOnly).toBe(false);
  return token;
}

async function sendWebhook(
  request: APIRequestContext, signing: Redacted, payload: Record<string, unknown>,
): Promise<void> {
  const body = JSON.stringify(payload);
  const timestamp = String(Math.floor(Date.now() / 1000));
  const event = randomUUID();
  const signature = protect(`sha256=${createHmac('sha256', signing.reveal())
    .update(`${timestamp}.${event}.${body}`).digest('hex')}`);
  const response = await request.post('/api/alerts/webhook', {
    data: body,
    headers: {
      'Content-Type': 'application/json',
      'X-Webhook-Timestamp': timestamp,
      'X-Webhook-Id': event,
      'X-Webhook-Signature': signature.reveal(),
    },
  });
  expect(response.status(), 'signed webhook was accepted').toBe(202);
  expect(await json<{ accepted: boolean }>(response)).toEqual({ accepted: true });
}

async function getAlerts(request: APIRequestContext, query: string): Promise<Alert[]> {
  const response = await request.get(`/api/alerts${query}`);
  expect(response.status(), 'alert list was available').toBe(200);
  return (await json<{ items: Alert[] }>(response)).items;
}

const headings = (alertId: string, incidentId: string): [string, string][] => [
  ['/', 'Operational overview'],
  ['/alerts', 'Alerts'],
  [`/alerts/${alertId}`, 'Alert details'],
  ['/incidents', 'Incidents'],
  [`/incidents/${incidentId}`, 'Incident details'],
  ['/response', 'Response center'],
  ['/threat-intel', 'Threat intelligence'],
  ['/ioc-scanner', 'IOC scanner'],
  ['/settings', 'Settings'],
  ['/users', 'Users'],
  ['/mitre', 'MITRE ATT&CK'],
  ['/analytics', 'Analytics'],
  ['/reports', 'Reports'],
  ['/toolkit', 'Toolkit'],
  ['/policies', 'Policies'],
];

test('signed alert to four-eyes response, security boundaries and Kill Switch', async ({
  page, context, browser, request,
}) => withRedactedErrors(async () => {
  const origin = validateTarget();
  const violations: string[] = [];
  monitorBrowser(context, origin, violations);
  const analyst = requiredSecret('SEED_ANALYST_PASSWORD');
  const senior = requiredSecret('SEED_SENIOR_ANALYST_PASSWORD');
  const administrator = requiredSecret('SEED_ADMIN_PASSWORD');
  const secretPath = process.env.SOC_WEBHOOK_SECRET_FILE;
  if (!secretPath) throw new Error('Missing webhook secret file path');
  const signing = protect(readFileSync(secretPath, 'utf8').replace(/[\r\n]+$/, ''));
  const source = `pb4-smoke-${randomUUID()}`;
  const hostile = '<img src=x onerror=window.__pb4xss=1>';
  const rule = `pb4-${randomUUID()} ${hostile}`;
  let alertId = '';
  let incidentId = '';
  let actionId = '';
  let analystCsrf: Redacted;

  await test.step('Check edge isolation, route guards and effective CSP', async () => {
    for (const [name, endpoint] of Object.entries(endpoints())) {
      expect(await canConnect(endpoint), `${name} is unreachable from the edge network`).toBe(false);
    }
    const response = await page.goto('/');
    expect(response?.status()).toBe(200);
    const headers = response?.headers() ?? {};
    expect(headers['content-security-policy']).toContain("script-src 'self'");
    expect(headers['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(headers['x-frame-options']).toBe('DENY');
    expect(headers['x-content-type-options']).toBe('nosniff');
    await expect(page).toHaveURL(/\/login$/);
    await page.evaluate(() => {
      const inline = document.createElement('script');
      inline.textContent = 'window.__pb4CspProbe = true';
      document.body.append(inline);
    });
    expect(await page.evaluate(() => Reflect.get(window, '__pb4CspProbe'))).toBeUndefined();
    const placeholderId = randomUUID();
    for (const [path] of headings(placeholderId, placeholderId)) {
      await page.goto(path);
      await expect(page).toHaveURL(/\/login$/);
      await expect(page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
    }
  });

  await test.step('Log in as analyst and reject a mutation without CSRF', async () => {
    await login(page, 'analyst', analyst);
    analystCsrf = await checkDevelopmentCookies(context);
    const missing = await context.request.post('/api/incidents', { data: { title: 'CSRF probe', alert_ids: [] } });
    expect(missing.status()).toBe(403);
  });

  await test.step('Send signed hostile alert and investigate it through the UI', async () => {
    await sendWebhook(request, signing, {
      source, rule_id: rule, severity: 'high', agent: '004', src_ip: '8.8.8.8', raw: { message: hostile },
    });
    await expect.poll(async () => {
      const found = (await getAlerts(context.request, `?source=${encodeURIComponent(source)}`))
        .find((item) => item.rule_id === rule);
      alertId = found?.id ?? '';
      return alertId.length > 0;
    }, { timeout: 45_000, intervals: [500, 1000, 2000] }).toBe(true);
    await page.goto('/alerts');
    await page.getByRole('link', { name: rule, exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Alert details' })).toBeVisible();
    await expect(page.locator('pre')).toContainText(hostile);
    await expect(page.locator('main img[src="x"]')).toHaveCount(0);
    expect(await page.evaluate(() => Reflect.get(window, '__pb4xss'))).toBeUndefined();
    const responsePromise = page.waitForResponse((response) =>
      response.url().endsWith(`/api/alerts/${alertId}/investigate`) && response.request().method() === 'POST');
    await page.getByRole('button', { name: 'Investigate alert' }).click();
    const response = await responsePromise;
    expect(response.status()).toBe(200);
    const result = await json<{ incident: Incident }>(response);
    incidentId = result.incident.id;
    expect(result.incident.alert_ids).toContain(alertId);
    await expect(page).toHaveURL(new RegExp(`/incidents/${incidentId}$`));
    await expect(page.getByRole('heading', { name: 'Incident details' })).toBeVisible();
  });

  await test.step('Request L3 and prove analyst approval is denied in UI and API', async () => {
    await page.getByRole('link', { name: 'Request response' }).click();
    await expect(page.getByLabel('Incident ID')).toHaveValue(incidentId);
    await page.getByLabel('Containment / action').selectOption('isolate_host');
    await page.getByLabel('Agent ID').fill('004');
    await page.getByLabel('Target IP').fill('8.8.8.8');
    const responsePromise = page.waitForResponse((response) =>
      response.url().endsWith('/api/response/actions') && response.request().method() === 'POST');
    await page.getByRole('button', { name: 'Submit response request' }).click();
    const response = await responsePromise;
    expect(response.status()).toBe(201);
    const action = await json<Action>(response);
    actionId = action.id;
    expect(action.status).toBe('pending_approval');
    const row = page.getByRole('table', { name: 'Response activity' }).getByRole('row')
      .filter({ hasText: `#${actionId.slice(0, 8)}` });
    await expect(row).toContainText('pending approval');
    await expect(row.getByRole('button', { name: 'Approve', exact: true })).toHaveCount(0);
    const denied = await context.request.post(`/api/response/actions/${actionId}/approve`, {
      headers: { 'X-CSRF-Token': analystCsrf.reveal() }, data: {},
    });
    expect(denied.status()).toBe(403);
    const list = await context.request.get(`/api/response/actions?incident_id=${incidentId}`);
    expect(list.status()).toBe(200);
    const unchanged = (await json<{ items: Action[] }>(list)).items.find((item) => item.id === actionId);
    expect(unchanged?.status).toBe('pending_approval');
    expect(unchanged?.decided_by).toBeNull();
    const commands = await context.request.get(`/api/response/commands?action_id=${actionId}`);
    expect((await json<{ items: Command[] }>(commands)).items).toEqual([]);
  });

  const seniorContext = await browser.newContext({ baseURL: origin });
  monitorBrowser(seniorContext, origin, violations);
  const seniorPage = await seniorContext.newPage();
  await test.step('Second user approves and the simulated command appears', async () => {
    await login(seniorPage, 'senior_analyst', senior);
    await checkDevelopmentCookies(seniorContext);
    await seniorPage.goto('/response');
    const row = seniorPage.getByRole('table', { name: 'Response activity' }).getByRole('row')
      .filter({ hasText: `#${actionId.slice(0, 8)}` });
    await row.getByRole('button', { name: 'Approve', exact: true }).click();
    const responsePromise = seniorPage.waitForResponse((response) =>
      response.url().endsWith(`/api/response/actions/${actionId}/approve`) && response.request().method() === 'POST');
    await seniorPage.getByRole('dialog').getByRole('button', { name: 'Confirm approve' }).click();
    const response = await responsePromise;
    expect(response.status()).toBe(200);
    const decision = await json<Action>(response);
    expect(decision.decided_by).not.toBeNull();
    expect(decision.decided_by).not.toBe(decision.requested_by);
    await expect.poll(async () => {
      const commandResponse = await seniorContext.request.get(`/api/response/commands?action_id=${actionId}`);
      expect(commandResponse.status()).toBe(200);
      const commands = (await json<{ items: Command[] }>(commandResponse)).items;
      return commands.filter((command) => command.command === 'isolate_host'
        && command.phase === 'execute' && command.simulated).length;
    }, { timeout: 45_000, intervals: [500, 1000, 2000] }).toBe(1);
    await seniorPage.getByRole('button', { name: 'Refresh activity' }).click();
    const commandRow = seniorPage.getByRole('table', { name: 'Executed-command log' }).getByRole('row')
      .filter({ hasText: `#${actionId.slice(0, 8)}` });
    await expect(commandRow).toContainText('isolate_host');
    await expect(commandRow).toContainText('Simulated');
  });

  await test.step('Verify modal focus and engage the Kill Switch', async () => {
    const trigger = seniorPage.getByRole('button', { name: 'Engage Kill Switch' });
    await trigger.click();
    const dialog = seniorPage.getByRole('dialog');
    await dialog.getByRole('button', { name: 'Close dialog' }).focus();
    for (let index = 0; index < 5; index += 1) {
      await seniorPage.keyboard.press('Tab');
      expect(await seniorPage.evaluate(() => document.querySelector('dialog')?.contains(document.activeElement))).toBe(true);
    }
    await seniorPage.keyboard.press('Escape');
    await expect(trigger).toBeFocused();
    await trigger.click();
    const responsePromise = seniorPage.waitForResponse((response) =>
      response.url().endsWith('/api/response/kill-switch') && response.request().method() === 'POST');
    await seniorPage.getByRole('dialog').getByRole('button', { name: 'Confirm engage' }).click();
    expect((await responsePromise).status()).toBe(200);
    const state = await seniorContext.request.get('/api/response/kill-switch');
    expect((await json<{ engaged: boolean }>(state)).engaged).toBe(true);
    await expect(seniorPage.getByRole('button', { name: 'Disengage Kill Switch' })).toBeVisible();
  });

  const adminContext = await browser.newContext({ baseURL: origin });
  monitorBrowser(adminContext, origin, violations);
  const adminPage = await adminContext.newPage();
  await test.step('Render all host routes and verify RTL table navigation', async () => {
    await login(adminPage, 'admin', administrator);
    await checkDevelopmentCookies(adminContext);
    for (const [path, title] of headings(alertId, incidentId)) {
      await adminPage.goto(path);
      await expect(adminPage.getByRole('heading', { name: title, level: 1 })).toBeVisible();
    }
    await expect(adminPage.getByText('Governance Plane — built in P9')).toBeVisible();
    await adminPage.goto('/settings');
    await expect(adminPage.getByRole('heading', { name: 'Workspace presentation' })).toBeVisible();
    await expect(adminPage.getByLabel('Display name')).toHaveValue('SMART SOC');
    await adminPage.goto('/users');
    await expect(adminPage.getByRole('heading', { name: 'User directory' })).toBeVisible();
    await expect(adminPage.getByRole('table', { name: 'User directory' })).toContainText('admin');
    await adminPage.goto('/alerts');
    await expect(adminPage.getByRole('table', { name: 'Alert feed' })).toBeVisible();
    await expect(adminPage.locator('html')).toHaveAttribute('dir', 'rtl');
    await adminPage.getByRole('button', { name: 'Switch layout to left-to-right' }).click();
    await expect(adminPage.locator('html')).toHaveAttribute('dir', 'ltr');
    await adminPage.getByRole('button', { name: 'Switch layout to right-to-left' }).click();
    await expect(adminPage.locator('html')).toHaveAttribute('dir', 'rtl');
  });

  await test.step('Handle a slow API and paginate a large alert list', async () => {
    for (let index = 0; index < 51; index += 1) {
      await sendWebhook(request, signing, {
        source, rule_id: `pagination-${index}-${randomUUID()}`, severity: 'low', raw: { index },
      });
    }
    await expect.poll(async () => (await getAlerts(adminContext.request, `?source=${encodeURIComponent(source)}&limit=100`)).length,
      { timeout: 60_000, intervals: [1000, 2000] }).toBeGreaterThan(50);
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    await adminPage.route('**/api/alerts', async (route) => { await gate; await route.continue(); });
    await adminPage.goto('/alerts');
    await expect(adminPage.getByRole('status').filter({ hasText: 'Loading data' })).toBeVisible();
    if (!release) throw new Error('The slow-request test did not create its release signal');
    release();
    await expect(adminPage.getByRole('table', { name: 'Alert feed' })).toBeVisible();
    await adminPage.unroute('**/api/alerts');
    const pager = adminPage.getByRole('navigation', { name: 'Alert pages' });
    await expect(pager.getByRole('button', { name: 'Next' })).toBeEnabled();
    await pager.getByRole('button', { name: 'Next' }).click();
    await expect(pager.getByRole('button', { name: 'Previous' })).toBeEnabled();
  });

  await test.step('Revoke a session mid-action and fail closed', async () => {
    await adminPage.goto('/response');
    const trigger = adminPage.getByRole('button', { name: 'Disengage Kill Switch' });
    await expect(trigger).toBeVisible();
    const csrf = await checkDevelopmentCookies(adminContext);
    const logout = await adminContext.request.post('/api/auth/logout', { headers: { 'X-CSRF-Token': csrf.reveal() } });
    expect(logout.status()).toBe(204);
    await trigger.click();
    await adminPage.getByRole('dialog').getByRole('button', { name: 'Confirm disengage' }).click();
    await expect(adminPage).toHaveURL(/\/login$/);
    const state = await seniorContext.request.get('/api/response/kill-switch');
    expect((await json<{ engaged: boolean }>(state)).engaged).toBe(true);
  });

  await test.step('Assert every browser data request stayed on the same-origin API', async () => {
    expect(violations).toEqual([]);
  });
  await adminContext.close();
  await seniorContext.close();
}));
