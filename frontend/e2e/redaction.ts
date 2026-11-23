import { readFileSync } from 'node:fs';
import { Redacted } from '../src/test/Redacted';

// Playwright workers and the reporter are separate processes. Each protects the
// seed credentials and webhook key, while a worker also records its own cookies
// and signatures before using them at a real HTTP/browser boundary.
const protectedValues: Redacted[] = [];

export function protect(value: string): Redacted {
  if (!value) throw new Error('A required end-to-end secret is empty');
  const result = new Redacted(value);
  protectedValues.push(result);
  return result;
}

for (const name of ['SEED_ADMIN_PASSWORD', 'SEED_SENIOR_ANALYST_PASSWORD', 'SEED_ANALYST_PASSWORD']) {
  const value = process.env[name];
  if (value) protect(value);
}
const secretFile = process.env.SOC_WEBHOOK_SECRET_FILE;
if (secretFile) {
  const value = readFileSync(secretFile, 'utf8').replace(/[\r\n]+$/, '');
  protect(value);
}

export function requiredSecret(name: string): Redacted {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required end-to-end environment variable ${name}`);
  return protect(value);
}

export function sanitize(text: string): string {
  let result = text;
  for (const secret of protectedValues) result = result.replaceAll(secret.reveal(), '<redacted>');
  result = result.replace(/sha256=[0-9a-f]{64}/gi, 'sha256=<redacted>');
  return result.replace(
    /\b(cookie|set-cookie|authorization|x-csrf-token|x-webhook-signature)\s*:\s*[^\r\n]*/gi,
    '$1: <redacted>',
  );
}

export async function withRedactedErrors<T>(work: () => Promise<T>): Promise<T> {
  try { return await work(); }
  catch (failure) {
    const diagnostic = failure instanceof Error ? failure.stack ?? failure.message : String(failure);
    const safe = sanitize(diagnostic);
    const error = new Error(safe);
    error.stack = safe;
    throw error;
  }
}
