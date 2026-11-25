import { describe, expect, it } from 'vitest';
import { protect, sanitize, withRedactedErrors } from '../../e2e/redaction';
import { Redacted } from './Redacted';

describe('end-to-end diagnostic redaction', () => {
  it('keeps error details but masks credentials, headers, and webhook signatures', () => {
    const password = Redacted.random();
    const cookie = Redacted.random();
    protect(password.reveal());
    const output = sanitize(`failure ${password.reveal()}\n  - Cookie: soc_dev_session=${cookie.reveal()}\nsha256=${'a'.repeat(64)}`);
    if (output.includes(password.reveal()) || output.includes(cookie.reveal())) throw new Error('A test secret leaked');
    expect(output).toContain('failure <redacted>');
    expect(output).toContain('Cookie: <redacted>');
    expect(output).toContain('sha256=<redacted>');
  });

  it('preserves a masked failure rather than hiding the diagnostic', async () => {
    const password = Redacted.random();
    protect(password.reveal());
    let failure = '';
    try { await withRedactedErrors(async () => { throw new Error(`diagnostic ${password.reveal()}`); }); }
    catch (error) { failure = error instanceof Error ? error.stack ?? error.message : String(error); }
    if (failure.includes(password.reveal())) throw new Error('A test secret leaked');
    expect(failure).toContain('diagnostic <redacted>');
  });
});
