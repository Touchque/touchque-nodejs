import { describe, test, expect, beforeEach, afterEach } from 'vitest';
import { TouchQue, withTouchQue, TouchQueConfigError, TouchQueError } from './index';
import { startFakeApi, FakeApi } from './testing/fakeApi';

let api: FakeApi;
beforeEach(async () => { api = await startFakeApi(); api.linked.add('jane@acme.com'); });
afterEach(async () => { await api.close(); });

describe('config', () => {
  test('reads TQ_API_KEY / TQ_API_SECRET / TQ_API_URL from the environment', async () => {
    const saved = { ...process.env };
    process.env.TQ_API_KEY = 'tq_env_key';
    process.env.TQ_API_SECRET = 'env_secret';
    process.env.TQ_API_URL = await baseOf(api);
    try {
      const tq = new TouchQue();
      const step = await tq.start('LOGIN', { user: 'jane@acme.com' });
      expect(step.state).toBe('waiting');
    } finally {
      process.env = saved;
    }
  });

  test('a missing key is a clear error', () => {
    const saved = { ...process.env };
    delete process.env.TQ_API_KEY;
    delete process.env.TQ_API_SECRET;
    try {
      expect(() => new TouchQue()).toThrow(TouchQueConfigError);
    } finally {
      process.env = saved;
    }
  });
});

/** The fake API's URL, read from the client it created. */
async function baseOf(a: FakeApi): Promise<string> {
  const { resources } = await import('./internal');
  return (resources(a.client).http as any).client.defaults.baseURL;
}

describe('start / check / complete', () => {
  test('headless flow: start returns the number at once, complete uses the approval once', async () => {
    const tq = api.client;
    const step = await tq.start('SEND_MONEY', { user: 'jane@acme.com', details: { Amount: '250 EUR' }, referenceId: 'tx-9' });
    expect(step).toMatchObject({ state: 'waiting', number: '47', details: [{ label: 'Amount', value: '250 EUR' }] });
    expect((await tq.check(step.requestId!)).state).toBe('waiting');
    api.approve();
    expect((await tq.check(step.requestId!)).state).toBe('approved');
    const approval = await tq.complete(step.requestId!, { user: 'jane@acme.com', action: 'SEND_MONEY', details: { Amount: '250 EUR' }, referenceId: 'tx-9' });
    expect(approval.assurance).toEqual({ phishingResistant: false, method: 'push' });
    await expect(tq.complete(step.requestId!, { user: 'jane@acme.com', action: 'SEND_MONEY', details: { Amount: '250 EUR' }, referenceId: 'tx-9' }))
      .rejects.toMatchObject({ status: 409, code: 'already_used' });
  });

  test('complete refuses an approval for a different amount', async () => {
    const tq = api.client;
    const step = await tq.start('SEND_MONEY', { user: 'jane@acme.com', details: { Amount: '250 EUR' } });
    api.approve();
    await expect(tq.complete(step.requestId!, { user: 'jane@acme.com', action: 'SEND_MONEY', details: { Amount: '9999 EUR' } }))
      .rejects.toBeInstanceOf(TouchQueError);
  });

  test('actions.define sends the slug, name and critical flag; omits what was not given', async () => {
    const tq = api.client;
    await tq.actions.define('SEND_MONEY', { name: 'Send money', critical: true }).catch(() => undefined);
    await tq.actions.define('EXPORT').catch(() => undefined);
    const bodies = api.calls.filter((c) => c.path === '/action-types').map((c) => c.body);
    expect(bodies[0]).toEqual({ type: 'SEND_MONEY', name: 'Send money', critical: true });
    expect(bodies[1]).toEqual({ type: 'EXPORT', name: 'EXPORT' });
  });
});

describe('withTouchQue (Next.js / Fetch API)', () => {
  const call = (h: ReturnType<typeof withTouchQue>, headers: Record<string, string> = {}) =>
    h(new Request('http://app.test/api/transfer', { method: 'POST', headers: { 'x-user': 'jane@acme.com', ...headers }, body: JSON.stringify({ amount: 5 }) }));

  test('202 with the step, then the handler runs once approved', async () => {
    const h = withTouchQue('SEND_MONEY', async (_req, { touchque }) => Response.json({ ok: true, via: touchque.assurance?.method }), {
      client: api.client,
      user: (req) => req.headers.get('x-user'),
      details: async (req) => ({ Amount: `${(await req.clone().json()).amount} EUR` }),
    });
    const first = await call(h);
    expect(first.status).toBe(202);
    const body = await first.json();
    expect(body.touchque.number).toBe('47');
    api.approve();
    const done = await call(h, { 'x-touchque-token': body.token });
    expect(done.status).toBe(200);
    expect(await done.json()).toEqual({ ok: true, via: 'push' });
  });
});
