import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest';
import { Touchque, withTouchque, ipFromVercel, TouchqueConfigError, TouchqueError, runGuard, WebhookReasons, WebhookEvents, signGuardToken, detailsDigest } from './index';
import { isStatusPoll } from './guard';
import type { GuardTokenClaims } from './steps';
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
      const tq = new Touchque();
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
      expect(() => new Touchque()).toThrow(TouchqueConfigError);
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
      .rejects.toBeInstanceOf(TouchqueError);
  });

  test('actionTypes.define sends the slug, name and critical flag; omits what was not given', async () => {
    const tq = api.client;
    await tq.actionTypes.define('SEND_MONEY', { name: 'Send money', critical: true }).catch(() => undefined);
    await tq.actionTypes.define('EXPORT').catch(() => undefined);
    const bodies = api.calls.filter((c) => c.path === '/action-types').map((c) => c.body);
    expect(bodies[0]).toEqual({ type: 'SEND_MONEY', name: 'Send money', critical: true });
    expect(bodies[1]).toEqual({ type: 'EXPORT', name: 'EXPORT' });
  });
});

describe('behavioural telemetry (R1-04)', () => {
  test('the waiting step carries the telemetry token, only when the workspace issues one', async () => {
    expect((await api.client.start('LOGIN', { user: 'jane@acme.com' })).telemetryToken).toBeUndefined();
    api.opts.telemetry = true;
    expect((await api.client.start('LOGIN', { user: 'jane@acme.com' })).telemetryToken).toBe('tt_test');
  });
});

describe('Vishing Shield', () => {
  test('the first waiting step carries the Mirror Alarm canary; polls do not', async () => {
    expect((await api.client.start('LOGIN', { user: 'jane@acme.com' })).canary).toBeUndefined();
    api.opts.canary = true;
    const first = await runGuard(api.client, { user: 'jane@acme.com', action: 'LOGIN' });
    expect(first.body!.touchque.canary!.url).toMatch(/\/c\/canary-.+\.gif$/);
    const poll = await runGuard(api.client, { user: 'jane@acme.com', action: 'LOGIN', token: first.body!.token });
    expect(poll.body!.touchque).toMatchObject({ state: 'waiting' });
    expect(poll.body!.touchque.canary).toBeUndefined();
  });

  test('a push tapped during a call becomes passkey_required mid-flight, also from the offline QR', async () => {
    const first = await runGuard(api.client, { user: 'jane@acme.com', action: 'LOGIN' });
    const offline = await runGuard(api.client, { user: 'jane@acme.com', action: 'LOGIN', token: first.body!.token, offline: true });
    expect(offline.body!.touchque.state).toBe('offline');
    api.escalate();
    const poll = await runGuard(api.client, { user: 'jane@acme.com', action: 'LOGIN', token: offline.body!.token });
    expect(poll.status).toBe(202);
    expect(poll.body!.touchque).toMatchObject({ state: 'passkey_required', requestId: first.body!.touchque.requestId });
    // A code typed for that QR is refused by Touchque: the step says passkey, not "blocked".
    const typed = await runGuard(api.client, { user: 'jane@acme.com', action: 'LOGIN', token: offline.body!.token, code: 'ABCD123' });
    expect(typed.body!.touchque).toMatchObject({ state: 'passkey_required', requestId: first.body!.touchque.requestId });
  });

  test('a provisional approval says so; critical actions are blocked until the phone re-confirms', async () => {
    const tq = api.client;
    const step = await tq.start('LOGIN', { user: 'jane@acme.com' });
    api.approve(undefined, 'DEVICE', { provisional: true });
    const approval = await tq.complete(step.requestId!, { user: 'jane@acme.com', action: 'LOGIN' });
    expect(approval).toMatchObject({ provisional: true, revoked: false, revokeReason: null, reconfirmedAt: null });
    expect(await tq.start('SEND_MONEY', { user: 'jane@acme.com' })).toEqual({ state: 'blocked', reason: 'provisional', caseCode: 'REF-USE' });
    api.reconfirm(step.requestId);
    expect((await tq.start('SEND_MONEY', { user: 'jane@acme.com' })).state).toBe('waiting');
  });

  test('an approval taken back on the phone is never used', async () => {
    const first = await runGuard(api.client, { user: 'jane@acme.com', action: 'LOGIN' });
    api.approve();
    api.revoke(undefined, 'COACHED');
    const done = await runGuard(api.client, { user: 'jane@acme.com', action: 'LOGIN', token: first.body!.token });
    expect(done.status).toBe(408);
    expect(done.body!.touchque).toMatchObject({ state: 'expired', reason: 'revoked' });
  });

  test('webhook reason and event constants', () => {
    expect(WebhookReasons).toMatchObject({ VISHING_SUSPECTED: 'vishing_suspected', PHISHING_ORIGIN: 'phishing_origin', USER_REPORTED_COACHED: 'user_reported_coached' });
    expect(WebhookEvents).toMatchObject({ APPROVAL_REVOKED: 'APPROVAL_REVOKED', APPROVAL_RECONFIRMED: 'APPROVAL_RECONFIRMED' });
    // The names the backend sends (Mobile SDK, Never Locked Out recovery and help desk events).
    const sent = ['MOBILE_PUSH',
      'RECOVERY_STARTED', 'RECOVERY_DEVICE_BOUND', 'RECOVERY_COOLING', 'RECOVERY_COMPLETED', 'RECOVERY_VETOED', 'RECOVERY_EXPIRED', 'RECOVERY_FAILED',
      'ASSIST_OPENED', 'ASSIST_ENDED', 'ASSIST_CHECK_PASSED', 'ASSIST_CHECK_FAILED', 'ASSIST_UNFROZEN', 'ASSIST_CLAIM_CONFIRMED', 'ASSIST_CLAIM_UNVERIFIED'];
    for (const name of sent) expect((WebhookEvents as Record<string, string>)[name]).toBe(name);
  });
});

describe('withTouchque (Next.js / Fetch API)', () => {
  const call = (h: ReturnType<typeof withTouchque>, headers: Record<string, string> = {}) =>
    h(new Request('http://app.test/api/transfer', { method: 'POST', headers: { 'x-user': 'jane@acme.com', ...headers }, body: JSON.stringify({ amount: 5 }) }));

  test('202 with the step, then the handler runs once approved', async () => {
    const h = withTouchque('SEND_MONEY', async (_req, { touchque }) => Response.json({ ok: true, via: touchque.assurance?.method }), {
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

  // R1-02: behind an appending proxy the leftmost hop is whatever the client sent.
  test('never sends the client-controlled leftmost X-Forwarded-For hop', async () => {
    const sent = async (opts: Partial<Parameters<typeof withTouchque>[2]>) => {
      api.calls.length = 0;
      const h = withTouchque('SEND_MONEY', async () => Response.json({ ok: true }), {
        client: api.client, user: (req) => req.headers.get('x-user'), ...opts,
      });
      await call(h, { 'x-forwarded-for': '1.2.3.4, 203.0.113.9', 'x-real-ip': '198.51.100.4' });
      return api.calls.find((c) => c.path === '/login/request')?.body.clientIp;
    };
    expect(await sent({})).toBeUndefined();
    expect(await sent({ trustedProxyHops: 1 })).toBe('203.0.113.9');
    expect(await sent({ trustedProxyHops: 2 })).toBe('1.2.3.4');
    expect(await sent({ trustedProxyHops: 3 })).toBeUndefined();
    expect(await sent({ ip: ipFromVercel })).toBe('198.51.100.4');
  });

  test('errorBody: a refusal in the app\'s own shape, with the step; a string is sent as it is', async () => {
    const shaped = withTouchque('SEND_MONEY', async () => Response.json({ ok: true }), {
      client: api.client, user: (req) => req.headers.get('x-user'), errorBody: (r) => ({ message: r.message, code: r.code }),
    });
    const start = await (await call(shaped)).json() as { token: string; touchque: { requestId: string } };
    api.reject();
    const res = await call(shaped, { 'x-touchque-token': start.token });
    expect(res.status).toBe(403);
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(res.headers.get('x-touchque-state')).toBe('rejected');
    expect(res.headers.get('x-touchque-reason')).toBeNull();
    expect(await res.json()).toEqual({ message: 'The approval was rejected.', code: 'rejected', touchque: { state: 'rejected', requestId: start.touchque.requestId } });
    const text = withTouchque('SEND_MONEY', async () => Response.json({ ok: true }), { client: api.client, user: () => null, errorBody: (r) => r.message });
    const anonymous = await call(text);
    expect(await anonymous.text()).toBe('"Sign in first."');
    expect(anonymous.headers.get('x-touchque-state')).toBe('blocked');
    expect(anonymous.headers.get('x-touchque-reason')).toBe('unauthenticated');
  });

  test('no TQ_API_KEY / TQ_API_SECRET: 500 misconfigured for a signed-in user, 401 without one; the handler never runs', async () => {
    const saved = { ...process.env };
    delete process.env.TQ_API_KEY;
    delete process.env.TQ_API_SECRET;
    try {
      const handler = vi.fn(async () => Response.json({ ok: true }));
      const h = withTouchque('SEND_MONEY', handler, { user: (req) => req.headers.get('x-user') });
      const res = await call(h);
      expect(res.status).toBe(500);
      expect(res.headers.get('content-type')).toBe('application/json');
      expect(res.headers.get('cache-control')).toBe('no-store');
      expect(res.headers.get('x-touchque-state')).toBe('blocked');
      expect(res.headers.get('x-touchque-reason')).toBe('misconfigured');
      expect(await res.json()).toEqual({
        touchque: { state: 'blocked', reason: 'misconfigured' },
        error: { code: 'misconfigured', message: 'Two-factor approval is not configured correctly.' },
      });
      const anonymous = await h(new Request('http://app.test/api/transfer', { method: 'POST' }));
      expect(anonymous.status).toBe(401);
      expect((await anonymous.json() as { error: { code: string } }).error.code).toBe('unauthenticated');
      expect(handler).not.toHaveBeenCalled();
    } finally {
      process.env = saved;
    }
  });
});

describe('runGuard — beforeStart (a relay charges what a poll on the first-time QR starts)', () => {
  const input = { user: 'new@acme.com', action: 'LOGIN' };
  const tokenOf = (r: { body?: { token?: string } }) => r.body!.token!;

  test('called once, only when that poll would start something; a result it returns is the answer', async () => {
    const first = await runGuard(api.client, input);
    const hook = vi.fn(() => undefined);
    const kept = await runGuard(api.client, { ...input, token: tokenOf(first), beforeStart: hook });
    expect(kept.body?.touchque).toMatchObject({ state: 'enroll' });
    expect(hook).not.toHaveBeenCalled(); // keeping the QR is no start

    api.linked.add('new@acme.com');
    api.calls.length = 0;
    const limited = { status: 429, body: { touchque: { state: 'rate_limited' as const, retryAfter: 30 } } };
    expect(await runGuard(api.client, { ...input, token: tokenOf(first), beforeStart: () => limited })).toBe(limited);
    expect(api.calls).toHaveLength(1); // the link state only: no push
    const linked = await runGuard(api.client, { ...input, token: tokenOf(first), beforeStart: hook });
    expect(linked.body?.touchque.state).toBe('waiting');
    expect(hook).toHaveBeenCalledTimes(1);
    await runGuard(api.client, { ...input, token: tokenOf(linked), beforeStart: hook });
    expect(hook).toHaveBeenCalledTimes(1); // a waiting poll never calls it
  });

  test('a QR at its expiry, or gone, is a start too', async () => {
    api.opts.secretTtlMs = 10_000;
    const hook = vi.fn(() => undefined);
    const first = await runGuard(api.client, input);
    const renewed = await runGuard(api.client, { ...input, token: tokenOf(first), beforeStart: hook });
    expect(renewed.body?.touchque.enroll?.qrCodeDataUrl).toBe('data:image/png;base64,QR2-new@acme.com');
    api.opts.secretTtlMs = undefined;
    const fresh = await runGuard(api.client, { user: 'other@acme.com', action: 'LOGIN' });
    api.pendingSecrets.delete('other@acme.com');
    await runGuard(api.client, { user: 'other@acme.com', action: 'LOGIN', token: tokenOf(fresh), beforeStart: hook });
    expect(hook).toHaveBeenCalledTimes(2);
  });
});

describe('isStatusPoll (relays do not count status polls against the per-user push limit)', () => {
  const token = (claims: Partial<GuardTokenClaims>) => signGuardToken('test_secret', {
    u: 'jane@acme.com', a: 'LOGIN', d: detailsDigest([]), r: null, st: 'enroll', exp: Date.now() + 60_000, ...claims,
  });
  const poll = (t: string, extra: Record<string, unknown> = {}) => isStatusPoll(api.client, { user: 'jane@acme.com', action: 'LOGIN', token: t, ...extra });

  test('a poll while the first-time QR is up is one; without its expiry, or within 15 s of it, it is not', () => {
    expect(poll(token({ ee: Date.now() + 120_000 }))).toBe(true);
    expect(poll(token({}))).toBe(false);
    expect(poll(token({ ee: Date.now() + 10_000 }))).toBe(false);
    expect(poll(token({ ee: Date.now() + 120_000, u: 'mallory@acme.com' }))).toBe(false);
    expect(poll(token({ ee: Date.now() + 120_000 }), { offline: true })).toBe(false);
    expect(poll(token({ st: 'waiting', rid: 'r1' }))).toBe(true);
    expect(poll(token({ st: 'waiting' }))).toBe(false);
  });
});

describe('"Why?" case codes', () => {
  test('a number-matched step names its case and plain reasons; a refusal names its case', async () => {
    api.actions.set('WIRE', { critical: true, active: true });
    const step = await api.client.start('WIRE', { user: 'jane@acme.com' });
    expect(step).toMatchObject({ state: 'waiting', number: '47', caseCode: 'K7P-2QX', reasons: [{ code: 'critical_action', text: 'The action is critical' }] });
    api.opts.blocked = 'access_policy';
    expect(await api.client.start('LOGIN', { user: 'jane@acme.com' })).toEqual({ state: 'blocked', reason: 'access_policy', caseCode: 'REF-USE' });
    api.opts.blocked = undefined;
    api.opts.frozen = true;
    expect(await api.client.start('LOGIN', { user: 'jane@acme.com' })).toMatchObject({ state: 'frozen', caseCode: 'REF-USE' });
  });

  test('the raw API error and the silent check carry it too', async () => {
    api.opts.blocked = 'risk';
    await expect(api.client.login.request({ externalUsername: 'jane@acme.com', type: 'LOGIN' })).rejects.toMatchObject({ status: 403, caseCode: 'REF-USE' });
    api.opts.blocked = undefined;
    expect((await api.client.risk.check({ externalUsername: 'jane@acme.com' })).caseCode).toBe('CHK-2QX');
  });

  test('login.request sends expiresIn only when given', async () => {
    await api.client.login.request({ externalUsername: 'jane@acme.com', type: 'LOGIN', expiresIn: 180, clientSignals: 'eyJ2IjoxfQ' });
    expect(api.calls.filter((c) => c.path === '/login/request').at(-1)?.body).toMatchObject({ expiresIn: 180, clientSignals: 'eyJ2IjoxfQ' });
    await api.client.login.request({ externalUsername: 'jane@acme.com', type: 'LOGIN' });
    expect(api.calls.filter((c) => c.path === '/login/request').at(-1)?.body).not.toHaveProperty('expiresIn');
  });

  test('the guard keeps showing the case while it waits', async () => {
    api.actions.set('WIRE', { critical: true, active: true });
    const first = await runGuard(api.client, { action: 'WIRE', user: 'jane@acme.com' });
    const again = await runGuard(api.client, { action: 'WIRE', user: 'jane@acme.com', token: (first.body as any).token });
    expect((first.body as any).touchque.caseCode).toBe('K7P-2QX');
    expect((again.body as any).touchque).toMatchObject({ state: 'waiting', caseCode: 'K7P-2QX' });
  });
});
