// @touchque/node/testing: FakeTouchque runs the real guard, answered in memory.
// No network, no keys.
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest';
import express from 'express';
import request from 'supertest';
import { requireTouchque, runGuard, getDefaultClient, GuardRefusal, TouchqueAPIError, Touchque } from './index';
import { isStatusPoll } from './guard';
import { FakeTouchque } from './testing';

let saved: NodeJS.ProcessEnv;
beforeEach(() => {
  saved = { ...process.env };
  delete process.env.TQ_API_KEY;
  delete process.env.TQ_API_SECRET;
});
afterEach(() => { process.env = saved; });

/** A partner app: one guarded route, the signed-in user from a header. */
function makeApp(client?: Touchque, extra: Record<string, unknown> = {}) {
  const app = express();
  app.use(express.json());
  app.post('/transfer',
    requireTouchque('SEND_MONEY', {
      client, user: (req) => req.get('x-user') || undefined, details: (req) => ({ Amount: `${req.body.amount} EUR` }), ...extra,
    }),
    (req, res) => res.json({ done: true, touchque: (req as unknown as { touchque: unknown }).touchque }));
  return app;
}

const send = (app: express.Express, token?: string, user = 'jane@acme.com', headers: Record<string, string> = {}) =>
  request(app).post('/transfer').set({ 'x-user': user, ...(token && { 'X-Touchque-Token': token }), ...headers }).send({ amount: 5 });

describe('FakeTouchque', () => {
  test('a route waits for the approval, then runs once; requests and calls say what the app asked', async () => {
    const tq = new FakeTouchque();
    const app = makeApp(tq);

    const first = await send(app);
    expect(first.status).toBe(202);
    expect(first.body.touchque).toMatchObject({ state: 'waiting', details: [{ label: 'Amount', value: '5 EUR' }] });
    expect((await send(app, first.body.token)).status).toBe(202); // still waiting

    tq.approve();
    const done = await send(app, first.body.token);
    expect(done.status).toBe(200);
    expect(done.body.touchque.assurance).toEqual({ phishingResistant: false, method: 'push' });
    expect((await send(app, first.body.token)).status).toBe(408); // used once

    const [r] = tq.requests;
    expect(r).toMatchObject({ user: 'jane@acme.com', type: 'SEND_MONEY', status: 'CONFIRMED', consumed: true, referenceId: null });
    expect(tq.calls[0]).toEqual({
      method: 'POST', path: '/login/request',
      body: { externalUsername: 'jane@acme.com', type: 'SEND_MONEY', clientIp: expect.any(String), details: [{ label: 'Amount', value: '5 EUR' }] },
    });
    expect(tq.calls.slice(1).map((c) => c.path)).toEqual([
      `/login/status/${r.id}`, `/login/status/${r.id}`, `/login/${r.id}/consume`, `/login/status/${r.id}`, `/login/${r.id}/consume`,
    ]);
  });

  test('a request keeps its expiry, and polls carry the one its status answers', async () => {
    const tq = new FakeTouchque();
    const app = makeApp(tq);
    const first = (await send(app)).body;
    expect(first.touchque.expiresAt).toBe(tq.requests[0].expiresAt);
    expect(Date.parse(tq.requests[0].expiresAt) - Date.now()).toBeGreaterThan(25_000);
    tq.requests[0].expiresAt = new Date(Date.parse(first.touchque.expiresAt) + 150_000).toISOString(); // extended
    const poll = (await send(app, first.token)).body;
    expect(poll.touchque).toMatchObject({ state: 'waiting', expiresAt: tq.requests[0].expiresAt });
  });

  test('reject, expire, a request by its id, the number to match', async () => {
    const tq = new FakeTouchque({ numberMatch: true });
    const app = makeApp(tq);
    const jane = (await send(app)).body;
    const joe = (await send(app, undefined, 'joe@acme.com')).body;
    expect(jane.touchque.number).toBe('47');

    expect(tq.reject(jane.touchque.requestId)).toBe(jane.touchque.requestId);
    tq.expire(); // the latest: joe's
    expect((await send(app, jane.token)).status).toBe(403);
    expect((await send(app, joe.token, 'joe@acme.com')).status).toBe(408);
    expect(() => new FakeTouchque().approve()).toThrow('FakeTouchque: no approval request yet');
    expect(() => tq.approve('nope')).toThrow('FakeTouchque: no approval request nope');
  });

  test('autoApprove: the first request still answers 202, the next one runs the route', async () => {
    const tq = new FakeTouchque({ autoApprove: true });
    const app = makeApp(tq);
    const first = await send(app);
    expect(first.status).toBe(202);
    expect((await send(app, first.body.token)).status).toBe(200);
  });

  test('install(): the default client for routes given none and runGuard(null), until uninstall()', async () => {
    const app = makeApp(); // no client
    expect((await send(app)).status).toBe(500); // no keys here
    const tq = new FakeTouchque().install();
    try {
      expect(getDefaultClient()).toBe(tq);
      const first = await send(app);
      expect(first.status).toBe(202);
      tq.approve();
      expect((await send(app, first.body.token)).status).toBe(200);

      const token = (await runGuard(null, { user: 'jane@acme.com', action: 'LOGIN' })).body!.token!;
      expect(isStatusPoll(null, { user: 'jane@acme.com', action: 'LOGIN', token })).toBe(true);

      const other = new FakeTouchque().install(); // installs stack: each puts back what it replaced
      expect(getDefaultClient()).toBe(other);
      other.uninstall();
      expect(getDefaultClient()).toBe(tq);
    } finally {
      tq.uninstall();
    }
    expect((await send(app)).status).toBe(500); // back to no default client
    expect(isStatusPoll(null, { user: 'jane@acme.com', action: 'LOGIN', token: 'v1.e30.x' })).toBe(false);
  });

  test('the first-time QR stays until linked, and a new one comes after it is gone or about to expire', async () => {
    const tq = new FakeTouchque();
    tq.unlink('new@acme.com');
    const app = makeApp(tq);
    const first = (await send(app, undefined, 'new@acme.com')).body;
    const qr = first.touchque.enroll;
    expect(qr).toMatchObject({ qrCodeDataUrl: expect.stringMatching(/^data:image\/png;base64,/), expiresAt: expect.any(String), recoveryCodes: [expect.any(String)] });

    const before = tq.calls.length;
    const poll = (await send(app, first.token, 'new@acme.com')).body;
    expect(poll.touchque).toEqual({ state: 'enroll', expiresAt: new Date(Date.parse(qr.expiresAt)).toISOString(), details: [{ label: 'Amount', value: '5 EUR' }] });
    expect(tq.calls.slice(before).map((c) => c.path)).toEqual(['/users/new%40acme.com']);

    tq.unlink('new@acme.com'); // the QR is gone (404): a new one
    const fresh = (await send(app, poll.token, 'new@acme.com')).body;
    expect(fresh.touchque.enroll.qrCodeDataUrl).not.toBe(qr.qrCodeDataUrl);
    expect(fresh.touchque.enroll.recoveryCodes).not.toEqual(qr.recoveryCodes);

    tq.link('new@acme.com');
    expect((await send(app, fresh.token, 'new@acme.com')).body.touchque.state).toBe('waiting');

    tq.secretTtlMs = 1000; // within 15 s of its expiry from the start
    tq.unlink('late@acme.com');
    const late = (await send(app, undefined, 'late@acme.com')).body;
    const replaced = (await send(app, late.token, 'late@acme.com')).body;
    expect(replaced.touchque.enroll.qrCodeDataUrl).not.toBe(late.touchque.enroll.qrCodeDataUrl);
  });

  test('linked: false: only linked users get a push; enroll: false answers enrollment_off', async () => {
    const tq = new FakeTouchque({ linked: false });
    expect(tq.isLinked('jane@acme.com')).toBe(false);
    const off = await runGuard(tq, { user: 'jane@acme.com', action: 'LOGIN', enroll: false });
    expect(off.body!.touchque).toEqual({ state: 'enroll', reason: 'enrollment_off' });
    tq.link('jane@acme.com');
    expect((await runGuard(tq, { user: 'jane@acme.com', action: 'LOGIN' })).body!.touchque.state).toBe('waiting');
  });

  test('a link check that fails is unavailable; a failing errorBody logs through the fake\'s logger', async () => {
    const logger = { warn: vi.fn(), error: vi.fn() };
    const tq = new FakeTouchque({ linked: false, logger });
    const app = makeApp(tq, { errorBody: (r: GuardRefusal) => { throw new Error(`no shape for ${r.code}`); } });
    const first = (await send(app)).body;
    expect(first.touchque.state).toBe('enroll');
    vi.spyOn(tq.auth, 'getUser').mockRejectedValue(new TouchqueAPIError(500, { error: 'down' }));
    const res = await send(app, first.token);
    expect(res.status).toBe(503);
    expect(res.body.touchque.reason).toBe('unavailable');
    expect(logger.error).toHaveBeenCalledWith('[Touchque] errorBody failed: Error: no shape for unavailable');
  });

  test('offline codes and calls it does not answer', async () => {
    const tq = new FakeTouchque();
    const app = makeApp(tq);
    const first = (await send(app)).body;
    const qr = (await send(app, first.token, 'jane@acme.com', { 'X-Touchque-Offline': '1' })).body;
    expect(qr.touchque.state).toBe('offline');
    const wrong = await send(app, qr.token, 'jane@acme.com', { 'X-Touchque-Code': 'WRONG' });
    expect(wrong.body.touchque.offline.attemptsLeft).toBe(4);
    const done = await send(app, qr.token, 'jane@acme.com', { 'X-Touchque-Code': tq.offlineCode });
    expect(done.status).toBe(200);
    expect(done.body.touchque.confirmedVia).toBe('OFFLINE_CODE');

    const totp = (await send(app)).body;
    tq.totpCode = '654321';
    const byTotp = await send(app, totp.token, 'jane@acme.com', { 'X-Touchque-Code': '654321', 'X-Touchque-Code-Type': 'totp' });
    expect(byTotp.body.touchque.confirmedVia).toBe('OFFLINE_TOTP');

    await tq.actionTypes.define('EXPORT', { name: 'Export data', critical: true });
    expect((await tq.actionTypes.list())[0]).toMatchObject({ type: 'EXPORT', name: 'Export data', critical: true, active: true });
    await expect(tq.recovery.list({ open: true })).rejects.toMatchObject({ name: 'TouchqueAPIError', status: 404 });
    expect(tq.calls.at(-1)).toEqual({ method: 'GET', path: '/recovery', body: {} });
  });
});

describe('FakeTouchque — 2FA setup context', () => {
  const IPHONE = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1';
  const FIREFOX = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0';
  /** A partner app behind one proxy of its own: req.ip is the address that proxy saw. */
  const proxiedApp = (tq: FakeTouchque) => makeApp(tq).set('trust proxy', 1);
  const refusal = (tq: FakeTouchque, secret: string) => tq.auth.validateSecret({ secret })
    .then(() => null, (e: TouchqueAPIError) => [e.status, e.data.reason ?? e.data.error]);

  test('setups keeps the browser the guard named for the first-time QR; validateSecret shows it as the phone does', async () => {
    const tq = new FakeTouchque();
    tq.unlink('new@acme.com');
    const first = await send(proxiedApp(tq), undefined, 'new@acme.com', { 'X-Forwarded-For': '1.2.3.4, 203.0.113.7', 'User-Agent': IPHONE });
    expect(first.body.touchque.state).toBe('enroll');
    expect(tq.setups).toEqual([{
      user: 'new@acme.com', secret: expect.any(String), clientIp: '203.0.113.7', userAgent: IPHONE,
      requestedAt: expect.any(String), expiresAt: first.body.touchque.enroll.expiresAt,
    }]);
    const [setup] = tq.setups;
    expect(Date.parse(setup.requestedAt)).toBeLessThanOrEqual(Date.now());
    expect(await tq.auth.validateSecret({ secret: setup.secret })).toEqual({
      valid: true, externalUsername: 'new@acme.com', integrationId: 'int-1',
      integration: { companyName: 'Fake workspace', icon: 'key-outline', color: '#007AFF', logo: null, logoDark: null, logoVersion: null },
      setupContext: {
        ip: '203.0.113.7', location: { city: 'Berlin', country: 'Germany', countryCode: 'DE' },
        device: { browser: 'Safari', os: 'iOS', model: 'iPhone' }, requestedAt: setup.requestedAt, farFromPhone: null,
      },
    });
    expect(tq.calls.at(-1)).toEqual({ method: 'POST', path: '/auth/secret/validate', body: { secret: setup.secret } });
  });

  test('a renewed QR keeps the browser of the poll that renewed it', async () => {
    const tq = new FakeTouchque();
    tq.secretTtlMs = 1000; // within 15 s of its expiry from the start
    tq.unlink('late@acme.com');
    const app = proxiedApp(tq);
    const late = (await send(app, undefined, 'late@acme.com', { 'X-Forwarded-For': '203.0.113.7', 'User-Agent': IPHONE })).body;
    const renewed = (await send(app, late.token, 'late@acme.com', { 'X-Forwarded-For': '198.51.100.23', 'User-Agent': FIREFOX })).body;
    expect(renewed.touchque.enroll.qrCodeDataUrl).not.toBe(late.touchque.enroll.qrCodeDataUrl);
    expect(tq.setups.map((x) => [x.clientIp, x.userAgent])).toEqual([['203.0.113.7', IPHONE], ['198.51.100.23', FIREFOX]]);
    expect((await tq.auth.validateSecret({ secret: tq.setups[1].secret })).setupContext).toMatchObject({
      ip: '198.51.100.23', location: { city: 'New York', country: 'United States', countryCode: 'US' }, device: { browser: 'Firefox', os: 'Windows', model: null },
    });
    expect(await refusal(tq, tq.setups[0].secret)).toEqual([404, 'not_found']); // replaced by the new QR
  });

  test('kept and shown as the API does: no loopback or private address, port and ::ffff: dropped, no device for a non-browser', async () => {
    const tq = new FakeTouchque({ linked: false });
    const contextFor = async (clientIp?: string, userAgent?: string) => {
      const { secret } = await tq.auth.generateSecret({ externalUsername: `u${tq.setups.length}@acme.com`, clientIp, userAgent });
      return (await tq.auth.validateSecret({ secret })).setupContext;
    };
    expect(await contextFor()).toBeNull();
    expect(await contextFor('127.0.0.1')).toBeNull();
    expect(await contextFor('::ffff:127.0.0.1', '')).toBeNull();
    expect(await contextFor('::ffff:198.51.100.23', FIREFOX)).toMatchObject({
      ip: '198.51.100.23', location: { city: 'New York', country: 'United States', countryCode: 'US' }, device: { browser: 'Firefox', os: 'Windows', model: null },
    });
    expect(await contextFor(' 203.0.113.7:51234 ')).toMatchObject({ ip: '203.0.113.7', location: { city: 'Berlin' }, device: null, farFromPhone: null });
    expect(await contextFor('[2001:db8::1]:443')).toMatchObject({ ip: '2001:db8::1', location: null });
    expect(await contextFor('192.168.1.20', IPHONE)).toMatchObject({ ip: null, location: null, device: { browser: 'Safari', os: 'iOS', model: 'iPhone' } });
    expect(await contextFor('not an address', 'curl/8.4.0')).toMatchObject({ ip: null, location: null, device: null });
    expect(await contextFor(undefined, `\u0001${IPHONE}\u007f`)).toMatchObject({ ip: null, device: { browser: 'Safari', os: 'iOS' } });
    // Recorded as the app sent them, whatever the phone is shown.
    expect(tq.setups.slice(1, 3).map((x) => x.clientIp)).toEqual(['127.0.0.1', '::ffff:127.0.0.1']);
    tq.setupContextNull = true; // an older QR, or a server before setup context
    expect(await contextFor('203.0.113.7', IPHONE)).toBeNull();
  });

  test('validateSecret answers like the API: 400, 404 (unknown, replaced, gone), 409 once linked, 410 once expired', async () => {
    const tq = new FakeTouchque({ linked: false });
    expect(await refusal(tq, '')).toEqual([400, 'secret is required']);
    expect(await refusal(tq, 'nope')).toEqual([404, 'not_found']);

    const first = await tq.auth.generateSecret({ externalUsername: 'a@acme.com' });
    const reset = await tq.auth.resetSecret({ externalUsername: 'a@acme.com' });
    expect(await refusal(tq, first.secret)).toEqual([404, 'not_found']);
    expect(await tq.auth.validateSecret({ secret: reset.secret })).toMatchObject({ valid: true, externalUsername: 'a@acme.com', setupContext: null });
    tq.link('a@acme.com');
    expect(await refusal(tq, reset.secret)).toEqual([409, 'already_used']);

    const late = await tq.auth.generateSecret({ externalUsername: 'b@acme.com' });
    tq.setups.at(-1)!.expiresAt = new Date(Date.now() - 1000).toISOString();
    expect(await refusal(tq, late.secret)).toEqual([410, 'expired']);

    const gone = await tq.auth.generateSecret({ externalUsername: 'c@acme.com' });
    tq.unlink('c@acme.com'); // the QR is gone
    expect(await refusal(tq, gone.secret)).toEqual([404, 'not_found']);
  });

  test('generate and reset answer as before, and record what was sent', async () => {
    const tq = new FakeTouchque({ linked: false });
    const gen = await tq.auth.generateSecret({ externalUsername: 'a@acme.com', clientIp: '203.0.113.7' });
    expect(Object.keys(gen)).toEqual(['secret', 'qrCodeDataUrl', 'externalUsername', 'expiresAt', 'ttlMs', 'recoveryCodes']);
    await expect(tq.auth.generateSecret({ externalUsername: 'a@acme.com', userAgent: FIREFOX })).rejects.toMatchObject({ status: 409 });
    const reset = await tq.auth.resetSecret({ externalUsername: 'a@acme.com', userAgent: FIREFOX });
    expect(Object.keys(reset)).toEqual(['success', 'secret', 'qrCodeDataUrl', 'externalUsername', 'expiresAt', 'ttlMs', 'recoveryCodes']);
    expect(tq.calls.map((c) => c.body)).toEqual([
      { externalUsername: 'a@acme.com', clientIp: '203.0.113.7' },
      { externalUsername: 'a@acme.com', userAgent: FIREFOX },
      { externalUsername: 'a@acme.com', userAgent: FIREFOX },
    ]);
    expect(tq.setups.map((x) => [x.secret, x.clientIp, x.userAgent])).toEqual([[gen.secret, '203.0.113.7', null], [reset.secret, null, FIREFOX]]);
  });
});

// The README's "Testing your routes" example, as written there.
describe('README: Testing your routes', () => {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { (req as any).user = { email: 'jane@acme.com' }; next(); }); // your sign-in
  app.post('/transfer',
    requireTouchque('SEND_MONEY', { details: (req) => ({ Amount: `${req.body.amount} EUR` }) }),
    (_req, res) => res.json({ ok: true }));

  let tq: FakeTouchque;
  beforeEach(() => { tq = new FakeTouchque().install(); }); // routes with no `client` use it
  afterEach(() => tq.uninstall());

  test('a transfer waits for the approval on the phone', async () => {
    const first = await request(app).post('/transfer').send({ amount: 5 });
    expect(first.status).toBe(202);
    expect(first.body.touchque.state).toBe('waiting');

    tq.approve(); // the person approves on the phone
    const done = await request(app).post('/transfer').set('X-Touchque-Token', first.body.token).send({ amount: 5 });
    expect(done.status).toBe(200);
    expect(tq.requests.at(-1)?.details).toEqual([{ label: 'Amount', value: '5 EUR' }]);
  });
});
