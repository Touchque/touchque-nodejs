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
