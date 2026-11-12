import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest';
import express from 'express';
import request from 'supertest';
import { requireTouchque } from './express';
import { startFakeApi, FakeApi } from '../testing/fakeApi';
import { Touchque, GuardRefusal } from '../index';

let api: FakeApi;
beforeEach(async () => { api = await startFakeApi(); });
afterEach(async () => { await api.close(); });

/** A partner app: one protected route, the signed-in user comes from a header. */
function partnerApp(action = 'SEND_MONEY', extra: Record<string, unknown> = {}) {
  const app = express();
  app.use(express.json());
  const handler = vi.fn((req: any, res: any) => res.json({ done: true, touchque: req.touchque }));
  app.post('/transfer',
    requireTouchque(action, {
      client: api.client,
      user: (req) => req.get('x-user') || undefined,
      details: (req) => ({ Amount: `${req.body.amount} EUR` }),
      ...extra,
    }),
    handler);
  return { app, handler };
}
const send = (app: express.Express, body: object, headers: Record<string, string> = {}) =>
  request(app).post('/transfer').set({ 'x-user': 'jane@acme.com', ...headers }).send(body);

describe('requireTouchque — one line, full flow', () => {
  test('no signed-in user → 401, nothing sent to Touchque', async () => {
    const { app, handler } = partnerApp();
    const res = await request(app).post('/transfer').send({ amount: 5 });
    expect(res.status).toBe(401);
    expect(res.body.touchque.reason).toBe('unauthenticated');
    expect(api.calls).toHaveLength(0);
    expect(handler).not.toHaveBeenCalled();
  });

  test('no phone linked yet → 202 enroll with a QR; after linking the same token starts the approval', async () => {
    const { app } = partnerApp();
    const first = await send(app, { amount: 5 });
    expect(first.status).toBe(202);
    expect(first.body.touchque.state).toBe('enroll');
    expect(first.body.touchque.enroll.qrCodeDataUrl).toContain('QR-jane@acme.com');
    api.linked.add('jane@acme.com');
    const second = await send(app, { amount: 5 }, { 'x-touchque-token': first.body.token });
    expect(second.status).toBe(202);
    expect(second.body.touchque.state).toBe('waiting');
  });

  test('never replaces a linked phone to show an enrollment QR', async () => {
    api.pendingSecrets.add('jane@acme.com'); // issued earlier, then linked by a race
    const { app } = partnerApp();
    api.linked.add('someone-else'); // unrelated
    const res = await send(app, { amount: 5 });
    expect(res.body.touchque.state).toBe('enroll');
    expect(api.calls.some((c) => c.path === '/auth/secret/reset')).toBe(true); // not linked → fresh QR is fine
    api.linked.add('jane@acme.com');
    api.calls.length = 0;
    await send(app, { amount: 5 });
    expect(api.calls.some((c) => c.path === '/auth/secret/reset')).toBe(false);
  });

  test('critical action: the matching number is in the FIRST response, before approval', async () => {
    api.linked.add('jane@acme.com');
    const { app, handler } = partnerApp();
    const res = await send(app, { amount: 250 });
    expect(res.status).toBe(202);
    expect(res.body.touchque).toMatchObject({ state: 'waiting', number: '47', details: [{ label: 'Amount', value: '250 EUR' }] });
    expect(typeof res.body.token).toBe('string');
    expect(handler).not.toHaveBeenCalled();
    const again = await send(app, { amount: 250 }, { 'x-touchque-token': res.body.token });
    expect(again.status).toBe(202);
    expect(again.body.touchque.number).toBe('47'); // still shown while waiting
  });

  test('approved → the route runs exactly once with req.touchque; replaying the token does not run it again', async () => {
    api.linked.add('jane@acme.com');
    const { app, handler } = partnerApp();
    const start = await send(app, { amount: 250 });
    api.approve();
    const done = await send(app, { amount: 250 }, { 'x-touchque-token': start.body.token });
    expect(done.status).toBe(200);
    expect(done.body.done).toBe(true);
    expect(done.body.touchque).toMatchObject({ user: 'jane@acme.com', action: 'SEND_MONEY', assurance: { method: 'push' } });
    const replay = await send(app, { amount: 250 }, { 'x-touchque-token': start.body.token });
    expect(replay.status).toBe(408);
    expect(replay.body.touchque.state).toBe('expired');
    expect(handler).toHaveBeenCalledTimes(1);
  });

  test('an approval for 250 EUR cannot pay 9,999 EUR, and cannot be used by another user', async () => {
    api.linked.add('jane@acme.com');
    api.linked.add('mallory@acme.com');
    const { app, handler } = partnerApp();
    const start = await send(app, { amount: 250 });
    api.approve();
    const bigger = await send(app, { amount: 9999 }, { 'x-touchque-token': start.body.token });
    expect(bigger.status).toBe(202); // a NEW approval for the new amount
    expect(bigger.body.touchque.details).toEqual([{ label: 'Amount', value: '9999 EUR' }]);
    const other = await send(app, { amount: 250 }, { 'x-touchque-token': start.body.token, 'x-user': 'mallory@acme.com' });
    expect(other.status).toBe(202);
    expect(handler).not.toHaveBeenCalled();
  });

  test('a tampered token is ignored', async () => {
    api.linked.add('jane@acme.com');
    const { app, handler } = partnerApp();
    const start = await send(app, { amount: 250 });
    api.approve();
    const [v, body, mac] = start.body.token.split('.');
    const forged = `${v}.${body}.${mac.slice(0, -2)}AA`;
    const res = await send(app, { amount: 250 }, { 'x-touchque-token': forged });
    expect(res.status).toBe(202);
    expect(handler).not.toHaveBeenCalled();
  });

  test('rejected on the phone → 403 rejected', async () => {
    api.linked.add('jane@acme.com');
    const { app } = partnerApp();
    const start = await send(app, { amount: 1 });
    api.reject();
    const res = await send(app, { amount: 1 }, { 'x-touchque-token': start.body.token });
    expect(res.status).toBe(403);
    expect(res.body.touchque.state).toBe('rejected');
  });

  test('passkey-only policy → 202 passkey_required; a passkey approval is phishing-resistant', async () => {
    api.linked.add('jane@acme.com');
    api.opts.passkeyOnly = true;
    const { app } = partnerApp();
    const start = await send(app, { amount: 1 });
    expect(start.body.touchque).toMatchObject({ state: 'passkey_required' });
    expect(start.body.touchque.requestId).toBeTruthy();
    expect(start.body.touchque.number).toBeUndefined();
    api.approve(undefined, 'WEBAUTHN');
    const done = await send(app, { amount: 1 }, { 'x-touchque-token': start.body.token });
    expect(done.status).toBe(200);
    expect(done.body.touchque.assurance).toEqual({ phishingResistant: true, method: 'passkey' });
  });

  test('frozen → 423 + Retry-After, rate limited → 429 + Retry-After, policy → 403 with reason', async () => {
    api.linked.add('jane@acme.com');
    const { app } = partnerApp();
    api.opts.frozen = true;
    const frozen = await send(app, { amount: 1 });
    expect(frozen.status).toBe(423);
    expect(frozen.headers['retry-after']).toBe('900');
    api.opts.frozen = false;
    api.opts.rateLimited = true;
    const limited = await send(app, { amount: 1 });
    expect(limited.status).toBe(429);
    expect(limited.headers['retry-after']).toBe('60');
    api.opts.rateLimited = false;
    api.opts.blocked = 'geo_policy';
    const blocked = await send(app, { amount: 1 });
    expect(blocked.status).toBe(403);
    expect(blocked.body.touchque).toEqual({ state: 'blocked', reason: 'geo_policy', caseCode: 'REF-USE' });
  });

  test('an undefined action is a clear configuration error, not a user-facing message; logged only through the logger', async () => {
    api.linked.add('jane@acme.com');
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const { app } = partnerApp('NOT_DEFINED');
      const res = await send(app, { amount: 1 });
      expect(res.status).toBe(500);
      expect(res.body.error.code).toBe('misconfigured');
      expect(spy).not.toHaveBeenCalled(); // silent by default

      const logger = { warn: vi.fn(), error: vi.fn() };
      const client = new Touchque({ apiKey: 'tq_test_key', apiSecret: 'test_secret', baseUrl: api.url, logger });
      const { app: logged } = partnerApp('NOT_DEFINED', { client });
      expect((await send(logged, { amount: 1 })).status).toBe(500);
      expect(logger.error.mock.calls[0][0]).toContain("tq.actionTypes.define('NOT_DEFINED')");
      expect(spy).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });

  test('offline: QR + typed code approves once; a wrong code keeps the challenge open', async () => {
    api.linked.add('jane@acme.com');
    const { app, handler } = partnerApp();
    const start = await send(app, { amount: 1 });
    const off = await send(app, { amount: 1 }, { 'x-touchque-token': start.body.token, 'x-touchque-offline': '1' });
    expect(off.status).toBe(202);
    expect(off.body.touchque).toMatchObject({ state: 'offline', offline: { qrDataUrl: 'data:image/png;base64,OFFLINE', totpAvailable: true } });
    const wrong = await send(app, { amount: 1 }, { 'x-touchque-token': off.body.token, 'x-touchque-code': 'ZZZZ999' });
    expect(wrong.status).toBe(202);
    expect(wrong.body.touchque.offline.attemptsLeft).toBe(4);
    const ok = await send(app, { amount: 1 }, { 'x-touchque-token': wrong.body.token, 'x-touchque-code': 'ABCD123' });
    expect(ok.status).toBe(200);
    expect(ok.body.touchque.assurance).toEqual({ phishingResistant: false, method: 'offline_code' });
    const again = await send(app, { amount: 1 }, { 'x-touchque-token': wrong.body.token, 'x-touchque-code': 'ABCD123' });
    expect(again.status).not.toBe(200);
    expect(handler).toHaveBeenCalledTimes(1);
  });

  test('a phone-side reject kills the offline QR: no code finishes it, no new QR, the page is told straight away', async () => {
    api.linked.add('jane@acme.com');
    const { app, handler } = partnerApp();
    const start = await send(app, { amount: 1 });
    const off = await send(app, { amount: 1 }, { 'x-touchque-token': start.body.token, 'x-touchque-offline': '1' });
    expect(off.body.touchque.state).toBe('offline');
    // The QR is linked to the push the user started.
    const qr = api.calls.filter((c) => c.path === '/offline/challenge').pop()!;
    expect(qr.body.requestId).toBe(start.body.touchque.requestId);

    // While the QR is up the page keeps polling; nothing changes until the phone answers.
    const poll = await send(app, { amount: 1 }, { 'x-touchque-token': off.body.token });
    expect(poll.status).toBe(202);
    expect(poll.body.touchque).toMatchObject({ state: 'offline', offline: { challengeId: off.body.touchque.offline.challengeId } });

    api.reject(); // the user taps Reject on the phone

    const rejected = await send(app, { amount: 1 }, { 'x-touchque-token': poll.body.token });
    expect(rejected.status).toBe(403);
    expect(rejected.body.touchque.state).toBe('rejected');

    // Even the right code from the QR that was already on screen does not finish it…
    const late = await send(app, { amount: 1 }, { 'x-touchque-token': off.body.token, 'x-touchque-code': 'ABCD123' });
    expect(late.status).toBe(403);
    expect(late.body.touchque).toMatchObject({ state: 'rejected', reason: 'request_rejected' });
    // …the time-based code doesn't either…
    const totp = await send(app, { amount: 1 }, { 'x-touchque-token': off.body.token, 'x-touchque-code': '123456', 'x-touchque-code-type': 'totp' });
    expect(totp.body.touchque.state).toBe('rejected');
    // …and pressing "offline mode" again gets no QR for that sign-in.
    const again = await send(app, { amount: 1 }, { 'x-touchque-token': start.body.token, 'x-touchque-offline': '1' });
    expect(again.body.touchque.state).toBe('rejected');
    expect(handler).not.toHaveBeenCalled();
  });

  test('offline QR with number matching: the page gets the number to print under the QR', async () => {
    api.linked.add('jane@acme.com');
    api.opts.numberMatch = true;
    const { app } = partnerApp();
    const start = await send(app, { amount: 1 });
    expect(start.body.touchque.number).toBe('47');
    const off = await send(app, { amount: 1 }, { 'x-touchque-token': start.body.token, 'x-touchque-offline': '1' });
    expect(off.body.touchque.offline.challengeCode).toBe('47');
  });

  test('offline time-based code (no camera)', async () => {
    api.linked.add('jane@acme.com');
    const { app } = partnerApp('LOGIN');
    const start = await send(app, {});
    const ok = await send(app, {}, { 'x-touchque-token': start.body.token, 'x-touchque-code': '123456', 'x-touchque-code-type': 'totp' });
    expect(ok.status).toBe(200);
    expect(ok.body.touchque.assurance.method).toBe('offline_totp');
  });

  test('legacy signature requireTouchque(tq, action, { getUserId }) still works', async () => {
    api.linked.add('a@b.com');
    const app = express();
    app.use(express.json());
    app.post('/x', requireTouchque(api.client, 'LOGIN', { getUserId: () => 'a@b.com' }), (_req, res) => res.json({ ok: true }));
    const res = await request(app).post('/x').send({});
    expect(res.status).toBe(202);
    expect(res.body.touchque.state).toBe('waiting');
  });
});

/** The claims a guard token carries. */
const claimsOf = (token: string) => JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
const secretCalls = () => api.calls.filter((c) => c.path === '/auth/generate-secret' || c.path === '/auth/secret/reset');

describe('requireTouchque — first-time QR: one per enrollment, not one per poll', () => {
  test('polls keep the QR on screen (only the link state is read); once linked the approval starts', async () => {
    const { app, handler } = partnerApp();
    const first = await send(app, { amount: 5 });
    expect(first.status).toBe(202);
    const { enroll } = first.body.touchque;
    expect(enroll).toMatchObject({ qrCodeDataUrl: 'data:image/png;base64,QR-jane@acme.com', recoveryCodes: ['r1'] });
    const ee = Date.parse(enroll.expiresAt);
    expect(ee).toBeGreaterThan(Date.now() + 4 * 60_000); // the API's 5 minutes
    expect(claimsOf(first.body.token)).toMatchObject({ st: 'enroll', ee });

    api.calls.length = 0;
    let token = first.body.token;
    for (let i = 0; i < 3; i++) {
      const poll = await send(app, { amount: 5 }, { 'x-touchque-token': token });
      expect(poll.status).toBe(202);
      expect(poll.headers['cache-control']).toBe('no-store');
      expect(poll.body.touchque).toEqual({ state: 'enroll', expiresAt: new Date(ee).toISOString(), details: [{ label: 'Amount', value: '5 EUR' }] });
      expect(claimsOf(poll.body.token)).toMatchObject({ st: 'enroll', ee });
      token = poll.body.token;
    }
    expect(api.calls.map((c) => c.method)).toEqual(['GET', 'GET', 'GET']);
    expect(api.calls.every((c) => c.path.startsWith('/users/'))).toBe(true);

    api.linked.add('jane@acme.com'); // the phone scanned the QR
    const linked = await send(app, { amount: 5 }, { 'x-touchque-token': token });
    expect(linked.status).toBe(202);
    expect(linked.body.touchque).toMatchObject({ state: 'waiting', number: '47' });
    expect(secretCalls()).toHaveLength(0);
    expect(handler).not.toHaveBeenCalled();
  });

  test('a QR within 15 s of its expiry is replaced: the poll brings a new QR and codes', async () => {
    api.opts.secretTtlMs = 10_000;
    const { app } = partnerApp();
    const first = await send(app, { amount: 5 });
    expect(first.body.touchque.enroll.qrCodeDataUrl).toBe('data:image/png;base64,QR-jane@acme.com');
    const poll = await send(app, { amount: 5 }, { 'x-touchque-token': first.body.token });
    expect(poll.status).toBe(202);
    expect(poll.body.touchque.enroll).toMatchObject({ qrCodeDataUrl: 'data:image/png;base64,QR2-jane@acme.com', recoveryCodes: ['r2'] });
    expect(claimsOf(poll.body.token).ee).toBe(Date.parse(poll.body.touchque.enroll.expiresAt));
    expect(secretCalls().map((c) => c.path)).toEqual(['/auth/generate-secret', '/auth/generate-secret', '/auth/secret/reset']);
  });

  test('a QR that is gone (the link state answers 404) is replaced too', async () => {
    const { app } = partnerApp();
    const first = await send(app, { amount: 5 });
    api.pendingSecrets.delete('jane@acme.com');
    const poll = await send(app, { amount: 5 }, { 'x-touchque-token': first.body.token });
    expect(poll.body.touchque.enroll.qrCodeDataUrl).toBe('data:image/png;base64,QR-jane@acme.com');
    expect(secretCalls().map((c) => c.path)).toEqual(['/auth/generate-secret', '/auth/generate-secret']);
  });
});

describe('requireTouchque — errorBody (your own error shape)', () => {
  test('an object is sent with the step as `touchque` (the SDK key wins) and no token; status and headers stay', async () => {
    api.linked.add('jane@acme.com');
    const errorBody = vi.fn((r: GuardRefusal) => ({ message: r.message, code: r.code, touchque: 'mine' }));
    const { app } = partnerApp('SEND_MONEY', { errorBody });
    const start = await send(app, { amount: 1 });
    api.reject();
    const res = await send(app, { amount: 1 }, { 'x-touchque-token': start.body.token });
    expect(res.status).toBe(403);
    expect(res.headers['content-type']).toMatch(/^application\/json/);
    expect(res.headers['cache-control']).toBe('no-store');
    const step = { state: 'rejected', requestId: start.body.touchque.requestId, details: [{ label: 'Amount', value: '1 EUR' }] };
    expect(res.body).toEqual({ message: 'The approval was rejected.', code: 'rejected', touchque: step });
    expect(errorBody.mock.calls).toEqual([[{ status: 403, code: 'rejected', message: 'The approval was rejected.', touchque: step }]]);
  });

  test('never called for a 202 step or on approval', async () => {
    api.linked.add('jane@acme.com');
    const errorBody = vi.fn(() => ({ shaped: true }));
    const { app, handler } = partnerApp('SEND_MONEY', { errorBody });
    const start = await send(app, { amount: 1 });
    expect(start.status).toBe(202);
    expect(start.body).toMatchObject({ touchque: { state: 'waiting' }, token: expect.any(String) });
    api.approve();
    expect((await send(app, { amount: 1 }, { 'x-touchque-token': start.body.token })).status).toBe(200);
    expect(handler).toHaveBeenCalledTimes(1);
    expect(errorBody).not.toHaveBeenCalled();
  });

  test('code and message for each refusal; Retry-After stays', async () => {
    api.linked.add('jane@acme.com');
    const seen: GuardRefusal[] = [];
    const { app } = partnerApp('SEND_MONEY', { errorBody: (r: GuardRefusal) => { seen.push(r); return { error: r.code }; } });
    const unknown = partnerApp('NOT_DEFINED', { errorBody: (r: GuardRefusal) => { seen.push(r); return { error: r.code }; } }).app;
    expect((await request(app).post('/transfer').send({ amount: 1 })).status).toBe(401);
    api.opts.frozen = true;
    const frozen = await send(app, { amount: 1 });
    expect(frozen.headers['retry-after']).toBe('900');
    expect(frozen.body).toMatchObject({ error: 'frozen', touchque: { state: 'frozen', retryAfter: 900 } });
    api.opts.frozen = false;
    api.opts.rateLimited = true;
    expect((await send(app, { amount: 1 })).headers['retry-after']).toBe('60');
    api.opts.rateLimited = false;
    api.opts.blocked = 'geo_policy';
    await send(app, { amount: 1 });
    api.opts.blocked = undefined;
    const start = await send(app, { amount: 1 });
    api.approve();
    await send(app, { amount: 1 }, { 'x-touchque-token': start.body.token });
    expect((await send(app, { amount: 1 }, { 'x-touchque-token': start.body.token })).status).toBe(408);
    expect((await send(unknown, { amount: 1 })).status).toBe(500);
    expect(seen.map(({ status, code, message }) => [status, code, message])).toEqual([
      [401, 'unauthenticated', 'Sign in first.'],
      [423, 'frozen', 'Too many rejected approvals. Try again later.'],
      [429, 'rate_limited', 'Too many attempts. Try again later.'],
      [403, 'geo_policy', 'The approval was refused.'],
      [408, 'already_used', 'The approval expired. Try again.'],
      [500, 'misconfigured', 'Two-factor approval is not configured correctly.'],
    ]);
  });

  test('anything but an object is sent as it is; undefined keeps the default body', async () => {
    const answer = async (shape: unknown) => {
      const { app } = partnerApp('SEND_MONEY', { errorBody: async () => shape });
      return request(app).post('/transfer').send({ amount: 1 });
    };
    for (const [shape, text] of [['Sign in first', '"Sign in first"'], [['a', 1], '["a",1]'], [null, 'null'], [7, '7']] as const) {
      const res = await answer(shape);
      expect(res.status).toBe(401);
      expect(res.headers['content-type']).toMatch(/^application\/json/);
      expect(res.text).toBe(text);
    }
    expect((await answer(undefined)).body).toEqual({
      touchque: { state: 'blocked', reason: 'unauthenticated' }, error: { code: 'unauthenticated', message: 'Sign in first.' },
    });
  });

  test('an object is what encodes to a JSON object: a class instance, toJSON(), a Map', async () => {
    class Problem { constructor(public title: string) {} }
    const answer = async (shape: unknown) => {
      const { app } = partnerApp('SEND_MONEY', { errorBody: () => shape });
      return request(app).post('/transfer').send({ amount: 1 });
    };
    const step = { state: 'blocked', reason: 'unauthenticated' };
    expect((await answer(new Problem('Sign in'))).body).toEqual({ title: 'Sign in', touchque: step });
    expect((await answer({ toJSON: () => ({ title: 'Sign in' }) })).body).toEqual({ title: 'Sign in', touchque: step });
    expect((await answer(new Map([['title', 'Sign in']]))).body).toEqual({ title: 'Sign in', touchque: step });
    expect((await answer({ toJSON: () => 'Sign in' })).text).toBe('"Sign in"');
    expect((await answer(new Date(0))).text).toBe('"1970-01-01T00:00:00.000Z"');
  });

  test('the result is judged with the app\'s own JSON replacer, and sent without a second pass', async () => {
    const logger = { warn: vi.fn(), error: vi.fn() };
    const client = new Touchque({ apiKey: 'tq_test_key', apiSecret: 'test_secret', baseUrl: api.url, logger });
    const answer = (replacer: (this: any, key: string, value: any) => any, shape: unknown) => {
      const { app } = partnerApp('SEND_MONEY', { client, errorBody: () => shape });
      app.set('json replacer', replacer);
      app.set('json spaces', 2);
      return request(app).post('/transfer').send({ amount: 1 });
    };
    const step = { state: 'blocked', reason: 'unauthenticated' };
    const bigint = await answer((_k, v) => (typeof v === 'bigint' ? v.toString() : v), { amount: 10n });
    expect(bigint.status).toBe(401);
    expect(bigint.body).toEqual({ amount: '10', touchque: step });
    const date = await answer(function (this: any, k, v) { return this[k] instanceof Date ? this[k].getTime() : v; }, { at: new Date(0) });
    expect(date.body).toEqual({ at: 0, touchque: step });
    expect(date.text.startsWith('{\n  "at": 0,')).toBe(true);
    expect(logger.error).not.toHaveBeenCalled();
  });

  test('a result JSON cannot encode takes the throwing path: the default body, logged', async () => {
    const logger = { warn: vi.fn(), error: vi.fn() };
    const client = new Touchque({ apiKey: 'tq_test_key', apiSecret: 'test_secret', baseUrl: api.url, logger });
    const cycle: Record<string, unknown> = {};
    cycle.self = cycle;
    for (const shape of [{ n: 10n }, cycle, { toJSON() { throw new Error('nope'); } }, () => 'x']) {
      const { app } = partnerApp('SEND_MONEY', { client, errorBody: () => shape });
      const res = await request(app).post('/transfer').send({ amount: 1 });
      expect(res.status).toBe(401);
      expect(res.body.error).toEqual({ code: 'unauthenticated', message: 'Sign in first.' });
    }
    expect(logger.error.mock.calls.map(([line]) => String(line).split(':')[0])).toEqual(Array(4).fill('[Touchque] errorBody failed'));
  });

  test('the callback gets a copy of the step: changing it changes nothing that is sent', async () => {
    api.linked.add('jane@acme.com');
    const { app } = partnerApp('SEND_MONEY', {
      errorBody: (r: GuardRefusal) => {
        r.touchque.state = 'approved';
        r.touchque.details![0].value = '9999 EUR';
        return { ok: false };
      },
    });
    const start = await send(app, { amount: 1 });
    api.reject();
    const res = await send(app, { amount: 1 }, { 'x-touchque-token': start.body.token });
    expect(res.body).toEqual({ ok: false, touchque: { state: 'rejected', requestId: start.body.touchque.requestId, details: [{ label: 'Amount', value: '1 EUR' }] } });
  });

  test('a callback that throws: the default body, and the error goes to the client logger', async () => {
    const logger = { warn: vi.fn(), error: vi.fn() };
    const client = new Touchque({ apiKey: 'tq_test_key', apiSecret: 'test_secret', baseUrl: api.url, logger });
    const { app } = partnerApp('SEND_MONEY', { client, errorBody: () => { throw new Error('boom'); } });
    const res = await request(app).post('/transfer').send({ amount: 1 });
    expect(res.status).toBe(401);
    expect(res.body.error).toEqual({ code: 'unauthenticated', message: 'Sign in first.' });
    expect(logger.error).toHaveBeenCalledWith('[Touchque] errorBody failed: Error: boom');
  });
});

describe('requireTouchque — refusal headers', () => {
  test('every answer of 400 or more names its state (and reason) in headers, whatever the body; a 202 does not', async () => {
    api.linked.add('jane@acme.com');
    const { app } = partnerApp('SEND_MONEY', { errorBody: (r: GuardRefusal) => r.message });
    const start = await send(app, { amount: 1 });
    expect(start.status).toBe(202);
    expect(start.headers['x-touchque-state']).toBeUndefined();
    api.opts.blocked = 'geo_policy';
    const blocked = await send(app, { amount: 1 });
    expect(blocked.status).toBe(403);
    expect(blocked.text).toBe('"The approval was refused."');
    expect(blocked.headers['x-touchque-state']).toBe('blocked');
    expect(blocked.headers['x-touchque-reason']).toBe('geo_policy');
    api.opts.blocked = undefined;
    api.reject();
    const rejected = await send(app, { amount: 1 }, { 'x-touchque-token': start.body.token });
    expect(rejected.headers['x-touchque-state']).toBe('rejected');
    expect(rejected.headers['x-touchque-reason']).toBeUndefined();
  });
});

// Last in this file: the final test leaves the default client built.
describe('requireTouchque — no TQ_API_KEY / TQ_API_SECRET', () => {
  let saved: NodeJS.ProcessEnv;
  beforeEach(() => {
    saved = { ...process.env };
    delete process.env.TQ_API_KEY;
    delete process.env.TQ_API_SECRET;
  });
  afterEach(() => { process.env = saved; });

  /** The partner app without a client: the guard builds one from the environment. */
  function envApp(extra: Record<string, unknown> = {}) {
    const app = express();
    app.use(express.json());
    const handler = vi.fn((_req: any, res: any) => res.json({ done: true }));
    app.post('/transfer', requireTouchque('SEND_MONEY', { user: (req) => req.get('x-user') || undefined, ...extra }), handler);
    return { app, handler };
  }

  test('a JSON answer, never a throw: 500 misconfigured for a signed-in user, 401 without one; the handler never runs', async () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const { app, handler } = envApp();
      const res = await send(app, { amount: 5 });
      expect(res.status).toBe(500);
      expect(res.headers['content-type']).toMatch(/^application\/json/);
      expect(res.headers['cache-control']).toBe('no-store');
      expect(res.headers['x-touchque-state']).toBe('blocked');
      expect(res.headers['x-touchque-reason']).toBe('misconfigured');
      expect(res.body).toEqual({
        touchque: { state: 'blocked', reason: 'misconfigured' },
        error: { code: 'misconfigured', message: 'Two-factor approval is not configured correctly.' },
      });
      const anonymous = await request(app).post('/transfer').send({ amount: 5 });
      expect(anonymous.status).toBe(401);
      expect(anonymous.body.touchque).toEqual({ state: 'blocked', reason: 'unauthenticated' });
      expect(handler).not.toHaveBeenCalled();
      expect(spy).not.toHaveBeenCalled(); // silent by default
    } finally {
      spy.mockRestore();
    }
  });

  test('errorBody shapes that 500 too', async () => {
    const { app } = envApp({ errorBody: (r: GuardRefusal) => ({ message: r.message, code: r.code }) });
    const res = await send(app, { amount: 5 });
    expect(res.status).toBe(500);
    expect(res.body).toEqual({
      message: 'Two-factor approval is not configured correctly.', code: 'misconfigured', touchque: { state: 'blocked', reason: 'misconfigured' },
    });
  });

  test('the client is built on a request once the keys are set, and kept', async () => {
    api.linked.add('jane@acme.com');
    const { app } = envApp();
    expect((await send(app, { amount: 5 })).status).toBe(500);
    Object.assign(process.env, { TQ_API_KEY: 'tq_test_key', TQ_API_SECRET: 'test_secret', TQ_API_URL: api.url });
    expect((await send(app, { amount: 5 })).body.touchque.state).toBe('waiting');
    delete process.env.TQ_API_KEY;
    expect((await send(app, { amount: 5 })).status).toBe(202);
  });
});
