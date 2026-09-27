import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest';
import express from 'express';
import request from 'supertest';
import { requireTouchQue } from './express';
import { startFakeApi, FakeApi } from '../testing/fakeApi';

let api: FakeApi;
beforeEach(async () => { api = await startFakeApi(); });
afterEach(async () => { await api.close(); });

/** A partner app: one protected route, the signed-in user comes from a header. */
function partnerApp(action = 'SEND_MONEY', extra: Record<string, unknown> = {}) {
  const app = express();
  app.use(express.json());
  const handler = vi.fn((req: any, res: any) => res.json({ done: true, touchque: req.touchque }));
  app.post('/transfer',
    requireTouchQue(action, {
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

describe('requireTouchQue — one line, full flow', () => {
  test('no signed-in user → 401, nothing sent to TouchQue', async () => {
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
    expect(blocked.body.touchque).toEqual({ state: 'blocked', reason: 'geo_policy' });
  });

  test('an undefined action is a clear configuration error, not a user-facing message', async () => {
    api.linked.add('jane@acme.com');
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const { app } = partnerApp('NOT_DEFINED');
    const res = await send(app, { amount: 1 });
    expect(res.status).toBe(500);
    expect(res.body.error.code).toBe('misconfigured');
    expect(spy.mock.calls[0][0]).toContain("tq.actions.define('NOT_DEFINED')");
    spy.mockRestore();
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

  test('offline time-based code (no camera)', async () => {
    api.linked.add('jane@acme.com');
    const { app } = partnerApp('LOGIN');
    const start = await send(app, {});
    const ok = await send(app, {}, { 'x-touchque-token': start.body.token, 'x-touchque-code': '123456', 'x-touchque-code-type': 'totp' });
    expect(ok.status).toBe(200);
    expect(ok.body.touchque.assurance.method).toBe('offline_totp');
  });

  test('legacy signature requireTouchQue(tq, action, { getUserId }) still works', async () => {
    api.linked.add('a@b.com');
    const app = express();
    app.use(express.json());
    app.post('/x', requireTouchQue(api.client, 'LOGIN', { getUserId: () => 'a@b.com' }), (_req, res) => res.json({ ok: true }));
    const res = await request(app).post('/x').send({});
    expect(res.status).toBe(202);
    expect(res.body.touchque.state).toBe('waiting');
  });
});
