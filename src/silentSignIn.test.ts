import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest';
import express from 'express';
import request from 'supertest';
import vectors from '../fixtures/silent-sign-in-vectors.json';
import { runGuard, withTouchQue, requireTouchQue, touchqueRouter, GUARD_HEADERS } from './index';
import { startFakeApi, FakeApi } from './testing/fakeApi';

// The proof as the browser sends it in X-TouchQue-Browser (base64url JSON) and its key's thumbprint.
const PROOF = (vectors.browserProof.cases.find((c) => c.name === 'validHeaderEncoding')!.proof as string);
const THUMBPRINT = vectors.browserProof.thumbprint.expected;
const SILENT_CODES = ['known_browser', 'recent_approval', 'same_phone', 'familiar_network', 'no_risk_signal'];

let api: FakeApi;
beforeEach(async () => { api = await startFakeApi(); api.linked.add('jane@acme.com'); });
afterEach(async () => { await api.close(); });

const paths = () => api.calls.map((c) => c.path);

describe('risk.check against the API', () => {
  test('a browser without a key, then a new browser, are asked; nothing goes to the phone', async () => {
    expect(await api.client.risk.check({ externalUsername: 'jane@acme.com' }))
      .toMatchObject({ prompt: true, assurance: 'normal', silentMode: 'enforce', reasons: [{ code: 'no_browser_key' }] });
    const res = await api.client.risk.check({ externalUsername: 'jane@acme.com', type: 'LOGIN', clientIp: '203.0.113.7', userAgent: 'UA', browserProof: PROOF, maxAgeSeconds: 3600 });
    expect(res).toMatchObject({ prompt: true, reasons: [{ code: 'new_browser', text: 'This browser has not been approved on the phone for this account' }] });
    expect(api.lastCheck).toEqual({ externalUsername: 'jane@acme.com', type: 'LOGIN', clientIp: '203.0.113.7', userAgent: 'UA', browserProof: PROOF, maxAgeSeconds: 3600 });
    expect(api.requests).toHaveLength(0);
  });

  test('silent: prompt false with the reasons; a critical action and an unlinked user still ask', async () => {
    api.opts.silent = true;
    const res = await api.client.risk.check({ externalUsername: 'jane@acme.com', browserProof: PROOF });
    expect(res.prompt).toBe(false);
    expect(res.assurance).toBe('high');
    expect(res.reasons.map((r) => r.code)).toEqual(SILENT_CODES);
    expect((await api.client.risk.check({ externalUsername: 'jane@acme.com', type: 'SEND_MONEY', browserProof: PROOF })).reasons)
      .toEqual([{ code: 'critical_action', text: 'The action is critical' }]);
    const unlinked = await api.client.risk.check({ externalUsername: 'nobody@acme.com', browserProof: PROOF });
    expect(unlinked).toMatchObject({ prompt: true, reasons: [{ code: 'phone_not_linked' }] });
  });

  test('login.request carries the proof; the approval makes the browser known until it is forgotten', async () => {
    const { requestId } = await api.client.login.request({ externalUsername: 'jane@acme.com', type: 'LOGIN', browserProof: PROOF });
    expect(api.calls.find((c) => c.path === '/login/request')!.body.browserProof).toBe(PROOF);
    expect((await api.client.risk.browsers({ externalUsername: 'jane@acme.com' })).browsers).toEqual([]);
    api.approve(requestId);
    const { browsers } = await api.client.risk.browsers({ externalUsername: 'jane@acme.com' });
    expect(browsers).toHaveLength(1);
    expect(browsers[0]).toMatchObject({ thumbprint: THUMBPRINT, lastMfaMethod: 'push', lastSilentAt: null });
    expect(await api.client.risk.forgetBrowsers({ externalUsername: 'jane@acme.com', thumbprint: 'other' })).toEqual({ forgotten: 0 });
    expect(await api.client.risk.forgetBrowsers({ externalUsername: 'jane@acme.com', thumbprint: THUMBPRINT })).toEqual({ forgotten: 1 });
    expect((await api.client.risk.browsers({ externalUsername: 'jane@acme.com' })).browsers).toEqual([]);
  });

  test('a provisional approval (during a call) does not make the browser known', async () => {
    await api.client.login.request({ externalUsername: 'jane@acme.com', type: 'LOGIN', browserProof: PROOF });
    api.approve(undefined, 'DEVICE', { provisional: true });
    expect((await api.client.risk.browsers({ externalUsername: 'jane@acme.com' })).browsers).toEqual([]);
  });
});

describe('guard: silentSignIn', () => {
  const input = { user: 'jane@acme.com', action: 'LOGIN', ip: '203.0.113.7', userAgent: 'UA', browserProof: PROOF, silentSignIn: true };

  test('a known browser with nothing new is approved at once, with no push', async () => {
    api.opts.silent = true;
    const res = await runGuard(api.client, input);
    expect(res.status).toBe(200);
    expect(res.approved).toMatchObject({
      requestId: 'silent', user: 'jane@acme.com', action: 'LOGIN', confirmedVia: 'SILENT',
      assurance: { phishingResistant: false, method: 'silent' },
    });
    expect(res.approved!.reasons!.map((r) => r.code)).toEqual(SILENT_CODES);
    expect(api.lastCheck).toEqual({ externalUsername: 'jane@acme.com', type: 'LOGIN', clientIp: '203.0.113.7', userAgent: 'UA', browserProof: PROOF });
    expect(paths()).toEqual(['/risk/check']);
  });

  test('otherwise the usual push starts, carrying the proof so its approval makes the browser known', async () => {
    const first = await runGuard(api.client, input);
    expect(first.status).toBe(202);
    expect(first.body!.touchque.state).toBe('waiting');
    expect(paths()).toEqual(['/risk/check', '/login/request']);
    expect(api.requests[0].browserProof).toBe(PROOF);
    // Polling with the token never asks again, even if the answer would now be silent.
    api.opts.silent = true;
    const poll = await runGuard(api.client, { ...input, token: first.body!.token });
    expect(poll.body!.touchque.state).toBe('waiting');
    expect(paths().filter((p) => p === '/risk/check')).toHaveLength(1);
    api.approve();
    const done = await runGuard(api.client, { ...input, token: first.body!.token });
    expect(done.approved).toMatchObject({ confirmedVia: 'DEVICE', assurance: { method: 'push' } });
    expect(api.browsers.map((b) => b.thumbprint)).toEqual([THUMBPRINT]);
  });

  test('a critical action always asks, with number matching', async () => {
    api.opts.silent = true;
    const res = await runGuard(api.client, { ...input, action: 'SEND_MONEY' });
    expect(res.body!.touchque).toMatchObject({ state: 'waiting', number: '47' });
    expect(api.lastCheck.type).toBe('SEND_MONEY');
  });

  test('fails closed: any error in the check starts the usual push', async () => {
    api.opts.silent = true;
    const spy = vi.spyOn(api.client.risk, 'check');
    for (const failure of [new Error('network down'), Object.assign(new Error('not found'), { status: 404 })]) {
      spy.mockRejectedValueOnce(failure);
      const res = await runGuard(api.client, input);
      expect(res.status).toBe(202);
      expect(res.body!.touchque.state).toBe('waiting');
    }
    // An answer that is not exactly `prompt: false` asks too.
    spy.mockResolvedValueOnce({ prompt: 'false' as never, reasons: [], assurance: 'high', silentMode: 'enforce' });
    expect((await runGuard(api.client, input)).body!.touchque.state).toBe('waiting');
    spy.mockRestore();
  });

  test('off by default, without a proof, or with a proof too large to be one: no check', async () => {
    api.opts.silent = true;
    expect((await runGuard(api.client, { ...input, silentSignIn: undefined })).status).toBe(202);
    expect(api.requests[0].browserProof).toBe(PROOF); // still attached: an approval makes the browser known
    expect((await runGuard(api.client, { ...input, browserProof: undefined })).status).toBe(202);
    expect((await runGuard(api.client, { ...input, browserProof: 'x'.repeat(5000) })).status).toBe(202);
    expect(api.requests[2].browserProof).toBeUndefined();
    expect(paths()).not.toContain('/risk/check');
  });

  test('{ maxAgeSeconds } is sent with the check', async () => {
    await runGuard(api.client, { ...input, silentSignIn: { maxAgeSeconds: 0 } });
    expect(api.lastCheck.maxAgeSeconds).toBe(0);
  });
});

describe('adapters read X-TouchQue-Browser only when silentSignIn is on', () => {
  function partnerApp(silentSignIn?: boolean) {
    const app = express();
    app.use(express.json());
    const handler = vi.fn((req: any, res: any) => res.json({ done: true, touchque: req.touchque }));
    app.post('/account', requireTouchQue('LOGIN', { client: api.client, user: () => 'jane@acme.com', silentSignIn }), handler);
    return { app, handler };
  }

  test('requireTouchQue: the handler runs at once for a known browser', async () => {
    api.opts.silent = true;
    const { app, handler } = partnerApp(true);
    const res = await request(app).post('/account').set('X-TouchQue-Browser', PROOF).send({});
    expect(res.status).toBe(200);
    expect(res.body.touchque).toMatchObject({ confirmedVia: 'SILENT', assurance: { method: 'silent' } });
    expect(handler).toHaveBeenCalledTimes(1);
    expect(api.lastCheck.browserProof).toBe(PROOF);
  });

  test('requireTouchQue without silentSignIn ignores the header', async () => {
    api.opts.silent = true;
    const { app, handler } = partnerApp();
    const res = await request(app).post('/account').set(GUARD_HEADERS.browser, PROOF).send({});
    expect(res.status).toBe(202);
    expect(handler).not.toHaveBeenCalled();
    expect(paths()).not.toContain('/risk/check');
    expect(api.requests[0].browserProof).toBeUndefined();
  });

  test('withTouchQue: ctx.touchque says silent', async () => {
    api.opts.silent = true;
    const route = withTouchQue('LOGIN', async (_req, { touchque }) => Response.json({ method: touchque.assurance?.method, reasons: touchque.reasons?.length }), {
      client: api.client, user: () => 'jane@acme.com', silentSignIn: true,
    });
    const res = await route(new Request('https://app.example.com/account', { method: 'POST', headers: { 'X-TouchQue-Browser': PROOF } }));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ method: 'silent', reasons: 5 });
  });

  test('touchqueRouter POST /login: success with via silent; a new browser gets the push with the proof', async () => {
    const onAuthenticated = vi.fn();
    const app = express();
    app.use(express.json());
    app.use('/touchque', touchqueRouter(api.client, {
      getUserId: () => undefined, getLoginUser: () => 'jane@acme.com', onAuthenticated, silentSignIn: true,
    }));
    const pushed = await request(app).post('/touchque/login').set('X-TouchQue-Browser', PROOF).send({});
    expect(pushed.status).toBe(202);
    expect(api.requests[0].browserProof).toBe(PROOF);
    expect(onAuthenticated).not.toHaveBeenCalled();

    api.opts.silent = true;
    const silent = await request(app).post('/touchque/login').set('X-TouchQue-Browser', PROOF).send({});
    expect(silent.status).toBe(200);
    expect(silent.body).toMatchObject({ status: 'success', requestId: 'silent', assurance: { method: 'silent' } });
    expect(onAuthenticated).toHaveBeenCalledTimes(1);
    expect(onAuthenticated.mock.calls[0][2]).toEqual({ externalUsername: 'jane@acme.com', requestId: 'silent', via: 'silent' });
    expect(api.requests).toHaveLength(1);
  });
});
