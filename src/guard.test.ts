// Guard 5.2: runGuard(null) uses the default client; guardResponse() is what the
// adapters send; waiting polls repeat expiresAt; enroll: false says why.
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest';
import express from 'express';
import request from 'supertest';
import {
  Touchque, runGuard, guardResponse, requireTouchque, withTouchque, getDefaultClient, setDefaultClient, signGuardToken, detailsDigest,
  GUARD_HEADERS, GuardRefusal, TouchqueConfigError,
} from './index';
import { isStatusPoll } from './guard';
import { startFakeApi, FakeApi } from './testing/fakeApi';

/** Forgets the default client, as if none had been built yet. */
const resetDefaultClient = () => setDefaultClient(null);
const claimsOf = (token: string) => JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));

let api: FakeApi;
let savedEnv: NodeJS.ProcessEnv;
beforeEach(async () => {
  api = await startFakeApi();
  api.linked.add('jane@acme.com');
  savedEnv = { ...process.env };
  delete process.env.TQ_API_KEY;
  delete process.env.TQ_API_SECRET;
  delete process.env.TQ_API_URL;
  resetDefaultClient();
});
afterEach(async () => {
  process.env = savedEnv;
  resetDefaultClient();
  await api.close();
});

describe('runGuard(null): the default client', () => {
  test('no keys: 401 without a user, else 500 misconfigured; nothing throws, nothing is logged', async () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const anonymous = await runGuard(null, { action: 'SEND_MONEY' });
      expect(anonymous).toEqual({
        status: 401, body: { touchque: { state: 'blocked', reason: 'unauthenticated' }, error: { code: 'unauthenticated', message: 'Sign in first.' } },
      });
      const signedIn = await runGuard(undefined, { user: 'jane@acme.com', action: 'SEND_MONEY' });
      expect(signedIn).toEqual({
        status: 500,
        body: { touchque: { state: 'blocked', reason: 'misconfigured' }, error: { code: 'misconfigured', message: 'Two-factor approval is not configured correctly.' } },
      });
      expect(isStatusPoll(null, { user: 'jane@acme.com', action: 'SEND_MONEY', token: 'v1.e30.x' })).toBe(false);
      expect(api.calls).toHaveLength(0);
      expect(spy).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });

  test('with keys: built from the environment on a request and kept; a failed build is tried again', async () => {
    expect((await runGuard(null, { user: 'jane@acme.com', action: 'LOGIN' })).status).toBe(500);
    Object.assign(process.env, { TQ_API_KEY: 'tq_test_key', TQ_API_SECRET: 'test_secret', TQ_API_URL: api.url });
    const first = await runGuard(null, { user: 'jane@acme.com', action: 'LOGIN' });
    expect(first.status).toBe(202);
    expect(first.body?.touchque.state).toBe('waiting');
    const built = getDefaultClient();
    const token = first.body!.token!;
    expect(isStatusPoll(null, { user: 'jane@acme.com', action: 'LOGIN', token })).toBe(true);
    expect(isStatusPoll(built, { user: 'jane@acme.com', action: 'LOGIN', token })).toBe(true);

    delete process.env.TQ_API_KEY; // kept once built
    api.approve();
    const done = await runGuard(null, { user: 'jane@acme.com', action: 'LOGIN', token });
    expect(done.approved).toMatchObject({ user: 'jane@acme.com', action: 'LOGIN', assurance: { method: 'push' } });
    expect(getDefaultClient()).toBe(built);
  });

  test('setDefaultClient: a default client with your logger for the null path; null forgets it', async () => {
    const logger = { warn: vi.fn(), error: vi.fn() };
    const mine = new Touchque({ apiKey: 'tq_test_key', apiSecret: 'test_secret', baseUrl: api.url, logger });
    expect(setDefaultClient(mine)).toBeUndefined();
    expect(getDefaultClient()).toBe(mine);
    const unknown = await runGuard(null, { user: 'jane@acme.com', action: 'NOT_DEFINED' });
    expect(unknown.status).toBe(500);
    expect(logger.error).toHaveBeenCalledWith(expect.stringMatching(/^\[Touchque\] .*Unknown action "NOT_DEFINED"/));
    const app = express();
    app.post('/t', requireTouchque('LOGIN', { user: () => 'jane@acme.com' }), (_req, res) => res.json({ ok: true }));
    expect((await request(app).post('/t')).body.touchque.state).toBe('waiting'); // the adapters use it too

    expect(setDefaultClient(null)).toBe(mine);
    expect(() => getDefaultClient()).toThrow(TouchqueConfigError); // no keys here: the fail-fast check at startup
    expect((await runGuard(null, { user: 'jane@acme.com', action: 'LOGIN' })).status).toBe(500);
    expect(setDefaultClient(mine)).toBeUndefined();
    expect(setDefaultClient()).toBe(mine);
  });
});

describe('guardResponse: what the adapters send', () => {
  /** The same route three ways, each on its own fake API in the same state: Express adapter, Fetch adapter, runGuard + guardResponse. */
  async function threeWays(errorBody?: (r: GuardRefusal) => unknown) {
    const apis = await Promise.all([startFakeApi(), startFakeApi(), startFakeApi()]);
    const [viaExpress, viaFetch, viaHandler] = apis.map((a) => a.client);
    const details = { Amount: '5 EUR' };
    const app = express();
    app.use(express.json());
    const user = (req: express.Request) => req.get('x-user') || undefined;
    app.post('/adapter/:action', (req, res, next) => requireTouchque(req.params.action, { client: viaExpress, user, details: () => details, errorBody })(req, res, next),
      (_req, res) => res.json({ ok: true }));
    app.post('/handler/:action', async (req, res) => {
      const result = await runGuard(viaHandler, { user: user(req), action: req.params.action, details, token: req.get(GUARD_HEADERS.token) });
      if (result.approved) return res.json({ ok: true });
      const { status, headers, body } = await guardResponse(result, { errorBody });
      res.status(status).set(headers).json(body);
    });
    const NAMES = ['content-type', 'cache-control', 'retry-after', 'x-touchque-state', 'x-touchque-reason'];
    const send = async (action: string, headers: Record<string, string>) => {
      const answers = [];
      for (const path of ['adapter', 'handler']) {
        const res = await request(app).post(`/${path}/${action}`).set(headers).send({});
        answers.push({ status: res.status, headers: Object.fromEntries(NAMES.map((n) => [n, res.headers[n]])), body: res.text });
      }
      const fetchAnswer = await withTouchque(action, async () => Response.json({ ok: true }), {
        client: viaFetch, user: (req) => req.headers.get('x-user'), details: () => details, errorBody,
      })(new Request('http://app.test/transfer', { method: 'POST', headers }));
      answers.push({
        status: fetchAnswer.status,
        headers: Object.fromEntries(NAMES.map((n) => [n, n === 'content-type' ? answers[0].headers[n] : fetchAnswer.headers.get(n) ?? undefined])),
        body: await fetchAnswer.text(),
      });
      expect(fetchAnswer.headers.get('content-type')).toBe('application/json');
      expect(answers[1]).toEqual(answers[0]);
      expect(answers[2]).toEqual(answers[0]);
      return { status: answers[0].status, headers: answers[0].headers, body: JSON.parse(answers[0].body) };
    };
    return { apis, send, close: () => Promise.all(apis.map((a) => a.close())) };
  }

  const misconfigured = { touchque: { state: 'blocked', reason: 'misconfigured' } };
  for (const [name, errorBody, body500] of [
    ['without errorBody', undefined,
      { ...misconfigured, error: { code: 'misconfigured', message: 'Two-factor approval is not configured correctly.' } }],
    ['with an errorBody object', (r: GuardRefusal) => ({ message: r.message, code: r.code }),
      { message: 'Two-factor approval is not configured correctly.', code: 'misconfigured', ...misconfigured }],
    ['with an errorBody string', (r: GuardRefusal) => r.message, 'Two-factor approval is not configured correctly.'],
  ] as const) {
    test(`202, 401, 403, 423, 429 and 500 answer the same, ${name}`, async () => {
      vi.useFakeTimers({ toFake: ['Date'], now: Date.parse('2026-11-12T10:00:00Z') });
      const { apis, send, close } = await threeWays(errorBody);
      try {
        for (const a of apis) a.linked.add('jane@acme.com');
        const jane = { 'x-user': 'jane@acme.com' };
        const waiting = await send('SEND_MONEY', jane);
        expect(waiting).toMatchObject({ status: 202, headers: { 'cache-control': 'no-store', 'x-touchque-state': undefined }, body: { touchque: { state: 'waiting' } } });
        expect(waiting.body.token).toEqual(expect.any(String));

        for (const a of apis) a.reject();
        const rejected = await send('SEND_MONEY', { ...jane, [GUARD_HEADERS.token]: waiting.body.token });
        expect(rejected).toMatchObject({ status: 403, headers: { 'x-touchque-state': 'rejected', 'x-touchque-reason': undefined } });

        expect((await send('SEND_MONEY', {})).status).toBe(401);
        for (const a of apis) a.opts.frozen = true;
        expect((await send('SEND_MONEY', jane)).headers).toMatchObject({ 'retry-after': '900', 'x-touchque-state': 'frozen' });
        for (const a of apis) Object.assign(a.opts, { frozen: false, rateLimited: true });
        const limited = await send('SEND_MONEY', jane);
        expect(limited).toMatchObject({ status: 429, headers: { 'retry-after': '60', 'x-touchque-state': 'rate_limited' } });
        for (const a of apis) a.opts.rateLimited = false;
        const unknown = await send('NOT_DEFINED', jane);
        expect(unknown).toEqual({
          status: 500,
          headers: {
            'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'retry-after': undefined,
            'x-touchque-state': 'blocked', 'x-touchque-reason': 'misconfigured',
          },
          body: body500,
        });
      } finally {
        vi.useRealTimers();
        await close();
      }
    });
  }

  test('no client and no keys: the adapters\' 500 and 401', async () => {
    const result = await runGuard(null, { user: 'jane@acme.com', action: 'SEND_MONEY' });
    expect(await guardResponse(result as { status: number; body: NonNullable<typeof result.body> })).toEqual({
      status: 500,
      headers: { 'Cache-Control': 'no-store', 'X-Touchque-State': 'blocked', 'X-Touchque-Reason': 'misconfigured' },
      body: { touchque: { state: 'blocked', reason: 'misconfigured' }, error: { code: 'misconfigured', message: 'Two-factor approval is not configured correctly.' } },
    });
    const app = express();
    app.post('/t', requireTouchque('SEND_MONEY', { user: () => 'jane@acme.com' }), (_req, res) => res.json({ ok: true }));
    const res = await request(app).post('/t');
    expect(res.status).toBe(500);
    expect(res.body).toEqual((await guardResponse(result as { status: number; body: NonNullable<typeof result.body> })).body);
  });

  test('a failing errorBody sends the default body and logs through `logger`; an approved result is refused', async () => {
    const result = await runGuard(api.client, { action: 'SEND_MONEY' });
    if (result.approved) throw new Error('not expected');
    const logger = { warn: vi.fn(), error: vi.fn() };
    const answer = await guardResponse(result, { errorBody: () => { throw new Error('boom'); }, logger });
    expect(answer.body).toBe(result.body);
    expect(logger.error).toHaveBeenCalledWith('[Touchque] errorBody failed: Error: boom');
    expect((await guardResponse(result, { errorBody: () => 1n })).body).toBe(result.body); // no logger: nothing logged, nothing thrown

    const first = await runGuard(api.client, { user: 'jane@acme.com', action: 'LOGIN' });
    api.approve();
    const approved = await runGuard(api.client, { user: 'jane@acme.com', action: 'LOGIN', token: first.body!.token });
    await expect(guardResponse(approved as never)).rejects.toThrow(TypeError);
  });
});

describe('waiting polls carry the request\'s current expiresAt', () => {
  const input = { user: 'jane@acme.com', action: 'LOGIN' };

  test('every waiting or passkey_required answer carries the live expiry; the token keeps it (rx)', async () => {
    const first = await runGuard(api.client, input);
    const { expiresAt } = first.body!.touchque;
    expect(expiresAt).toEqual(expect.any(String));
    const rx = Date.parse(expiresAt!);
    expect(claimsOf(first.body!.token!)).toMatchObject({ st: 'waiting', rx });

    const poll = await runGuard(api.client, { ...input, token: first.body!.token });
    expect(poll.body!.touchque).toMatchObject({ state: 'waiting', expiresAt: new Date(rx).toISOString() });
    expect(claimsOf(poll.body!.token!).rx).toBe(rx);

    api.escalate(); // tapped during a call: the push now waits for a passkey, open 180 s more
    const live = Date.parse(api.requests[0].expiresAt!);
    expect(live - rx).toBeGreaterThan(140_000);
    const passkey = await runGuard(api.client, { ...input, token: poll.body!.token });
    expect(passkey.body!.touchque).toMatchObject({ state: 'passkey_required', expiresAt: new Date(live).toISOString() });
    expect(claimsOf(passkey.body!.token!).rx).toBe(live);
    const again = await runGuard(api.client, { ...input, token: passkey.body!.token });
    expect(again.body!.touchque).toMatchObject({ state: 'passkey_required', expiresAt: new Date(live).toISOString() });
  });

  test('a status answer without expiresAt: the token\'s rx', async () => {
    const first = await runGuard(api.client, input);
    const rx = claimsOf(first.body!.token!).rx;
    delete api.requests[0].expiresAt; // an API that does not answer it
    const poll = await runGuard(api.client, { ...input, token: first.body!.token });
    expect(poll.body!.touchque).toMatchObject({ state: 'waiting', expiresAt: new Date(rx).toISOString() });
    expect(claimsOf(poll.body!.token!).rx).toBe(rx);
  });

  test('the passkey switches that are no poll keep the token\'s rx; the next poll carries the live 180 s', async () => {
    // A code typed from the offline QR after the push moved to a passkey.
    const first = await runGuard(api.client, input);
    const rx = claimsOf(first.body!.token!).rx;
    const offline = await runGuard(api.client, { ...input, token: first.body!.token, offline: true });
    api.escalate();
    const live = Date.parse(api.requests[0].expiresAt!);
    expect(live - rx).toBeGreaterThan(140_000);
    const typed = await runGuard(api.client, { ...input, token: offline.body!.token, code: 'ABCD123' });
    expect(typed.body!.touchque).toMatchObject({ state: 'passkey_required', expiresAt: new Date(rx).toISOString() });
    expect(claimsOf(typed.body!.token!).rx).toBe(rx);
    const poll = await runGuard(api.client, { ...input, token: typed.body!.token });
    expect(poll.body!.touchque).toMatchObject({ state: 'passkey_required', expiresAt: new Date(live).toISOString() });
    expect(claimsOf(poll.body!.token!).rx).toBe(live);

    // The offline QR asked for (offline: true) with a waiting token after the push moved to a passkey.
    const second = await runGuard(api.client, input);
    const rx2 = claimsOf(second.body!.token!).rx;
    api.escalate();
    const live2 = Date.parse(api.requests[1].expiresAt!);
    const asked = await runGuard(api.client, { ...input, token: second.body!.token, offline: true });
    expect(asked.body!.touchque).toMatchObject({ state: 'passkey_required', expiresAt: new Date(rx2).toISOString() });
    expect(claimsOf(asked.body!.token!).rx).toBe(rx2);
    const poll2 = await runGuard(api.client, { ...input, token: asked.body!.token });
    expect(poll2.body!.touchque).toMatchObject({ state: 'passkey_required', expiresAt: new Date(live2).toISOString() });
    expect(claimsOf(poll2.body!.token!).rx).toBe(live2);
  });

  test('through the offline QR too; a token without rx keeps the 5.1 answer', async () => {
    const first = await runGuard(api.client, input);
    const rx = claimsOf(first.body!.token!).rx;
    const offline = await runGuard(api.client, { ...input, token: first.body!.token, offline: true });
    expect(offline.body!.touchque.state).toBe('offline');
    expect(offline.body!.touchque.expiresAt).toBeUndefined();
    expect(claimsOf(offline.body!.token!).rx).toBe(rx);
    api.requests[0].expiresAt = new Date(rx + 5_000).toISOString(); // the QR is kept: its token takes the live expiry
    const kept = await runGuard(api.client, { ...input, token: offline.body!.token });
    expect(kept.body!.touchque).toEqual({ state: 'offline', offline: { challengeId: offline.body!.touchque.offline!.challengeId } });
    expect(claimsOf(kept.body!.token!).rx).toBe(rx + 5_000);
    api.escalate();
    const live = Date.parse(api.requests[0].expiresAt!);
    const passkey = await runGuard(api.client, { ...input, token: kept.body!.token });
    expect(passkey.body!.touchque).toMatchObject({ state: 'passkey_required', expiresAt: new Date(live).toISOString() });

    // A token from before rx: the live expiry when Touchque answers one, else none, as in 5.1.
    const second = await runGuard(api.client, input);
    const old = signGuardToken('test_secret', {
      u: 'jane@acme.com', a: 'LOGIN', d: detailsDigest([]), r: null, st: 'waiting', rid: second.body!.touchque.requestId, exp: Date.now() + 60_000,
    });
    const withLive = await runGuard(api.client, { ...input, token: old });
    expect(withLive.body!.touchque).toMatchObject({ state: 'waiting', expiresAt: second.body!.touchque.expiresAt });
    delete api.requests[1].expiresAt;
    const legacy = await runGuard(api.client, { ...input, token: old });
    expect(legacy.body!.touchque.state).toBe('waiting');
    expect(legacy.body!.touchque).not.toHaveProperty('expiresAt');
    expect(claimsOf(legacy.body!.token!)).not.toHaveProperty('rx');
  });
});

describe('enroll: false says why', () => {
  test('a user with no phone gets { state: enroll, reason: enrollment_off }: no QR, no secret, the same on every poll', async () => {
    const input = { user: 'new@acme.com', action: 'LOGIN', enroll: false, details: { Amount: '5 EUR' } };
    const first = await runGuard(api.client, input);
    expect(first.status).toBe(202);
    expect(first.body!.touchque).toEqual({ state: 'enroll', reason: 'enrollment_off', details: [{ label: 'Amount', value: '5 EUR' }] });
    expect(claimsOf(first.body!.token!)).not.toHaveProperty('ee');
    const again = await runGuard(api.client, { ...input, token: first.body!.token });
    expect(again.body!.touchque).toMatchObject({ state: 'enroll', reason: 'enrollment_off' });
    expect(api.calls.some((c) => c.path === '/auth/generate-secret' || c.path === '/auth/secret/reset')).toBe(false);
    expect(await api.client.start('LOGIN', { user: 'new@acme.com', enroll: false })).toEqual({ state: 'enroll', reason: 'enrollment_off' });
  });
});
