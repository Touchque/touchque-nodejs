import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest';
import { startFakeApi, FakeApi } from './testing/fakeApi';
import express from 'express';
import request from 'supertest';
import { touchqueRouter } from './router';
import { TouchQueRejectedError, TouchQueTimeoutError } from './errors';
import type { TouchQue } from './index';

function fakeTq(overrides: Record<string, any> = {}): TouchQue {
  return {
    auth: {
      generateSecret: vi.fn(async () => ({ secret: 'S3CR3T', qrCodeDataUrl: 'data:image/png;base64,x' })),
      resetSecret: vi.fn(async () => ({ secret: 'NEWSECRET', qrCodeDataUrl: 'data:image/png;base64,y' })),
      getUser: vi.fn(async () => ({ used: false, deviceId: null })),
      ...overrides.auth,
    },
    login: {
      verify: vi.fn(async () => ({ approved: true, status: 'CONFIRMED', requestId: 'req_1', challengeCode: '42' })),
      ...overrides.login,
    },
    offline: {
      challenge: vi.fn(async () => ({ challengeId: 'c1', qr: 'TQ1.a.b', qrDataUrl: 'data:image/png;base64,q', expiresAt: 't', expiresInSeconds: 120, totpAvailable: true })),
      verify: vi.fn(async () => ({ approved: true, challengeId: 'c1', externalUsername: 'user@example.com', type: 'LOGIN' })),
      verifyTotp: vi.fn(async () => ({ approved: true, externalUsername: 'user@example.com' })),
      ...overrides.offline,
    },
    webauthn: {
      primaryOptions: vi.fn(async () => ({ attemptId: 'att_1', options: {} })),
      primaryVerify: vi.fn(async () => ({ success: true, externalUsername: 'user@example.com', requestId: 'req_2' })),
      authenticateOptions: vi.fn(async () => ({ someOption: true })),
      authenticateVerify: vi.fn(async () => ({ success: true, message: 'approved' })),
      registerOptions: vi.fn(async () => ({})),
      registerVerify: vi.fn(async () => ({ verified: true, credentialId: 'cred_1' })),
      listCredentials: vi.fn(async () => ({ credentials: [] })),
      deleteCredential: vi.fn(async () => ({ deleted: true })),
      ...overrides.webauthn,
    },
  } as unknown as TouchQue;
}

function appWithRouter(tq: TouchQue, routerOptions: Partial<Parameters<typeof touchqueRouter>[1]> = {}) {
  const app = express();
  app.use(express.json());
  app.use(
    '/touchque',
    touchqueRouter(tq, { getUserId: () => 'user@example.com', ...routerOptions } as any),
  );
  return app;
}

describe('touchqueRouter — enrollment', () => {
  test('POST /enroll/start 401s when getUserId returns nothing', async () => {
    const app = appWithRouter(fakeTq(), { getUserId: () => undefined });
    const res = await request(app).post('/touchque/enroll/start');
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('UNAUTHORIZED_FOR_2FA');
  });

  test('POST /enroll/start returns the secret + QR', async () => {
    const app = appWithRouter(fakeTq());
    const res = await request(app).post('/touchque/enroll/start');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ secret: 'S3CR3T', qrCodeDataUrl: expect.any(String) });
  });

  test('POST /enroll/start retries via resetSecret on a 409 (existing unexpired secret)', async () => {
    const tq = fakeTq({
      auth: { generateSecret: vi.fn(async () => { throw { status: 409 }; }) },
    });
    const app = appWithRouter(tq);
    const res = await request(app).post('/touchque/enroll/start');
    expect(res.status).toBe(200);
    expect(res.body.secret).toBe('NEWSECRET');
    expect((tq.auth as any).resetSecret).toHaveBeenCalled();
  });

  test('POST /enroll/start NEVER replaces an already-linked phone (409 already_linked, no reset)', async () => {
    const tq = fakeTq({
      auth: {
        generateSecret: vi.fn(async () => { throw { status: 409 }; }),
        getUser: vi.fn(async () => ({ used: true, deviceId: 'victim-phone' })),
      },
    });
    const app = appWithRouter(tq);
    const res = await request(app).post('/touchque/enroll/start');
    expect(res.status).toBe(409);
    expect(res.body.error).toBe('already_linked');
    expect((tq.auth as any).resetSecret).not.toHaveBeenCalled();
  });

  test('GET /enroll/status maps a 404 to { linked: false } instead of erroring', async () => {
    const tq = fakeTq({ auth: { getUser: vi.fn(async () => { throw { status: 404 }; }) } });
    const app = appWithRouter(tq);
    const res = await request(app).get('/touchque/enroll/status');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ linked: false, used: false, deviceId: null });
  });

  test('GET /enroll/status reports linked once the device is set', async () => {
    const tq = fakeTq({ auth: { getUser: vi.fn(async () => ({ used: true, deviceId: 'dev_1' })) } });
    const app = appWithRouter(tq);
    const res = await request(app).get('/touchque/enroll/status');
    expect(res.body).toEqual({ linked: true, used: true, deviceId: 'dev_1' });
  });
});

describe('touchqueRouter — classic login (two-phase)', () => {
  let api: FakeApi;
  beforeEach(async () => { api = await startFakeApi(); api.linked.add('user@example.com'); });
  afterEach(async () => { await api.close(); });
  const realApp = (opts: Record<string, unknown> = {}) => appWithRouter(api.client, { rateLimit: false, ...opts });

  test('POST /login 400s without externalUsername', async () => {
    const res = await request(realApp()).post('/touchque/login').send({});
    expect(res.status).toBe(400);
  });

  test('first POST /login answers 202 with the matching number BEFORE approval; the token completes it once', async () => {
    api.opts.numberMatch = true;
    const onAuthenticated = vi.fn();
    const app = realApp({ onAuthenticated, getDetails: () => ({ Action: 'Sign in' }) });
    const first = await request(app).post('/touchque/login').set('User-Agent', 'Mozilla/5.0 (Macintosh)').send({ externalUsername: 'user@example.com' });
    expect(first.status).toBe(202);
    expect(first.body.touchque).toMatchObject({ state: 'waiting', number: '47', details: [{ label: 'Action', value: 'Sign in' }] });
    const sent = api.calls.find((c) => c.path === '/login/request')!.body;
    expect(sent).toMatchObject({ externalUsername: 'user@example.com', type: 'LOGIN', userAgent: 'Mozilla/5.0 (Macintosh)' });
    expect(onAuthenticated).not.toHaveBeenCalled();

    api.approve();
    const done = await request(app).post('/touchque/login').set('X-TouchQue-Token', first.body.token).send({ externalUsername: 'user@example.com' });
    expect(done.status).toBe(200);
    expect(done.body).toMatchObject({ status: 'success', requestId: first.body.touchque.requestId, assurance: { method: 'push' } });
    expect(onAuthenticated).toHaveBeenCalledTimes(1);
    expect(onAuthenticated.mock.calls[0][2]).toMatchObject({ externalUsername: 'user@example.com', via: 'login' });

    const replay = await request(app).post('/touchque/login').set('X-TouchQue-Token', first.body.token).send({ externalUsername: 'user@example.com' });
    expect(replay.status).not.toBe(200);
    expect(onAuthenticated).toHaveBeenCalledTimes(1);
  });

  test('rejected → 403 rejected; unknown user → 202 enroll (first-time QR)', async () => {
    const app = realApp();
    const first = await request(app).post('/touchque/login').send({ externalUsername: 'user@example.com' });
    api.reject();
    const rej = await request(app).post('/touchque/login').set('X-TouchQue-Token', first.body.token).send({ externalUsername: 'user@example.com' });
    expect(rej.status).toBe(403);
    expect(rej.body.touchque.state).toBe('rejected');
    const fresh = await request(app).post('/touchque/login').send({ externalUsername: 'new@example.com' });
    expect(fresh.status).toBe(202);
    expect(fresh.body.touchque.state).toBe('enroll');
  });

  test('TouchQue unreachable → 503 without internal details', async () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const app = realApp();
    await api.close();
    const res = await request(app).post('/touchque/login').send({ externalUsername: 'user@example.com' });
    expect(res.status).toBe(503);
    expect(res.body.error.code).toBe('unavailable');
    spy.mockRestore();
    api = await startFakeApi(); // afterEach closes it
  });
});

describe('touchqueRouter — passkeys', () => {
  test('POST /passkey/authenticate/options relays to webauthn.primaryOptions', async () => {
    const app = appWithRouter(fakeTq());
    const res = await request(app).post('/touchque/passkey/authenticate/options').send({ email: 'user@example.com' });
    expect(res.status).toBe(200);
    expect(res.body.attemptId).toBe('att_1');
  });

  test('POST /passkey/authenticate/verify calls onAuthenticated on success', async () => {
    const onAuthenticated = vi.fn();
    const app = appWithRouter(fakeTq(), { onAuthenticated });
    const res = await request(app).post('/touchque/passkey/authenticate/verify').send({ attemptId: 'att_1', response: {} });
    expect(res.status).toBe(200);
    expect(onAuthenticated).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      { externalUsername: 'user@example.com', requestId: 'req_2', via: 'passkey' },
    );
  });

  test('POST /passkey/authenticate/verify surfaces requiresStepUp without calling onAuthenticated', async () => {
    const onAuthenticated = vi.fn();
    const tq = fakeTq({ webauthn: { primaryVerify: vi.fn(async () => ({ success: false, requiresStepUp: true })) } });
    const app = appWithRouter(tq, { onAuthenticated });
    const res = await request(app).post('/touchque/passkey/authenticate/verify').send({});
    expect(res.body).toEqual({ requiresStepUp: true });
    expect(onAuthenticated).not.toHaveBeenCalled();
  });

  test('POST /passkey/login/options relays to webauthn.authenticateOptions (approve a pending request)', async () => {
    const tq = fakeTq();
    const app = appWithRouter(tq);
    const res = await request(app).post('/touchque/passkey/login/options').send({ requestId: 'req_9' });
    expect(res.status).toBe(200);
    expect((tq.webauthn as any).authenticateOptions).toHaveBeenCalledWith({ requestId: 'req_9' });
  });

  test('POST /passkey/login/verify opens the session for the user TouchQue approved, ignoring a name from the browser', async () => {
    const onAuthenticated = vi.fn();
    const tq = fakeTq();
    (tq.webauthn as any).authenticateVerify = vi.fn(async () => ({ success: true, message: 'approved', externalUsername: 'attacker@example.com', requestId: 'req_9' }));
    const app = appWithRouter(tq, { onAuthenticated });
    const res = await request(app)
      .post('/touchque/passkey/login/verify')
      .send({ requestId: 'req_9', response: {}, externalUsername: 'victim@example.com' });
    expect(res.status).toBe(200);
    expect(onAuthenticated).toHaveBeenCalledTimes(1);
    expect(onAuthenticated).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      { externalUsername: 'attacker@example.com', requestId: 'req_9', via: 'passkey' },
    );
  });

  test('POST /passkey/login/verify never opens a session when TouchQue does not name the user (older API)', async () => {
    const onAuthenticated = vi.fn();
    const app = appWithRouter(fakeTq(), { onAuthenticated });
    await request(app).post('/touchque/passkey/login/verify').send({ requestId: 'req_9', response: {}, externalUsername: 'victim@example.com' });
    expect(onAuthenticated).not.toHaveBeenCalled();
  });

  test('the auth-required passkey routes 401 without a resolvable user', async () => {
    const app = appWithRouter(fakeTq(), { getUserId: () => undefined });
    const optionsRes = await request(app).post('/touchque/passkey/register/options');
    const listRes = await request(app).get('/touchque/passkey/credentials');
    const delRes = await request(app).delete('/touchque/passkey/credentials/abc');
    expect(optionsRes.status).toBe(401);
    expect(listRes.status).toBe(401);
    expect(delRes.status).toBe(401);
  });

  test('DELETE /passkey/credentials/:id relays to webauthn.deleteCredential', async () => {
    const tq = fakeTq();
    const app = appWithRouter(tq);
    const res = await request(app).delete('/touchque/passkey/credentials/cred_1');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ deleted: true });
    expect((tq.webauthn as any).deleteCredential).toHaveBeenCalledWith('cred_1', { externalUsername: expect.any(String) });
  });
});

describe('touchqueRouter — offline sign', () => {
  test('POST /offline/challenge issues a QR for the typed user with the caller\'s IP/UA and getDetails()', async () => {
    const tq = fakeTq();
    const app = appWithRouter(tq, { getDetails: () => ({ Action: 'Sign in' }) });
    const res = await request(app).post('/touchque/offline/challenge').set('User-Agent', 'Mozilla/5.0 (Macintosh)').send({ externalUsername: 'User@Example.com' });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ challengeId: 'c1', qr: 'TQ1.a.b', totpAvailable: true });
    expect((tq.offline.challenge as any)).toHaveBeenCalledWith(expect.objectContaining({
      externalUsername: 'user@example.com', type: 'LOGIN', userAgent: 'Mozilla/5.0 (Macintosh)', details: { Action: 'Sign in' }, clientIp: expect.any(String),
    }));
  });

  test('POST /offline/challenge 400s without externalUsername', async () => {
    const res = await request(appWithRouter(fakeTq())).post('/touchque/offline/challenge').send({});
    expect(res.status).toBe(400);
  });

  test('POST /offline/verify calls onAuthenticated with the username TOUCHQUE returned, not the one in the body', async () => {
    const onAuthenticated = vi.fn();
    const app = appWithRouter(fakeTq(), { onAuthenticated });
    const res = await request(app).post('/touchque/offline/verify').send({ challengeId: 'c1', code: 'ABC-DEFG', externalUsername: 'victim@example.com' });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: 'success', approved: true, requestId: 'c1' });
    expect(onAuthenticated).toHaveBeenCalledWith(expect.anything(), expect.anything(), { externalUsername: 'user@example.com', requestId: 'c1', via: 'offline' });
  });

  test('POST /offline/verify: a wrong code is 401 and does NOT authenticate', async () => {
    const onAuthenticated = vi.fn();
    const tq = fakeTq({ offline: { verify: vi.fn(async () => ({ approved: false, reason: 'invalid_code', attemptsLeft: 4 })) } });
    const res = await request(appWithRouter(tq, { onAuthenticated })).post('/touchque/offline/verify').send({ challengeId: 'c1', code: 'AAAAAAA' });
    expect(res.status).toBe(401);
    expect(res.body).toMatchObject({ approved: false, reason: 'invalid_code', attemptsLeft: 4 });
    expect(onAuthenticated).not.toHaveBeenCalled();
  });

  test('POST /offline/verify: expired / used / locked are 400 and do NOT authenticate', async () => {
    const onAuthenticated = vi.fn();
    const tq = fakeTq({ offline: { verify: vi.fn(async () => ({ approved: false, reason: 'expired' })) } });
    const res = await request(appWithRouter(tq, { onAuthenticated })).post('/touchque/offline/verify').send({ challengeId: 'c1', code: 'AAAAAAA' });
    expect(res.status).toBe(400);
    expect(onAuthenticated).not.toHaveBeenCalled();
  });

  test('POST /offline/totp verifies with the action type (so critical actions are refused) and authenticates', async () => {
    const onAuthenticated = vi.fn();
    const tq = fakeTq();
    const res = await request(appWithRouter(tq, { onAuthenticated, actionType: 'LOGIN' })).post('/touchque/offline/totp').send({ externalUsername: 'User@Example.com', code: 'ABCDEFG' });
    expect(res.status).toBe(200);
    expect((tq.offline.verifyTotp as any)).toHaveBeenCalledWith(expect.objectContaining({ externalUsername: 'user@example.com', code: 'ABCDEFG', type: 'LOGIN' }));
    expect(onAuthenticated).toHaveBeenCalledWith(expect.anything(), expect.anything(), { externalUsername: 'user@example.com', via: 'offline-totp' });
  });
});

/** Same client IP on every request (loopback can arrive as IPv4 or IPv6, which splits per-IP counters). */
function fixedIpApp(tq: TouchQue, routerOptions: Record<string, unknown>) {
  const app = express();
  app.set('trust proxy', true);
  app.use(express.json());
  app.use('/touchque', touchqueRouter(tq, { getUserId: () => 'u', ...routerOptions } as any));
  return app;
}

describe('touchqueRouter — abuse protection (pre-auth routes)', () => {
  test('with getLoginUser, POST /login pushes ONLY to the first-factor user, never to a username from the body', async () => {
    const api = await startFakeApi();
    api.linked.add('alice@example.com');
    const app = appWithRouter(api.client, { getLoginUser: () => 'Alice@Example.com', rateLimit: false });
    const res = await request(app).post('/touchque/login').send({ externalUsername: 'victim@example.com' });
    expect(res.status).toBe(202);
    const pushes = api.calls.filter((c) => c.path === '/login/request').map((c) => c.body.externalUsername);
    expect(pushes).toEqual(['alice@example.com']);
    await api.close();
  });

  test('with getLoginUser, pre-auth routes 401 when nobody passed the first factor (no push is sent)', async () => {
    const tq = fakeTq();
    const app = appWithRouter(tq, { getLoginUser: () => undefined, rateLimit: false });
    for (const [path, body] of [['/touchque/login', { externalUsername: 'victim@example.com' }], ['/touchque/offline/challenge', { externalUsername: 'victim@example.com' }], ['/touchque/offline/totp', { externalUsername: 'victim@example.com', code: 'AAAAAAA' }]] as const) {
      const res = await request(app).post(path).send(body);
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('FIRST_FACTOR_REQUIRED');
    }
    expect((tq.login as any).verify).not.toHaveBeenCalled();
    expect((tq.offline as any).challenge).not.toHaveBeenCalled();
  });

  test('with getLoginUser, an offline code for a different user does not open a session', async () => {
    const onAuthenticated = vi.fn();
    const tq = fakeTq({ offline: { verify: vi.fn(async () => ({ approved: true, challengeId: 'c1', externalUsername: 'someone.else@example.com', type: 'LOGIN' })) } });
    const app = appWithRouter(tq, { getLoginUser: () => 'alice@example.com', onAuthenticated, rateLimit: false });
    const res = await request(app).post('/touchque/offline/verify').send({ challengeId: 'c1', code: 'AAAAAAA' });
    expect(res.status).toBe(401);
    expect(onAuthenticated).not.toHaveBeenCalled();
  });

  test('push-bombing one user through /login is capped per username (429 + Retry-After), across IPs', async () => {
    const api = await startFakeApi();
    api.linked.add('victim@example.com');
    const tq = api.client;
    const app = express();
    app.set('trust proxy', true); // lets the test vary req.ip
    app.use(express.json());
    app.use('/touchque', touchqueRouter(tq, { getUserId: () => 'u', rateLimit: { perUser: 3, perIp: 100 } } as any));
    const statuses: number[] = [];
    for (let i = 0; i < 5; i++) {
      const r = await request(app).post('/touchque/login').set('X-Forwarded-For', `198.51.100.${i}`).send({ externalUsername: 'victim@example.com' });
      statuses.push(r.status);
      if (r.status === 429) expect(Number(r.headers['retry-after'])).toBeGreaterThan(0);
    }
    expect(statuses).toEqual([202, 202, 202, 429, 429]);
    // the 30 s de-duplication folds repeats into one pending request; the limiter stopped the rest
    expect(api.calls.filter((c) => c.path === '/login/request')).toHaveLength(3);
    await api.close();
  });

  test('one IP spraying many usernames is capped per IP', async () => {
    const tq = fakeTq();
    const app = fixedIpApp(tq, { rateLimit: { perIp: 4, perUser: 100 } });
    const statuses: number[] = [];
    for (let i = 0; i < 6; i++) statuses.push((await request(app).post('/touchque/offline/challenge').set('X-Forwarded-For', '203.0.113.7').send({ externalUsername: `u${i}@example.com` })).status);
    expect(statuses.filter((s) => s === 429)).toHaveLength(2);
    expect((tq.offline as any).challenge).toHaveBeenCalledTimes(4);
  });

  test('offline code guessing is capped per IP', async () => {
    const tq = fakeTq({ offline: { verify: vi.fn(async () => ({ approved: false, reason: 'invalid_code', attemptsLeft: 3 })) } });
    const app = fixedIpApp(tq, { rateLimit: { perIp: 3 } });
    const statuses: number[] = [];
    for (let i = 0; i < 5; i++) statuses.push((await request(app).post('/touchque/offline/verify').set('X-Forwarded-For', '203.0.113.7').send({ challengeId: 'c1', code: 'AAAAAAA' })).status);
    expect(statuses).toEqual([401, 401, 401, 429, 429]);
  });

  test('rateLimit: false turns the built-in limiter off', async () => {
    const api = await startFakeApi();
    api.linked.add('a@example.com');
    const app = appWithRouter(api.client, { rateLimit: false });
    for (let i = 0; i < 30; i++) expect((await request(app).post('/touchque/login').send({ externalUsername: 'a@example.com' })).status).toBe(202);
    await api.close();
  });
});

describe('touchqueRouter — phishing-resistant policy', () => {
  test('POST /login answers 202 passkey_required with the requestId when TouchQue demands a passkey (no push)', async () => {
    const api = await startFakeApi();
    api.linked.add('a@example.com');
    api.opts.passkeyOnly = true;
    const app = appWithRouter(api.client, { rateLimit: false });
    const res = await request(app).post('/touchque/login').send({ externalUsername: 'a@example.com' });
    expect(res.status).toBe(202);
    expect(res.body.touchque.state).toBe('passkey_required');
    expect(res.body.touchque.requestId).toBe(api.requests[0].id);
    await api.close();
  });

  test('with getLoginUser, a passkey approval for another user opens no session', async () => {
    const onAuthenticated = vi.fn();
    const tq = fakeTq();
    (tq.webauthn as any).authenticateVerify = vi.fn(async () => ({ success: true, message: 'ok', externalUsername: 'other@example.com', requestId: 'r' }));
    const app = appWithRouter(tq, { getLoginUser: () => 'alice@example.com', onAuthenticated, rateLimit: false });
    const res = await request(app).post('/touchque/passkey/login/verify').send({ requestId: 'r', response: {} });
    expect(res.status).toBe(401);
    expect(onAuthenticated).not.toHaveBeenCalled();
  });
});
