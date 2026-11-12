// touchqueRelay: touchqueRouter's routes and checks as a Fetch handler,
// driven with Request objects against the fake Touchque API.
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest';
import { startFakeApi, FakeApi } from './testing/fakeApi';
import { touchqueRelay, TouchqueRelayOptions } from './index';
import type { Touchque } from './index';

type Relay = (req: Request) => Promise<Response>;

const call = (relay: Relay, method: string, path: string, body?: unknown, headers: Record<string, string> = {}) =>
  relay(new Request(`http://app.test/touchque${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    ...(body !== undefined && { body: typeof body === 'string' ? body : JSON.stringify(body) }),
  }));
const post = (relay: Relay, path: string, body: unknown = {}, headers: Record<string, string> = {}) => call(relay, 'POST', path, body, headers);

const relayFor = (tq: Touchque, options: Partial<TouchqueRelayOptions> = {}) =>
  touchqueRelay(tq, { getUserId: () => 'user@example.com', ...options });

/** A client whose passkey calls are mocks (the fake API has no primary passkey routes). */
function passkeyTq(webauthn: Record<string, unknown> = {}): Touchque {
  return {
    webauthn: {
      primaryOptions: vi.fn(async () => ({ attemptId: 'att_1', options: {} })),
      primaryVerify: vi.fn(async () => ({ success: true, externalUsername: 'user@example.com', requestId: 'req_2' })),
      authenticateOptions: vi.fn(async () => ({ someOption: true })),
      authenticateVerify: vi.fn(async () => ({ success: true, message: 'approved' })),
      listCredentials: vi.fn(async () => ({ credentials: [] })),
      deleteCredential: vi.fn(async () => ({ deleted: true })),
      ...webauthn,
    },
  } as unknown as Touchque;
}

let api: FakeApi;
beforeEach(async () => { api = await startFakeApi(); api.linked.add('user@example.com'); });
afterEach(async () => { await api.close(); });

describe('touchqueRelay — routing and bodies', () => {
  test('answers only under basePath: 404 elsewhere, 405 with Allow for another method', async () => {
    const relay = relayFor(api.client, { rateLimit: false });
    expect((await relay(new Request('http://app.test/other/login', { method: 'POST' }))).status).toBe(404);
    expect((await post(relay, '/nope')).status).toBe(404);
    const wrong = await call(relay, 'GET', '/login');
    expect(wrong.status).toBe(405);
    expect(wrong.headers.get('allow')).toBe('POST');
    const custom = relayFor(api.client, { rateLimit: false, basePath: '/api/tq/' });
    const res = await custom(new Request('http://app.test/api/tq/enroll/status'));
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('no-store');
  });

  test('reads JSON bodies only: bad JSON 400, over 100 KiB 413, another content type is no body', async () => {
    const relay = relayFor(api.client, { rateLimit: false });
    expect((await post(relay, '/login', '{')).status).toBe(400);
    expect((await post(relay, '/login', '"user@example.com"')).status).toBe(400);
    expect((await post(relay, '/login', { externalUsername: 'x'.repeat(101 * 1024) })).status).toBe(413);
    const text = await post(relay, '/login', JSON.stringify({ externalUsername: 'user@example.com' }), { 'Content-Type': 'text/plain' });
    expect(text.status).toBe(400);
    expect(await text.json()).toEqual({ error: 'externalUsername_required' });
    expect(api.calls.some((c) => c.path === '/login/request')).toBe(false);
  });
});

describe('touchqueRelay — enrollment', () => {
  test('401 UNAUTHORIZED_FOR_2FA when getUserId returns nothing', async () => {
    const relay = relayFor(api.client, { getUserId: async () => undefined });
    const res = await post(relay, '/enroll/start');
    expect(res.status).toBe(401);
    expect((await res.json()).error).toBe('UNAUTHORIZED_FOR_2FA');
  });

  test('issues the QR, issues a new one for an unscanned QR, and never replaces a linked phone', async () => {
    const relay = relayFor(api.client, { getUserId: () => 'new@example.com' });
    const first = await post(relay, '/enroll/start');
    expect(first.status).toBe(200);
    expect((await first.json()).qrCodeDataUrl).toBe('data:image/png;base64,QR-new@example.com');
    const again = await post(relay, '/enroll/start');
    expect((await again.json()).qrCodeDataUrl).toBe('data:image/png;base64,QR2-new@example.com');

    const linked = await post(relayFor(api.client), '/enroll/start');
    expect(linked.status).toBe(409);
    expect((await linked.json()).error).toBe('already_linked');
    expect(api.calls.filter((c) => c.path === '/auth/secret/reset')).toHaveLength(1);
  });

  test('GET /enroll/status: linked once the phone is set, { linked: false } for an unknown user', async () => {
    expect(await (await call(relayFor(api.client), 'GET', '/enroll/status')).json()).toEqual({ linked: true, used: true, deviceId: 'dev-1' });
    const unknown = relayFor(api.client, { getUserId: () => 'nobody@example.com' });
    expect(await (await call(unknown, 'GET', '/enroll/status')).json()).toEqual({ linked: false, used: false, deviceId: null });
  });
});

describe('touchqueRelay — classic login (two-phase)', () => {
  test('202 with the number before approval; the token completes it once, with onAuthenticated\'s cookie', async () => {
    api.opts.numberMatch = true;
    const onAuthenticated = vi.fn((_req: Request, info: { externalUsername: string }, headers: Headers) => {
      headers.append('Set-Cookie', `sid=${info.externalUsername}; HttpOnly`);
    });
    const relay = relayFor(api.client, { rateLimit: false, onAuthenticated, getDetails: () => ({ Action: 'Sign in' }) });
    const first = await post(relay, '/login', { externalUsername: 'User@Example.com' }, { 'User-Agent': 'Mozilla/5.0 (Macintosh)' });
    expect(first.status).toBe(202);
    const step = await first.json();
    expect(step.touchque).toMatchObject({ state: 'waiting', number: '47', details: [{ label: 'Action', value: 'Sign in' }] });
    expect(api.calls.find((c) => c.path === '/login/request')!.body).toMatchObject({ externalUsername: 'user@example.com', type: 'LOGIN', userAgent: 'Mozilla/5.0 (Macintosh)' });
    expect(onAuthenticated).not.toHaveBeenCalled();

    api.approve();
    const done = await post(relay, '/login', { externalUsername: 'user@example.com' }, { 'X-Touchque-Token': step.token });
    expect(done.status).toBe(200);
    expect(await done.json()).toMatchObject({ status: 'success', requestId: step.touchque.requestId, assurance: { method: 'push' } });
    expect(done.headers.get('set-cookie')).toBe('sid=user@example.com; HttpOnly');
    expect(onAuthenticated.mock.calls[0][1]).toMatchObject({ externalUsername: 'user@example.com', via: 'login' });

    const replay = await post(relay, '/login', { externalUsername: 'user@example.com' }, { 'X-Touchque-Token': step.token });
    expect(replay.status).not.toBe(200);
    expect(onAuthenticated).toHaveBeenCalledTimes(1);
  });

  test('rejected → 403; pre-auth never hands an unlinked user a linking QR', async () => {
    const relay = relayFor(api.client, { rateLimit: false });
    const first = await (await post(relay, '/login', { externalUsername: 'user@example.com' })).json();
    api.reject();
    const rej = await post(relay, '/login', { externalUsername: 'user@example.com' }, { 'X-Touchque-Token': first.token });
    expect(rej.status).toBe(403);
    expect((await rej.json()).touchque.state).toBe('rejected');
    const fresh = await (await post(relay, '/login', { externalUsername: 'new@example.com' })).json();
    expect(fresh.touchque.state).toBe('enroll');
    expect(fresh.touchque.enroll).toBeUndefined();
    expect(api.calls.some((c) => c.path === '/auth/generate-secret')).toBe(false);
  });

  test('with getLoginUser: pushes ONLY to the first-factor user and offers first-time linking', async () => {
    const relay = relayFor(api.client, { rateLimit: false, getLoginUser: async () => 'New@Example.com' });
    const res = await post(relay, '/login', { externalUsername: 'victim@example.com' });
    expect(res.status).toBe(202);
    expect((await res.json()).touchque.enroll.qrCodeDataUrl).toBeTruthy();
    api.linked.add('alice@example.com');
    const bound = relayFor(api.client, { rateLimit: false, getLoginUser: () => 'alice@example.com' });
    await post(bound, '/login', { externalUsername: 'victim@example.com' });
    expect(api.calls.filter((c) => c.path === '/login/request').map((c) => c.body.externalUsername)).toEqual(['new@example.com', 'alice@example.com']);
  });

  test('with getLoginUser, pre-auth routes 401 FIRST_FACTOR_REQUIRED when nobody passed the first factor', async () => {
    const relay = relayFor(api.client, { rateLimit: false, getLoginUser: () => undefined });
    for (const [path, body] of [['/login', { externalUsername: 'victim@example.com' }], ['/offline/challenge', { externalUsername: 'victim@example.com' }], ['/offline/totp', { externalUsername: 'victim@example.com', code: '123456' }]] as const) {
      const res = await post(relay, path, body);
      expect(res.status).toBe(401);
      expect((await res.json()).error).toBe('FIRST_FACTOR_REQUIRED');
    }
    expect(api.calls).toHaveLength(0);
  });
});

describe('touchqueRelay — offline sign', () => {
  test('without getLoginUser the offline routes are off (403), Touchque never called', async () => {
    const relay = relayFor(api.client, { rateLimit: false });
    for (const [path, body] of [['/offline/challenge', { externalUsername: 'victim@example.com' }], ['/offline/verify', { challengeId: 'c1', code: 'ABCD123' }], ['/offline/totp', { externalUsername: 'victim@example.com', code: '123456' }]] as const) {
      const res = await post(relay, path, body);
      expect(res.status).toBe(403);
      expect((await res.json()).error).toBe('OFFLINE_REQUIRES_FIRST_FACTOR');
    }
    expect(api.calls).toHaveLength(0);
  });

  test('QR for the first-factor user, then the code opens a session only for that user', async () => {
    const onAuthenticated = vi.fn();
    const relay = relayFor(api.client, { rateLimit: false, getLoginUser: () => 'user@example.com', onAuthenticated, ip: () => '203.0.113.7' });
    const ch = await (await post(relay, '/offline/challenge', { externalUsername: 'victim@example.com' })).json();
    expect(ch).toMatchObject({ challengeId: expect.any(String), qr: 'TQ2.x', totpAvailable: true });
    expect(api.calls.find((c) => c.path === '/offline/challenge')!.body).toMatchObject({ externalUsername: 'user@example.com', clientIp: '203.0.113.7' });

    const wrong = await post(relay, '/offline/verify', { challengeId: ch.challengeId, code: 'AAAAAAA' });
    expect(wrong.status).toBe(401);
    expect(await wrong.json()).toMatchObject({ approved: false, reason: 'invalid_code', attemptsLeft: 4 });
    const ok = await post(relay, '/offline/verify', { challengeId: ch.challengeId, code: 'ABCD123' });
    expect(await ok.json()).toEqual({ status: 'success', approved: true, requestId: ch.challengeId });
    expect(onAuthenticated.mock.calls[0][1]).toEqual({ externalUsername: 'user@example.com', requestId: ch.challengeId, via: 'offline' });

    // A code for another user's QR does not open this user's session.
    const other = relayFor(api.client, { rateLimit: false, getLoginUser: () => 'someone.else@example.com', onAuthenticated });
    const ch2 = await (await post(relayFor(api.client, { rateLimit: false, getLoginUser: () => 'user@example.com' }), '/offline/challenge')).json();
    expect((await post(other, '/offline/verify', { challengeId: ch2.challengeId, code: 'ABCD123' })).status).toBe(401);
    expect(onAuthenticated).toHaveBeenCalledTimes(1);
  });

  test('POST /offline/totp verifies with the action type and authenticates', async () => {
    const onAuthenticated = vi.fn();
    const relay = relayFor(api.client, { rateLimit: false, getLoginUser: () => 'user@example.com', onAuthenticated });
    const res = await post(relay, '/offline/totp', { code: '123456' });
    expect(await res.json()).toEqual({ status: 'success', approved: true });
    expect(api.calls.find((c) => c.path === '/offline/totp/verify')!.body).toMatchObject({ externalUsername: 'user@example.com', code: '123456', type: 'LOGIN' });
    expect(onAuthenticated.mock.calls[0][1]).toEqual({ externalUsername: 'user@example.com', via: 'offline-totp' });
  });
});

describe('touchqueRelay — rate limits (the same FixedWindowLimiter)', () => {
  test('push-bombing one user is capped per username (429 + Retry-After), across IPs', async () => {
    api.linked.add('victim@example.com');
    const relay = relayFor(api.client, { trustedProxyHops: 1, rateLimit: { perUser: 3, perIp: 100 } });
    const statuses: number[] = [];
    for (let i = 0; i < 5; i++) {
      const r = await post(relay, '/login', { externalUsername: 'victim@example.com' }, { 'X-Forwarded-For': `198.51.100.${i}` });
      statuses.push(r.status);
      if (r.status === 429) expect(Number(r.headers.get('retry-after'))).toBeGreaterThan(0);
    }
    expect(statuses).toEqual([202, 202, 202, 429, 429]);
    expect(api.calls.filter((c) => c.path === '/login/request')).toHaveLength(3);
  });

  test('one IP spraying many usernames is capped per IP; with no client address only the per-user limits apply', async () => {
    const spray = async (options: Partial<TouchqueRelayOptions>) => {
      const relay = relayFor(api.client, { allowOfflineWithoutFirstFactor: true, rateLimit: { perIp: 4, perUser: 100 }, ...options });
      const statuses: number[] = [];
      for (let i = 0; i < 6; i++) statuses.push((await post(relay, '/offline/challenge', { externalUsername: `u${i}@example.com` })).status);
      return statuses;
    };
    expect((await spray({ ip: () => '203.0.113.7' })).filter((s) => s === 429)).toHaveLength(2);
    expect(await spray({})).toEqual([200, 200, 200, 200, 200, 200]);
  });

  test('polling a sent push is not counted against the per-user limit; new attempts are', async () => {
    const relay = relayFor(api.client, { ip: () => '203.0.113.9' });
    const first = await (await post(relay, '/login', { externalUsername: 'user@example.com' })).json();
    for (let i = 0; i < 12; i++) {
      if (i === 9) api.approve();
      const poll = await post(relay, '/login', { externalUsername: 'user@example.com' }, { 'X-Touchque-Token': first.token });
      if (i < 9) expect(poll.status).toBe(202);
      else { expect(poll.status).toBe(200); break; }
    }
    for (let i = 0; i < 4; i++) await post(relay, '/login', { externalUsername: 'user@example.com' });
    expect((await post(relay, '/login', { externalUsername: 'user@example.com' })).status).toBe(429);
  });

  test('polls that only keep the first-time QR are never charged to the user', async () => {
    const relay = relayFor(api.client, { ip: () => '203.0.113.9', getLoginUser: () => 'new@example.com', rateLimit: { perUser: 2, perIp: 100 } });
    const first = await (await post(relay, '/login')).json() as { touchque: { enroll: { qrCodeDataUrl: string; expiresAt: string } }; token: string };
    expect(first.touchque.enroll.qrCodeDataUrl).toBeTruthy();
    let token = first.token;
    for (let i = 0; i < 12; i++) {
      const poll = await post(relay, '/login', {}, { 'X-Touchque-Token': token });
      expect(poll.status).toBe(202);
      const body = await poll.json() as { touchque: unknown; token: string };
      expect(body.touchque).toEqual({ state: 'enroll', expiresAt: first.touchque.enroll.expiresAt });
      token = body.token;
    }
    api.linked.add('new@example.com');
    const linked = await (await post(relay, '/login', {}, { 'X-Touchque-Token': token })).json() as { touchque: { state: string } };
    expect(linked.touchque.state).toBe('waiting'); // the push after linking is the user's 2nd charge
    expect(api.calls.filter((c) => c.path === '/auth/generate-secret' || c.path === '/auth/secret/reset')).toHaveLength(1);
  });

  test('replaying the first-time QR token after linking is charged: 429 once the per-user budget is spent', async () => {
    const relay = relayFor(api.client, { ip: () => '203.0.113.9', getLoginUser: () => 'new@example.com', rateLimit: { perUser: 3, perIp: 100 } });
    const first = await (await post(relay, '/login')).json() as { token: string };
    api.linked.add('new@example.com');
    const replays: Response[] = [];
    for (let i = 0; i < 4; i++) replays.push(await post(relay, '/login', {}, { 'X-Touchque-Token': first.token }));
    expect(replays.map((r) => r.status)).toEqual([202, 202, 429, 429]);
    expect(await replays[2].json()).toMatchObject({ error: 'RATE_LIMITED', retryAfter: expect.any(Number) });
    expect(replays[2].headers.get('retry-after')).toBeTruthy();
    expect(api.calls.filter((c) => c.path === '/login/request')).toHaveLength(3); // the first attempt and 2 pushes
  });

  test('a poll on a QR already within 15 s of its expiry is charged up front, as a fresh attempt', async () => {
    api.opts.secretTtlMs = 10_000;
    const relay = relayFor(api.client, { ip: () => '203.0.113.9', getLoginUser: () => 'new@example.com', rateLimit: { perUser: 2, perIp: 100 } });
    let token = (await (await post(relay, '/login')).json() as { token: string }).token;
    const statuses: number[] = [];
    for (let i = 0; i < 3; i++) {
      const poll = await post(relay, '/login', {}, { 'X-Touchque-Token': token });
      statuses.push(poll.status);
      token = (await poll.json() as { token?: string }).token ?? token;
    }
    expect(statuses).toEqual([202, 429, 429]);
  });

  test('a status poll whose QR reaches its renewal inside runGuard is charged to the user (beforeStart)', async () => {
    api.opts.secretTtlMs = 15_400; // the 15 s margin begins 400 ms after the QR
    const t0 = Date.now();
    const clock = vi.spyOn(Date, 'now').mockReturnValue(t0);
    const getUser = api.client.auth.getUser.bind(api.client.auth);
    // Reading the link state takes the clock past the margin: counted as a status poll, renewed in runGuard.
    const slow = vi.spyOn(api.client.auth, 'getUser').mockImplementation(async (o) => { clock.mockReturnValue(t0 + 1_000); return getUser(o); });
    try {
      const relay = relayFor(api.client, { ip: () => '203.0.113.9', getLoginUser: () => 'new@example.com', rateLimit: { perUser: 3, perIp: 100 } });
      const first = await (await post(relay, '/login')).json() as { token: string };
      const statuses: number[] = [];
      for (let i = 0; i < 3; i++) {
        clock.mockReturnValue(t0);
        statuses.push((await post(relay, '/login', {}, { 'X-Touchque-Token': first.token })).status);
      }
      expect(statuses).toEqual([202, 202, 429]); // perUser 3: the first attempt and 2 renewals
      expect(api.calls.filter((c) => c.path === '/auth/secret/reset')).toHaveLength(2);
    } finally {
      slow.mockRestore();
      clock.mockRestore();
    }
  });

  test('a refusal names its state (and reason) in X-Touchque-State / X-Touchque-Reason', async () => {
    const relay = relayFor(api.client, { rateLimit: false });
    const first = await post(relay, '/login', { externalUsername: 'user@example.com' });
    expect(first.headers.get('x-touchque-state')).toBeNull();
    api.reject();
    const rejected = await post(relay, '/login', { externalUsername: 'user@example.com' }, { 'X-Touchque-Token': (await first.json() as { token: string }).token });
    expect(rejected.status).toBe(403);
    expect(rejected.headers.get('x-touchque-state')).toBe('rejected');
    expect(rejected.headers.get('x-touchque-reason')).toBeNull();
    api.opts.blocked = 'geo_policy';
    const blocked = await post(relay, '/login', { externalUsername: 'user@example.com' });
    expect(blocked.headers.get('x-touchque-state')).toBe('blocked');
    expect(blocked.headers.get('x-touchque-reason')).toBe('geo_policy');
  });

  test('rateLimit: false turns the limiter off', async () => {
    const relay = relayFor(api.client, { rateLimit: false, ip: () => '203.0.113.7' });
    for (let i = 0; i < 30; i++) expect((await post(relay, '/login', { externalUsername: 'user@example.com' })).status).toBe(202);
  });
});

describe('touchqueRelay — passkeys', () => {
  test('sign-in: options for any passkey without an email; verify opens the session with headers', async () => {
    const tq = passkeyTq();
    const onAuthenticated = vi.fn((_req: Request, _info: unknown, headers: Headers) => { headers.set('Set-Cookie', 'sid=1'); });
    const relay = relayFor(tq, { onAuthenticated });
    expect((await post(relay, '/passkey/authenticate/options')).status).toBe(200);
    expect(tq.webauthn.primaryOptions).toHaveBeenCalledWith({});
    const res = await post(relay, '/passkey/authenticate/verify', { attemptId: 'att_1', response: {} });
    expect(await res.json()).toEqual({ status: 'success', requestId: 'req_2' });
    expect(res.headers.get('set-cookie')).toBe('sid=1');
    expect(onAuthenticated.mock.calls[0][1]).toEqual({ externalUsername: 'user@example.com', requestId: 'req_2', via: 'passkey' });
  });

  test('approving a pending request opens a session only for the user Touchque approved', async () => {
    const onAuthenticated = vi.fn();
    const tq = passkeyTq({ authenticateVerify: vi.fn(async () => ({ success: true, message: 'ok', externalUsername: 'other@example.com', requestId: 'r' })) });
    const bound = relayFor(tq, { getLoginUser: () => 'alice@example.com', onAuthenticated });
    expect((await post(bound, '/passkey/login/verify', { requestId: 'r', response: {}, externalUsername: 'alice@example.com' })).status).toBe(401);
    expect(onAuthenticated).not.toHaveBeenCalled();
    await post(relayFor(tq, { onAuthenticated }), '/passkey/login/verify', { requestId: 'r', response: {}, externalUsername: 'victim@example.com' });
    expect(onAuthenticated.mock.calls[0][1]).toEqual({ externalUsername: 'other@example.com', requestId: 'r', via: 'passkey' });
  });

  test('adding a passkey with a linked phone: approve on the phone first, then the options once', async () => {
    const relay = relayFor(api.client);
    const first = await post(relay, '/passkey/register/options');
    expect(first.status).toBe(202);
    const step = await first.json();
    expect(step.touchque).toMatchObject({ state: 'waiting', number: '47' });
    expect(api.calls.find((c) => c.path === '/login/request')?.body.type).toBe('PASSKEY_ENROLL');
    api.approve();
    const done = await post(relay, '/passkey/register/options', {}, { 'X-Touchque-Token': step.token });
    expect((await done.json()).challenge).toBe('reg-challenge');
    expect((await post(relay, '/passkey/register/options', {}, { 'X-Touchque-Token': step.token })).status).not.toBe(200);
  });

  test('credentials: 401 without a user; DELETE passes the decoded id', async () => {
    const tq = passkeyTq();
    const anonymous = relayFor(tq, { getUserId: () => null });
    expect((await call(anonymous, 'GET', '/passkey/credentials')).status).toBe(401);
    expect((await call(anonymous, 'DELETE', '/passkey/credentials/abc')).status).toBe(401);
    const res = await call(relayFor(tq), 'DELETE', '/passkey/credentials/cred%201');
    expect(await res.json()).toEqual({ deleted: true });
    expect(tq.webauthn.deleteCredential).toHaveBeenCalledWith('cred 1', { externalUsername: 'user@example.com' });
  });
});
