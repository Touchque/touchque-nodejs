import { describe, it, expect } from 'vitest';
import { createHash, generateKeyPairSync, sign as signRaw } from 'crypto';
import express from 'express';
import request from 'supertest';
import { HostedLogin, HostedLoginError, CONNECTION_TOKEN_TYPE } from './hostedLogin';
import { MyAccount, MyAccountError } from './myAccount';
import { hostedLoginRoutes, requireSignIn, requireAccessToken } from './middleware/hostedLoginExpress';

const ISSUER = 'https://acme.login.touchque.com';
const CLIENT = 'client-123';
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const other = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = publicKey.export({ format: 'jwk' }) as { n: string; e: string };

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
function jwt(payload: Record<string, unknown>, { typ = 'JWT', key = privateKey, kid = 'k1' } = {}) {
  const input = `${b64({ alg: 'RS256', typ, kid })}.${b64(payload)}`;
  return `${input}.${signRaw('sha256', Buffer.from(input), key).toString('base64url')}`;
}
const now = () => Math.floor(Date.now() / 1000);
const atHash = (t: string) => createHash('sha256').update(t).digest().subarray(0, 16).toString('base64url');

// A fake tenant: JWKS + token endpoint that checks PKCE and client auth.
function fakeTenant(opts: { nonceOverride?: string; signWith?: typeof privateKey } = {}) {
  const codes = new Map<string, { challenge: string; nonce: string }>();
  const calls: Array<{ url: string; body: URLSearchParams; headers: Record<string, string> }> = [];
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    const u = new URL(url);
    const headers = (init?.headers || {}) as Record<string, string>;
    const reply = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
    if (u.pathname === '/.well-known/jwks.json') return reply(200, { keys: [{ kty: 'RSA', kid: 'k1', use: 'sig', alg: 'RS256', n: jwk.n, e: jwk.e }] });
    if (u.pathname === '/oauth/token') {
      const body = new URLSearchParams(String(init?.body));
      calls.push({ url, body, headers });
      if (body.get('grant_type') === 'authorization_code') {
        const c = codes.get(body.get('code') || '');
        const verifier = body.get('code_verifier') || '';
        if (!c || createHash('sha256').update(verifier).digest('base64url') !== c.challenge) return reply(400, { error: 'invalid_grant' });
        const at = jwt({ iss: ISSUER, sub: 'usr_1', aud: ['https://api.acme.test', `${ISSUER}/userinfo`], exp: now() + 300, iat: now(), client_id: CLIENT, scope: 'openid read:orders' }, { typ: 'at+jwt' });
        const id = jwt({ iss: ISSUER, sub: 'usr_1', aud: CLIENT, exp: now() + 300, iat: now(), nonce: opts.nonceOverride || c.nonce, email: 'a@acme.test', at_hash: atHash(at) }, { key: opts.signWith || privateKey });
        return reply(200, { access_token: at, token_type: 'Bearer', expires_in: 300, scope: 'openid read:orders offline_access', id_token: id, refresh_token: 'tqr_1' });
      }
      if (body.get('grant_type') === 'refresh_token') {
        if (body.get('refresh_token') !== 'tqr_1') return reply(400, { error: 'invalid_grant' });
        const at = jwt({ iss: ISSUER, sub: 'usr_1', aud: `${ISSUER}/userinfo`, exp: now() + 300, iat: now(), client_id: CLIENT }, { typ: 'at+jwt' });
        return reply(200, { access_token: at, token_type: 'Bearer', expires_in: 300, scope: 'openid', refresh_token: 'tqr_2' });
      }
    }
    return reply(404, { error: 'not_found' });
  }) as unknown as typeof fetch;
  // What /authorize would do: remember the challenge and nonce for a code.
  const authorize = (url: string) => {
    const p = new URL(url).searchParams;
    const code = `code-${codes.size}`;
    codes.set(code, { challenge: p.get('code_challenge') || '', nonce: p.get('nonce') || '' });
    return { code, state: p.get('state') || '' };
  };
  return { fetchImpl, authorize, calls };
}

describe('HostedLogin', () => {
  it('builds an authorization URL with PKCE S256, state and nonce', () => {
    const login = new HostedLogin({ domain: 'acme.login.touchque.com', clientId: CLIENT, redirectUri: 'https://app/cb', audience: 'https://api.acme.test' });
    const a = login.authorizationUrl({ screenHint: 'signup', uiLocales: 'tr' });
    const u = new URL(a.url);
    expect(u.origin + u.pathname).toBe(`${ISSUER}/authorize`);
    expect(u.searchParams.get('code_challenge')).toBe(createHash('sha256').update(a.codeVerifier).digest('base64url'));
    expect(u.searchParams.get('code_challenge_method')).toBe('S256');
    expect(u.searchParams.get('state')).toBe(a.state);
    expect(u.searchParams.get('nonce')).toBe(a.nonce);
    expect(u.searchParams.get('audience')).toBe('https://api.acme.test');
    expect(u.searchParams.get('screen_hint')).toBe('signup');
    expect(u.searchParams.get('ui_locales')).toBe('tr');
  });

  it('finishes the callback: code exchange with the verifier, verified ID token, refresh', async () => {
    const t = fakeTenant();
    const login = new HostedLogin({ domain: ISSUER, clientId: CLIENT, clientSecret: 's3cret', redirectUri: 'https://app/cb', fetch: t.fetchImpl });
    const a = login.authorizationUrl();
    const { code, state } = t.authorize(a.url);
    const session = await login.handleCallback(`https://app/cb?code=${code}&state=${state}&iss=${encodeURIComponent(ISSUER)}`, a);
    expect(session.claims?.sub).toBe('usr_1');
    expect(session.claims?.email).toBe('a@acme.test');
    expect(session.refreshToken).toBe('tqr_1');
    expect(t.calls[0].headers.Authorization).toBe(`Basic ${Buffer.from(`${CLIENT}:s3cret`).toString('base64')}`);
    const next = await login.refresh('tqr_1');
    expect(next.refreshToken).toBe('tqr_2');
    const claims = await login.verifyAccessToken(session.accessToken, { audience: 'https://api.acme.test', requiredScopes: ['read:orders'] });
    expect(claims.sub).toBe('usr_1');
    await expect(login.verifyAccessToken(session.accessToken, { audience: 'https://other' })).rejects.toThrow(HostedLoginError);
    await expect(login.verifyAccessToken(session.accessToken, { audience: 'https://api.acme.test', requiredScopes: ['write:orders'] })).rejects.toMatchObject({ code: 'insufficient_scope' });
    await expect(login.verifyAccessToken(session.idToken as string, { audience: CLIENT })).rejects.toThrow(/token type/);
  });

  it('refuses a wrong state, an error answer, a foreign issuer, a wrong nonce and a forged signature', async () => {
    const t = fakeTenant();
    const login = new HostedLogin({ domain: ISSUER, clientId: CLIENT, redirectUri: 'https://app/cb', fetch: t.fetchImpl });
    const a = login.authorizationUrl();
    const { code } = t.authorize(a.url);
    await expect(login.handleCallback({ code, state: 'other' }, a)).rejects.toMatchObject({ code: 'state_mismatch' });
    await expect(login.handleCallback({ error: 'access_denied', state: a.state }, a)).rejects.toMatchObject({ code: 'access_denied' });
    await expect(login.handleCallback({ code, state: a.state, iss: 'https://evil' }, a)).rejects.toMatchObject({ code: 'issuer_mismatch' });

    const bad = fakeTenant({ nonceOverride: 'replayed' });
    const l2 = new HostedLogin({ domain: ISSUER, clientId: CLIENT, redirectUri: 'https://app/cb', fetch: bad.fetchImpl });
    const a2 = l2.authorizationUrl();
    await expect(l2.handleCallback({ ...bad.authorize(a2.url) }, a2)).rejects.toMatchObject({ code: 'nonce_mismatch' });

    const forged = fakeTenant({ signWith: other.privateKey });
    const l3 = new HostedLogin({ domain: ISSUER, clientId: CLIENT, redirectUri: 'https://app/cb', fetch: forged.fetchImpl });
    const a3 = l3.authorizationUrl();
    await expect(l3.handleCallback({ ...forged.authorize(a3.url) }, a3)).rejects.toThrow(/signature/);
  });

  it('checks iss (RFC 9207): this issuer or none is accepted, a foreign or empty one is refused before the code exchange', async () => {
    const t = fakeTenant();
    const login = new HostedLogin({ domain: ISSUER, clientId: CLIENT, redirectUri: 'https://app/cb', fetch: t.fetchImpl });
    const a = login.authorizationUrl();
    const { code } = t.authorize(a.url);
    for (const iss of ['https://evil', 'https://acme.login.touchque.com.evil', `${ISSUER}/`, '']) {
      await expect(login.handleCallback({ code, state: a.state, iss }, a)).rejects.toMatchObject({ code: 'issuer_mismatch' });
    }
    // A foreign error answer is reported as the issuer mismatch, not as its own error.
    await expect(login.handleCallback({ error: 'access_denied', state: a.state, iss: 'https://evil' }, a)).rejects.toMatchObject({ code: 'issuer_mismatch' });
    expect(t.calls).toHaveLength(0);
    expect((await login.handleCallback({ code, state: a.state, iss: ISSUER }, a)).claims?.sub).toBe('usr_1');
    const b = login.authorizationUrl();
    const older = t.authorize(b.url);
    expect((await login.handleCallback(`https://app/cb?code=${older.code}&state=${older.state}`, b)).claims?.sub).toBe('usr_1');
  });

  it('logout URL carries the hint and the return address', () => {
    const login = new HostedLogin({ domain: ISSUER, clientId: CLIENT });
    const u = new URL(login.logoutUrl({ idTokenHint: 'h', postLogoutRedirectUri: 'https://app/' }));
    expect(u.pathname).toBe('/oidc/logout');
    expect(u.searchParams.get('id_token_hint')).toBe('h');
    expect(u.searchParams.get('post_logout_redirect_uri')).toBe('https://app/');
  });

  it('refuses a plaintext http:// issuer off this machine (like the API baseUrl)', () => {
    for (const domain of ['http://acme.login.example.com', 'http://10.0.0.5:5001', 'http://localhost.evil.com']) {
      expect(() => new HostedLogin({ domain, clientId: CLIENT })).toThrow(HostedLoginError);
      expect(() => new MyAccount({ domain, accessToken: 'at' })).toThrow(MyAccountError);
    }
    for (const domain of ['http://localhost:5001', 'http://127.0.0.1:5001', 'http://[::1]:5001', 'http://acme.login.localhost:5001/']) {
      expect(new HostedLogin({ domain, clientId: CLIENT }).issuer).toBe(domain.replace(/\/$/, ''));
    }
    expect(new HostedLogin({ domain: 'acme.login.touchque.com', clientId: CLIENT }).issuer).toBe(ISSUER);
  });
});

describe('Express: hostedLoginRoutes + requireSignIn', () => {
  it('signs in through /login and /callback and keeps the session in an encrypted cookie', async () => {
    const t = fakeTenant();
    const login = new HostedLogin({ domain: ISSUER, clientId: CLIENT, clientSecret: 'x', redirectUri: 'http://localhost:3000/callback', fetch: t.fetchImpl });
    const app = express();
    app.use(hostedLoginRoutes({ login, secret: 'a'.repeat(40) }));
    app.get('/me', requireSignIn(), (req, res) => res.json({ sub: req.touchqueSession?.user.sub }));
    app.get('/api', requireAccessToken(login, { audience: 'https://api.acme.test' }), (req, res) => res.json({ ok: true }));

    const anon = await request(app).get('/me');
    expect(anon.status).toBe(302);
    expect(anon.headers.location).toBe('/login?returnTo=%2Fme');

    const start = await request(app).get('/login?returnTo=/me');
    expect(start.status).toBe(302);
    const txCookie = (start.headers['set-cookie'] as unknown as string[]).find((c) => c.startsWith('tq_login_tx='))!.split(';')[0];
    const { code, state } = t.authorize(start.headers.location);
    const cb = await request(app).get(`/callback?code=${code}&state=${state}`).set('Cookie', txCookie);
    expect(cb.status).toBe(302);
    expect(cb.headers.location).toBe('/me');
    const cookies = (cb.headers['set-cookie'] as unknown as string[]).map((c) => c.split(';')[0]).filter((c) => !c.endsWith('='));
    const me = await request(app).get('/me').set('Cookie', cookies.join('; '));
    expect(me.body).toEqual({ sub: 'usr_1' });

    // A tampered session cookie is no session.
    const tampered = cookies.map((c) => (c.startsWith('tq_session') ? `${c.slice(0, -4)}AAAA` : c));
    expect((await request(app).get('/me').set('Cookie', tampered.join('; '))).status).toBe(302);
    // The API check.
    expect((await request(app).get('/api')).status).toBe(401);
  });

  it('a callback from another browser (no transaction cookie) fails', async () => {
    const t = fakeTenant();
    const login = new HostedLogin({ domain: ISSUER, clientId: CLIENT, redirectUri: 'http://localhost:3000/callback', fetch: t.fetchImpl });
    const app = express();
    app.use(hostedLoginRoutes({ login, secret: 'b'.repeat(40) }));
    app.use((err: Error, req: express.Request, res: express.Response, _next: express.NextFunction) => res.status(400).json({ error: (err as HostedLoginError).code }));
    const res = await request(app).get('/callback?code=x&state=y');
    expect(res.body.error).toBe('state_missing');
  });
});

describe('acting for a user: token exchange and CIBA', () => {
  function fakeAgentTenant() {
    const calls: Array<{ path: string; body: URLSearchParams; auth?: string }> = [];
    let polls = 0;
    const fetchImpl = (async (url: string, init?: RequestInit) => {
      const u = new URL(url);
      const body = new URLSearchParams(String(init?.body));
      calls.push({ path: u.pathname, body, auth: (init?.headers as Record<string, string>)?.Authorization });
      const reply = (status: number, b: unknown) => new Response(JSON.stringify(b), { status, headers: { 'content-type': 'application/json' } });
      if (u.pathname === '/bc-authorize') return reply(200, { auth_req_id: 'req-1', expires_in: 300, interval: 0, binding_code: '42' });
      if (body.get('requested_token_type') === 'urn:touchque:params:oauth:token-type:connection-access-token') {
        if (body.get('connection') !== 'google') return reply(400, { error: 'invalid_grant', error_description: 'no tokens stored' });
        return reply(200, { access_token: 'ya29.g', token_type: 'Bearer', expires_in: 3500, scope: 'openid email', issued_token_type: 'urn:ietf:params:oauth:token-type:access_token', connection: 'google' });
      }
      if (body.get('grant_type') === 'urn:ietf:params:oauth:grant-type:token-exchange') {
        return reply(200, { access_token: 'at-x', token_type: 'Bearer', expires_in: 120, scope: 'payments:create', issued_token_type: 'urn:ietf:params:oauth:token-type:access_token' });
      }
      if (body.get('grant_type') === 'urn:openid:params:grant-type:ciba') {
        polls += 1;
        if (polls === 1) return reply(400, { error: 'authorization_pending' });
        if (body.get('auth_req_id') === 'denied') return reply(400, { error: 'access_denied', error_description: 'The user did not approve' });
        return reply(200, { access_token: 'at-c', token_type: 'Bearer', expires_in: 300, scope: 'payments:create', authorization_details: [{ type: 'payment_initiation' }] });
      }
      return reply(404, { error: 'not_found' });
    }) as unknown as typeof fetch;
    return { fetchImpl, calls, resetPolls: () => { polls = 0; } };
  }

  it('exchanges a user token and asks the user on the phone', async () => {
    const t = fakeAgentTenant();
    const login = new HostedLogin({ domain: 'acme.login.touchque.com', clientId: CLIENT, clientSecret: 'tqs_s', fetch: t.fetchImpl });
    const ex = await login.exchangeToken('user-at', { audience: 'https://api.acme.test', scope: 'payments:create' });
    expect(ex).toMatchObject({ accessToken: 'at-x', issuedTokenType: 'urn:ietf:params:oauth:token-type:access_token' });
    expect(Object.fromEntries(t.calls[0].body)).toMatchObject({ subject_token: 'user-at', subject_token_type: 'urn:ietf:params:oauth:token-type:access_token', audience: 'https://api.acme.test' });

    const ask = await login.askUser({ loginHint: 'ada@acme.test', scope: 'openid payments:create', bindingMessage: 'Pay invoice 42', authorizationDetails: [{ type: 'payment_initiation' }] });
    expect(ask).toMatchObject({ authReqId: 'req-1', interval: 0, bindingCode: '42' });
    expect(JSON.parse(t.calls[1].body.get('authorization_details') || '[]')).toEqual([{ type: 'payment_initiation' }]);
    const approved = await login.waitForUser(ask);
    expect(approved).toMatchObject({ accessToken: 'at-c', authorizationDetails: [{ type: 'payment_initiation' }] });
    t.resetPolls();
    await expect(login.waitForUser({ ...ask, authReqId: 'denied' })).rejects.toMatchObject({ code: 'access_denied' });
  });

  it('gets a provider token from the token vault', async () => {
    const t = fakeAgentTenant();
    const login = new HostedLogin({ domain: 'acme.login.touchque.com', clientId: CLIENT, clientSecret: 'tqs_s', fetch: t.fetchImpl });
    const got = await login.getConnectionToken('user-at', { connection: 'google', scope: 'email' });
    expect(got).toMatchObject({ accessToken: 'ya29.g', connection: 'google', scope: 'openid email' });
    expect(Object.fromEntries(t.calls[0].body)).toMatchObject({ subject_token: 'user-at', connection: 'google', scope: 'email', requested_token_type: CONNECTION_TOKEN_TYPE });
    expect(t.calls[0].body.get('audience')).toBeNull();
    await expect(login.getConnectionToken('user-at', { connection: 'github' })).rejects.toMatchObject({ code: 'invalid_grant' });
  });
});
