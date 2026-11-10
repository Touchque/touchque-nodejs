// TouchQue Login in Next.js: the route handlers (login, callback, me, token,
// logout) against a fake tenant, and the Edge middleware reading the same
// session cookie with WebCrypto.
import { describe, it, expect } from 'vitest';
import { createHash, generateKeyPairSync, sign as signRaw } from 'crypto';
import { createTouchQueLogin } from './nextLogin';
import { touchqueMiddleware, hasSession } from './nextMiddleware';

const ISSUER = 'https://acme.login.touchque.com';
const CLIENT = 'client-123';
const SECRET = 's'.repeat(40);
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = publicKey.export({ format: 'jwk' }) as { n: string; e: string };
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (p: Record<string, unknown>, typ = 'JWT') => {
  const input = `${b64({ alg: 'RS256', typ, kid: 'k1' })}.${b64(p)}`;
  return `${input}.${signRaw('sha256', Buffer.from(input), privateKey).toString('base64url')}`;
};
const now = () => Math.floor(Date.now() / 1000);

function fakeTenant() {
  const codes = new Map<string, { challenge: string; nonce: string }>();
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    const u = new URL(url);
    const reply = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
    if (u.pathname === '/.well-known/jwks.json') return reply(200, { keys: [{ kty: 'RSA', kid: 'k1', use: 'sig', alg: 'RS256', n: jwk.n, e: jwk.e }] });
    if (u.pathname === '/oauth/revoke') return reply(200, {});
    if (u.pathname === '/oauth/token') {
      const body = new URLSearchParams(String(init?.body));
      if (body.get('grant_type') === 'refresh_token') return reply(200, { access_token: 'at-2', token_type: 'Bearer', expires_in: 300, scope: 'openid', refresh_token: 'tqr_2' });
      const c = codes.get(body.get('code') || '');
      if (!c || createHash('sha256').update(body.get('code_verifier') || '').digest('base64url') !== c.challenge) return reply(400, { error: 'invalid_grant' });
      const at = 'at-1';
      const id = jwt({ iss: ISSUER, sub: 'usr_1', aud: CLIENT, exp: now() + 300, iat: now(), nonce: c.nonce, email: 'zoe@acme.test', at_hash: createHash('sha256').update(at).digest().subarray(0, 16).toString('base64url') });
      return reply(200, { access_token: at, token_type: 'Bearer', expires_in: 1, scope: 'openid offline_access', id_token: id, refresh_token: 'tqr_1' });
    }
    return reply(404, {});
  }) as unknown as typeof fetch;
  const authorize = (url: string) => {
    const p = new URL(url).searchParams;
    const code = `code-${codes.size}`;
    codes.set(code, { challenge: p.get('code_challenge') || '', nonce: p.get('nonce') || '' });
    return { code, state: p.get('state') || '' };
  };
  return { fetchImpl, authorize };
}

// What a browser does with Set-Cookie: keep the values, drop the cleared ones.
function jarFrom(res: Response, jar: Record<string, string> = {}) {
  for (const c of res.headers.getSetCookie()) {
    const [pair] = c.split(';');
    const i = pair.indexOf('=');
    const name = pair.slice(0, i);
    const value = pair.slice(i + 1);
    if (/Max-Age=0/.test(c)) delete jar[name]; else jar[name] = value;
  }
  return jar;
}
const cookieHeader = (jar: Record<string, string>) => Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');
const req = (path: string, jar: Record<string, string> = {}) => new Request(`http://localhost:3000${path}`, { headers: { cookie: cookieHeader(jar) } });

describe('createTouchQueLogin (Next.js)', () => {
  it('signs in, reads the session, refreshes the token, signs out; the middleware guards pages', async () => {
    const t = fakeTenant();
    const touchque = createTouchQueLogin({ domain: ISSUER, clientId: CLIENT, secret: SECRET, appUrl: 'http://localhost:3000', fetch: t.fetchImpl });
    const call = (path: string, jar: Record<string, string>) => touchque.handlers.GET(req(path, jar), { params: Promise.resolve({ action: path.split('?')[0].split('/')[2] }) });
    const guard = touchqueMiddleware({ secret: SECRET, protect: ['/dashboard'] });

    // Signed out: the middleware sends a protected page to the sign-in.
    let r = (await guard(req('/dashboard/orders?tab=open'))) as Response;
    expect(r.status).toBe(307);
    expect(r.headers.get('location')).toBe('http://localhost:3000/auth/login?returnTo=%2Fdashboard%2Forders%3Ftab%3Dopen');
    expect(await guard(req('/about'))).toBeUndefined();

    let jar: Record<string, string> = {};
    r = await call('/auth/login?returnTo=/dashboard', jar);
    expect(r.status).toBe(302);
    const authorizeUrl = r.headers.get('location') as string;
    expect(authorizeUrl.startsWith(`${ISSUER}/authorize?`)).toBe(true);
    expect(new URL(authorizeUrl).searchParams.get('redirect_uri')).toBe('http://localhost:3000/auth/callback');
    jar = jarFrom(r, jar);
    const { code, state } = t.authorize(authorizeUrl);
    r = await call(`/auth/callback?code=${code}&state=${state}`, jar);
    expect(r.headers.get('location')).toBe('http://localhost:3000/dashboard');
    jar = jarFrom(r, jar);
    expect(Object.keys(jar)).toEqual(['tq_session']);
    expect(r.headers.getSetCookie().some((c) => c.startsWith('tq_session=') && /HttpOnly/.test(c) && !/Secure/.test(c))).toBe(true);

    expect((await touchque.getSession(cookieHeader(jar)))?.user.email).toBe('zoe@acme.test');
    expect(await hasSession(jar.tq_session, SECRET)).toBe(true);
    expect(await hasSession(jar.tq_session, 'x'.repeat(40))).toBe(false);
    expect(await hasSession(`${jar.tq_session.slice(0, -4)}AAAA`, SECRET)).toBe(false);
    expect(await guard(req('/dashboard', jar))).toBeUndefined();

    r = await call('/auth/me', jar);
    expect((await r.json()).user.sub).toBe('usr_1');
    // expires_in 1: the token route refreshes and keeps the rotated refresh token.
    r = await call('/auth/token', jar);
    expect((await r.json()).accessToken).toBe('at-2');
    jar = jarFrom(r, jar);
    expect((await touchque.getSession(cookieHeader(jar)))?.refreshToken).toBe('tqr_2');

    r = await call('/auth/logout', jar);
    expect(new URL(r.headers.get('location') as string).pathname).toBe('/oidc/logout');
    jar = jarFrom(r, jar);
    expect(jar.tq_session).toBeUndefined();
    expect((await call('/auth/me', jar)).status).toBe(401);
  });

  it('a callback without this browser\'s sign-in fails; returnTo stays on this site', async () => {
    const t = fakeTenant();
    const touchque = createTouchQueLogin({ domain: ISSUER, clientId: CLIENT, secret: SECRET, appUrl: 'https://app.acme.test', fetch: t.fetchImpl });
    let r = await touchque.handlers.GET(new Request('https://app.acme.test/auth/callback?code=x&state=y'));
    expect(r.status).toBe(400);
    expect((await r.json()).error).toBe('state_missing');
    r = await touchque.handlers.GET(new Request('https://app.acme.test/auth/login?returnTo=//evil.example'));
    const jar = jarFrom(r);
    const { code, state } = t.authorize(r.headers.get('location') as string);
    r = await touchque.handlers.GET(new Request(`https://app.acme.test/auth/callback?code=${code}&state=${state}`, { headers: { cookie: cookieHeader(jar) } }));
    expect(r.headers.get('location')).toBe('https://app.acme.test/');
    expect(r.headers.getSetCookie().some((c) => c.startsWith('tq_session=') && /Secure/.test(c))).toBe(true);
  });
});
