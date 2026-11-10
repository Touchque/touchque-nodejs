import { describe, it, expect } from 'vitest';
import { HostedLogin } from './hostedLogin';
import { MyAccountError } from './myAccount';

const ISSUER = 'https://acme.login.touchque.com';

function fakeTenant() {
  const calls: Array<{ url: URL; method: string; body: string; headers: Record<string, string> }> = [];
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    const u = new URL(url);
    const headers = (init?.headers || {}) as Record<string, string>;
    calls.push({ url: u, method: init?.method || 'GET', body: String(init?.body || ''), headers });
    const reply = (status: number, body: unknown, extra: Record<string, string> = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...extra } });
    if (u.pathname === '/oauth/token') return reply(200, { access_token: 'me-at', token_type: 'Bearer', expires_in: 600, scope: 'read:me update:me', refresh_token: 'tqr_2' });
    if (u.pathname === '/me/v1/profile' && init?.method === 'PATCH') return reply(200, { id: 'usr_1', name: JSON.parse(String(init.body)).name });
    if (u.pathname === '/me/v1/sessions/s1') return new Response(null, { status: 204 });
    if (u.pathname === '/me/v1' && init?.method === 'DELETE') {
      return reply(401, { error: 'insufficient_user_authentication', error_description: 'A more recent sign-in is required' }, { 'www-authenticate': 'Bearer error="insufficient_user_authentication", max_age="600"' });
    }
    return reply(404, { error: 'not_found' });
  }) as unknown as typeof fetch;
  return { calls, fetchImpl };
}

describe('My Account API', () => {
  it('trades the refresh token for a /me/ token, then calls /me/v1 with it', async () => {
    const t = fakeTenant();
    const login = new HostedLogin({ domain: 'acme.login.touchque.com', clientId: 'c1', fetch: t.fetchImpl });
    const me = await login.myAccountToken('tqr_1');
    expect(me).toMatchObject({ accessToken: 'me-at', refreshToken: 'tqr_2' });
    const form = new URLSearchParams(t.calls[0].body);
    expect(form.get('audience')).toBe(`${ISSUER}/me/`);
    expect(form.get('scope')).toBe('read:me update:me');
    expect(form.get('refresh_token')).toBe('tqr_1');

    const account = login.myAccount(me.accessToken);
    expect(await account.updateProfile({ name: 'Zoë' })).toEqual({ id: 'usr_1', name: 'Zoë' });
    expect(t.calls[1].headers.Authorization).toBe('Bearer me-at');
    expect(await account.endSession('s1')).toBeUndefined();
    expect(login.accountUrl('security')).toBe(`${ISSUER}/account/security`);
  });

  it('turns the RFC 9470 challenge into a step-up error', async () => {
    const t = fakeTenant();
    const account = new HostedLogin({ domain: ISSUER, clientId: 'c1', fetch: t.fetchImpl }).myAccount('old-at');
    const err = await account.deleteAccount().catch((e) => e);
    expect(err).toBeInstanceOf(MyAccountError);
    expect(err).toMatchObject({ code: 'insufficient_user_authentication', status: 401, stepUp: true, maxAge: 600 });
  });
});
