// src/nextLogin.ts — Touchque Login in a Next.js app (App Router).
//
//   // lib/touchque.ts
//   import { createTouchqueLogin } from '@touchque/node';
//   export const touchque = createTouchqueLogin({
//     domain: process.env.TOUCHQUE_LOGIN_DOMAIN!, clientId: process.env.TOUCHQUE_LOGIN_CLIENT_ID!,
//     clientSecret: process.env.TOUCHQUE_LOGIN_CLIENT_SECRET, secret: process.env.TOUCHQUE_SESSION_SECRET!,
//     appUrl: process.env.APP_URL!,                       // https://app.acme.com
//   });
//   // app/auth/[action]/route.ts
//   export const { GET } = touchque.handlers;            // /auth/login, /auth/callback, /auth/logout, /auth/me, /auth/token
//   // a server component or route handler
//   const session = await touchque.getSession(await cookies());
//
// Protect pages with `touchqueMiddleware` from `@touchque/node/next/middleware`
// (it runs on the Edge). The session is an encrypted cookie: no store needed.
// Route handlers here use the Node.js runtime (the default).

import { HostedLogin, HostedLoginConfig, IdTokenClaims, TokenSet, AuthorizationUrlOptions } from './hostedLogin';
import { seal, unseal, cookieHeaders, parseCookies, readCookie, safeReturnTo, CookieOptions } from './hostedLoginSession';
import { TouchqueError } from './errors';

export interface NextSession {
  user: IdTokenClaims;
  accessToken: string;
  expiresAt: number;
  idToken?: string;
  refreshToken?: string;
  scope: string;
}

export interface TouchqueNextOptions extends Omit<HostedLoginConfig, 'redirectUri'> {
  /** At least 32 random characters; encrypts the cookies (the middleware needs the same value). */
  secret: string;
  /** Your app's origin, like https://app.acme.com (the callback is {appUrl}{basePath}/callback). */
  appUrl: string;
  /** Where the handlers are mounted. Default /auth. */
  basePath?: string;
  /** Where to go after signing in, when no returnTo was given. Default /. */
  afterSignIn?: string;
  /** Where to go after signing out (a registered sign-out URL). Default {appUrl}/. */
  postLogoutRedirectUri?: string;
  /** Session cookie lifetime in seconds. Default 7 days. */
  sessionMaxAgeSec?: number;
  /** Cookie name. Default tq_session (the middleware's default too). */
  cookieName?: string;
}

/** Anything cookies can be read from: Next's cookies() store, a Request, Headers or a Cookie header. */
export type CookieSource = { getAll(): Array<{ name: string; value: string }> } | Request | Headers | string | null | undefined;

const TX_COOKIE = 'tq_login_tx';

function cookiesOf(source: CookieSource): Record<string, string> {
  if (!source) return {};
  if (typeof source === 'string') return parseCookies(source);
  if (typeof (source as Request).headers?.get === 'function') return parseCookies((source as Request).headers.get('cookie'));
  if (typeof (source as Headers).get === 'function' && !(source as { getAll?: unknown }).getAll) return parseCookies((source as Headers).get('cookie'));
  const out: Record<string, string> = {};
  for (const c of (source as { getAll(): Array<{ name: string; value: string }> }).getAll()) out[c.name] = c.value;
  return out;
}

function redirect(location: string, cookies: string[] = []): Response {
  const headers = new Headers({ Location: location, 'Cache-Control': 'no-store' });
  for (const c of cookies) headers.append('Set-Cookie', c);
  return new Response(null, { status: 302, headers });
}

function json(body: unknown, status = 200, cookies: string[] = []): Response {
  const headers = new Headers({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  for (const c of cookies) headers.append('Set-Cookie', c);
  return new Response(JSON.stringify(body), { status, headers });
}

export function createTouchqueLogin(options: TouchqueNextOptions) {
  if (!options?.appUrl) throw new TouchqueError('appUrl is required');
  if (!options.secret || options.secret.length < 32) throw new TouchqueError('secret must be at least 32 characters');
  const appUrl = options.appUrl.replace(/\/+$/, '');
  const basePath = (options.basePath || '/auth').replace(/\/+$/, '');
  const cookieName = options.cookieName || 'tq_session';
  const maxAge = options.sessionMaxAgeSec || 7 * 86400;
  const login = new HostedLogin({ ...options, redirectUri: `${appUrl}${basePath}/callback` });
  const secure = !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(appUrl);
  const cookie = (seconds: number): CookieOptions => ({ secure, maxAgeSec: seconds });

  const sessionFrom = (tokens: TokenSet, previous?: NextSession): NextSession => ({
    user: tokens.claims || (previous as NextSession).user,
    accessToken: tokens.accessToken,
    expiresAt: tokens.expiresAt,
    scope: tokens.scope,
    ...(tokens.idToken || previous?.idToken ? { idToken: tokens.idToken || previous?.idToken } : {}),
    ...(tokens.refreshToken || previous?.refreshToken ? { refreshToken: tokens.refreshToken || previous?.refreshToken } : {}),
  });

  /** The signed-in session, or null. Never refreshes (a server component cannot set cookies). */
  async function getSession(source: CookieSource): Promise<NextSession | null> {
    return unseal<NextSession>(readCookie(cookieName, cookiesOf(source)), options.secret, 'session');
  }

  async function handle(request: Request, action: string): Promise<Response> {
    const url = new URL(request.url);
    const cookies = parseCookies(request.headers.get('cookie'));
    if (action === 'login' || action === 'signup') {
      const returnTo = safeReturnTo(url.searchParams.get('returnTo'), options.afterSignIn || '/');
      const o: AuthorizationUrlOptions = {
        ...(action === 'signup' && { screenHint: 'signup' }),
        ...(url.searchParams.get('organization') && { organization: url.searchParams.get('organization') as string }),
        ...(url.searchParams.get('invitation') && { invitation: url.searchParams.get('invitation') as string }),
        ...(url.searchParams.get('max_age') && { maxAge: Number(url.searchParams.get('max_age')) }),
      };
      const req = login.authorizationUrl(o);
      const tx = seal({ state: req.state, nonce: req.nonce, codeVerifier: req.codeVerifier, returnTo, maxAge: o.maxAge }, options.secret, 'tx', 600);
      return redirect(req.url, cookieHeaders(TX_COOKIE, tx, cookies, cookie(600)));
    }
    if (action === 'callback') {
      const tx = unseal<{ state: string; nonce: string; codeVerifier: string; returnTo: string; maxAge?: number }>(readCookie(TX_COOKIE, cookies), options.secret, 'tx');
      if (!tx) return json({ error: 'state_missing', error_description: 'No sign-in was started in this browser' }, 400);
      try {
        const tokens = await login.handleCallback(url, { state: tx.state, nonce: tx.nonce, codeVerifier: tx.codeVerifier, maxAge: tx.maxAge });
        const sealed = seal(sessionFrom(tokens), options.secret, 'session', maxAge);
        return redirect(`${appUrl}${tx.returnTo}`, [...cookieHeaders(TX_COOKIE, null, cookies, cookie(0)), ...cookieHeaders(cookieName, sealed, cookies, cookie(maxAge))]);
      } catch (err) {
        const e = err as { code?: string; description?: string };
        return json({ error: e.code || 'callback_failed', error_description: e.description || null }, 400, cookieHeaders(TX_COOKIE, null, cookies, cookie(0)));
      }
    }
    if (action === 'logout') {
      const session = unseal<NextSession>(readCookie(cookieName, cookies), options.secret, 'session');
      if (session?.refreshToken) await login.revoke(session.refreshToken).catch(() => undefined);
      const target = login.logoutUrl({ idTokenHint: session?.idToken, postLogoutRedirectUri: options.postLogoutRedirectUri || `${appUrl}/` });
      return redirect(target, cookieHeaders(cookieName, null, cookies, cookie(0)));
    }
    if (action === 'me') {
      const session = unseal<NextSession>(readCookie(cookieName, cookies), options.secret, 'session');
      return session ? json({ user: session.user }) : json({ error: 'signed_out' }, 401);
    }
    if (action === 'token') {
      // A fresh access token for client components (refreshed, the rotated refresh token kept).
      const session = unseal<NextSession>(readCookie(cookieName, cookies), options.secret, 'session');
      if (!session) return json({ error: 'signed_out' }, 401);
      if (session.expiresAt - 30 > Date.now() / 1000) return json({ accessToken: session.accessToken, expiresAt: session.expiresAt });
      if (!session.refreshToken) return json({ error: 'signed_out' }, 401, cookieHeaders(cookieName, null, cookies, cookie(0)));
      try {
        const next = sessionFrom(await login.refresh(session.refreshToken), session);
        return json({ accessToken: next.accessToken, expiresAt: next.expiresAt }, 200, cookieHeaders(cookieName, seal(next, options.secret, 'session', maxAge), cookies, cookie(maxAge)));
      } catch {
        return json({ error: 'signed_out' }, 401, cookieHeaders(cookieName, null, cookies, cookie(0)));
      }
    }
    return json({ error: 'not_found' }, 404);
  }

  const handlers = {
    /** app{basePath}/[action]/route.ts: `export const { GET } = touchque.handlers;` */
    GET: async (request: Request, context?: { params?: Promise<{ action?: string }> | { action?: string } }) => {
      const params = context?.params ? await context.params : undefined;
      const action = params?.action || new URL(request.url).pathname.slice(basePath.length + 1).split('/')[0];
      return handle(request, action);
    },
  };

  return { login, handlers, getSession, basePath, cookieName };
}
