// src/middleware/hostedLoginExpress.ts
// Touchque Login in an Express app, two lines:
//
//   const login = new HostedLogin({ domain, clientId, clientSecret, redirectUri: 'https://app.acme.com/callback' });
//   app.use(hostedLoginRoutes({ login, secret: process.env.SESSION_SECRET }));   // /login, /callback, /logout
//   app.get('/account', requireSignIn(), (req, res) => res.json(req.touchqueSession.user));
//
// The session lives in an encrypted cookie (no store needed). requireSignIn()
// refreshes the access token when it is about to expire and a refresh token
// is there (ask for offline_access).

import type { Router, Request, Response, NextFunction } from 'express';
import { HostedLogin, HostedLoginError, IdTokenClaims, TokenSet } from '../hostedLogin';
import { seal, unseal, cookieHeaders, parseCookies, readCookie, safeReturnTo, CookieOptions } from '../hostedLoginSession';
import { expressRouter } from './loadExpress';

export interface HostedLoginSession {
  user: IdTokenClaims;
  accessToken: string;
  expiresAt: number;
  idToken?: string;
  refreshToken?: string;
  scope: string;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      touchqueSession?: HostedLoginSession;
    }
  }
}

export interface HostedLoginRoutesOptions {
  login: HostedLogin;
  /** At least 32 random characters; encrypts the cookies. */
  secret: string;
  paths?: { login?: string; callback?: string; logout?: string };
  /** Where to go after signing out (must be a registered sign-out URL). */
  postLogoutRedirectUri?: string;
  /** Cookie name for the session. Default tq_session. */
  cookieName?: string;
  /** Session cookie lifetime in seconds. Default 7 days. */
  sessionMaxAgeSec?: number;
  /** Secure cookies. Default: true unless the redirect URI is http://localhost. */
  secure?: boolean;
  /** Runs after a successful sign-in, before the redirect (link the user to your records). */
  afterSignIn?: (req: Request, session: HostedLoginSession) => void | Promise<void>;
}

const TX_COOKIE = 'tq_login_tx';
let lastConfig: (HostedLoginRoutesOptions & { cookieName: string }) | null = null;

function sessionFrom(tokens: TokenSet, previous?: HostedLoginSession): HostedLoginSession {
  return {
    user: tokens.claims || (previous as HostedLoginSession).user,
    accessToken: tokens.accessToken,
    expiresAt: tokens.expiresAt,
    scope: tokens.scope,
    ...(tokens.idToken || previous?.idToken ? { idToken: tokens.idToken || previous?.idToken } : {}),
    ...(tokens.refreshToken || previous?.refreshToken ? { refreshToken: tokens.refreshToken || previous?.refreshToken } : {}),
  };
}

function cookieOpts(o: HostedLoginRoutesOptions, maxAgeSec: number): CookieOptions {
  const secure = o.secure ?? !/^http:\/\/(localhost|127\.0\.0\.1)/.test(o.login.redirectUri || '');
  return { secure, maxAgeSec };
}

function setCookies(res: Response, headers: string[]) {
  if (!headers.length) return;
  const prev = res.getHeader('Set-Cookie');
  const list = Array.isArray(prev) ? prev.map(String) : prev ? [String(prev)] : [];
  res.setHeader('Set-Cookie', [...list, ...headers]);
}

export function hostedLoginRoutes(options: HostedLoginRoutesOptions): Router {
  const o = { cookieName: 'tq_session', sessionMaxAgeSec: 7 * 86400, ...options };
  if (!o.login) throw new HostedLoginError('config', 'login is required');
  seal({}, o.secret, 'check', 1); // throws early on a short secret
  lastConfig = o;
  const paths = { login: '/login', callback: '/callback', logout: '/logout', ...(o.paths || {}) };
  const router = expressRouter('hostedLoginRoutes');

  router.get(paths.login, (req: Request, res: Response) => {
    const returnTo = safeReturnTo(req.query.returnTo);
    const auth = o.login.authorizationUrl({
      ...(req.query.screen_hint === 'signup' && { screenHint: 'signup' as const }),
      ...(typeof req.query.login_hint === 'string' && { loginHint: req.query.login_hint }),
      ...(typeof req.query.connection === 'string' && { connection: req.query.connection }),
      ...(typeof req.query.organization === 'string' && { organization: req.query.organization }),
      ...(typeof req.query.invitation === 'string' && { invitation: req.query.invitation }),
    });
    const cookies = parseCookies(req.headers.cookie);
    const tx = seal({ state: auth.state, nonce: auth.nonce, codeVerifier: auth.codeVerifier, returnTo }, o.secret, 'tx', 900);
    setCookies(res, cookieHeaders(TX_COOKIE, tx, cookies, cookieOpts(o, 900)));
    res.redirect(302, auth.url);
  });

  router.get(paths.callback, async (req: Request, res: Response, next: NextFunction) => {
    try {
      const cookies = parseCookies(req.headers.cookie);
      const tx = unseal<{ state: string; nonce: string; codeVerifier: string; returnTo: string }>(readCookie(TX_COOKIE, cookies), o.secret, 'tx');
      if (!tx) throw new HostedLoginError('state_missing', 'This sign-in expired or started in another browser');
      const tokens = await o.login.handleCallback(req.originalUrl || req.url, tx);
      const session = sessionFrom(tokens);
      if (o.afterSignIn) await o.afterSignIn(req, session);
      setCookies(res, [
        ...cookieHeaders(TX_COOKIE, null, cookies, cookieOpts(o, 0)),
        ...cookieHeaders(o.cookieName, seal(session, o.secret, 'session', o.sessionMaxAgeSec), cookies, cookieOpts(o, o.sessionMaxAgeSec)),
      ]);
      res.redirect(302, tx.returnTo || '/');
    } catch (err) {
      next(err);
    }
  });

  router.get(paths.logout, (req: Request, res: Response) => {
    const cookies = parseCookies(req.headers.cookie);
    const session = unseal<HostedLoginSession>(readCookie(o.cookieName, cookies), o.secret, 'session');
    setCookies(res, cookieHeaders(o.cookieName, null, cookies, cookieOpts(o, 0)));
    res.redirect(302, o.login.logoutUrl({ idTokenHint: session?.idToken, postLogoutRedirectUri: o.postLogoutRedirectUri }));
  });

  return router;
}

export interface RequireSignInOptions {
  /** Use the options passed to hostedLoginRoutes (default: the last one set up). */
  routes?: HostedLoginRoutesOptions;
  /** Answer 401 JSON instead of redirecting to the sign-in (APIs). */
  api?: boolean;
  /** Where the sign-in route is. Default /login. */
  loginPath?: string;
}

/** Puts the session on req.touchqueSession, or sends the browser to sign in. */
export function requireSignIn(opts: RequireSignInOptions = {}) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const o = (opts.routes as typeof lastConfig) || lastConfig;
    if (!o) return next(new HostedLoginError('config', 'Mount hostedLoginRoutes() first'));
    const cookies = parseCookies(req.headers.cookie);
    let session = unseal<HostedLoginSession>(readCookie(o.cookieName || 'tq_session', cookies), o.secret, 'session');
    if (session && session.expiresAt - 30 < Date.now() / 1000) {
      if (!session.refreshToken) session = null;
      else {
        try {
          session = sessionFrom(await o.login.refresh(session.refreshToken), session);
          setCookies(res, cookieHeaders(o.cookieName || 'tq_session', seal(session, o.secret, 'session', o.sessionMaxAgeSec || 7 * 86400), cookies, cookieOpts(o, o.sessionMaxAgeSec || 7 * 86400)));
        } catch {
          session = null;
        }
      }
    }
    if (!session) {
      if (opts.api) return res.status(401).json({ error: 'sign_in_required' });
      return res.redirect(302, `${opts.loginPath || o.paths?.login || '/login'}?returnTo=${encodeURIComponent(safeReturnTo(req.originalUrl))}`);
    }
    req.touchqueSession = session;
    return next();
  };
}

/** For APIs: checks the Bearer access token and puts its claims on req.touchqueToken. */
export function requireAccessToken(login: HostedLogin, { audience, scopes = [] }: { audience: string; scopes?: string[] }) {
  return async (req: Request & { touchqueToken?: unknown }, res: Response, next: NextFunction) => {
    const m = /^Bearer\s+(\S+)$/i.exec(String(req.headers.authorization || ''));
    if (!m) {
      res.setHeader('WWW-Authenticate', 'Bearer');
      return res.status(401).json({ error: 'invalid_token' });
    }
    try {
      req.touchqueToken = await login.verifyAccessToken(m[1], { audience, requiredScopes: scopes });
      return next();
    } catch (err) {
      const e = err as HostedLoginError;
      res.setHeader('WWW-Authenticate', `Bearer error="${e.code === 'insufficient_scope' ? 'insufficient_scope' : 'invalid_token'}"`);
      return res.status(e.code === 'insufficient_scope' ? 403 : 401).json({ error: e.code || 'invalid_token' });
    }
  };
}
