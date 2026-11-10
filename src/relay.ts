// src/relay.ts
//
// touchqueRouter for Next.js (App Router) and any Fetch-API runtime (Hono,
// Remix, SvelteKit, Bun, Deno, Cloudflare Workers with nodejs_compat): the
// same relay routes and checks, as one handler that takes a Request and
// returns a Response. No express needed.
//
//   // app/touchque/[...path]/route.ts
//   const relay = touchqueRelay(tq, {
//     getUserId: async () => (await auth())?.user?.email,
//     getLoginUser: async () => (await passwordStep())?.email,
//     ip: ipFromVercel,
//     onAuthenticated: async (req, info, headers) => { headers.append('Set-Cookie', await sessionCookie(info.externalUsername)); },
//   });
//   export { relay as GET, relay as POST, relay as DELETE };
//
// Endpoints (under `basePath`, default /touchque): the ones touchqueRouter
// mounts, with the same answers (see src/router.ts):
//   POST   /enroll/start, GET /enroll/status                       (auth required)
//   POST   /login                                                  (pre-auth) -> 202 { touchque: step, token } until approved
//   POST   /offline/challenge, /offline/verify, /offline/totp      (pre-auth; off until getLoginUser is set)
//   POST   /passkey/authenticate/options, /passkey/authenticate/verify, /passkey/login/options, /passkey/login/verify (pre-auth)
//   POST   /passkey/register/options, /passkey/register/verify     (auth required)
//   GET    /passkey/credentials, DELETE /passkey/credentials/:id   (auth required)
// Another path answers 404, a known path with another method 405.
//
// Set `getLoginUser`, exactly as for touchqueRouter: POST /login and the
// offline routes then act only for the user who passed YOUR first factor.
// Pre-auth routes are rate limited per IP and per username by default
// (`rateLimit`, the same FixedWindowLimiter). Fetch has no socket address:
// say where the end user's address comes from (`ip` or `trustedProxyHops`, as
// for withTouchQue). Without one the per-IP limits are skipped (the
// per-username ones stay) and no client IP is sent to Touchque.
//
// JSON bodies are read only with Content-Type application/json, at most 100 KiB.

import { TouchQue } from './index';
import { TouchQueRejectedError, TouchQueTimeoutError, TouchQuePasskeyRequiredError, TouchQueAPIError } from './errors';
import { runGuard, guardInputFromHeaders, isStatusPoll, silentInputFromHeaders, SilentSignInOptions, GuardBody } from './guard';
import type { LoginRequestDetails } from './types';
import { FixedWindowLimiter, RateLimitOptions } from './rateLimiter';
import { forwardedFor } from './next';
import { logOf } from './internal';
import { describeError, type SdkLog } from './core/HttpClient';

type MaybePromise<T> = T | Promise<T>;
// The parsed JSON body; its fields are passed through as touchqueRouter passes `req.body`'s.
type Body = Record<string, any>;

/** Reserved action: the approval on the phone that unlocks adding a passkey. */
const PASSKEY_ENROLL_ACTION = 'PASSKEY_ENROLL';
const MAX_BODY_BYTES = 100 * 1024;
// A 1.5 s poll for a 2-minute push is 80 requests: one attempt's worth of polls.
const POLLS_PER_ATTEMPT = 10;

export interface TouchQueRelayOptions {
  /**
   * Resolve the signed-in user's identifier for the "auth required" routes
   * (enrollment, passkey registration/management) from YOUR session. Return
   * nothing if there is no signed-in user — the route responds 401.
   */
  getUserId: (req: Request) => MaybePromise<string | undefined | null>;

  /**
   * STRONGLY RECOMMENDED. The user who has already passed your first factor
   * (e.g. the password step stored in the session). When set, POST /login,
   * POST /offline/challenge and POST /offline/totp use this user and IGNORE any
   * username in the request body; if it returns nothing they answer 401
   * FIRST_FACTOR_REQUIRED. Without it, anyone can type any user's email and
   * make Touchque push to that user's phone (push-bombing) or spend that
   * user's offline attempts.
   */
  getLoginUser?: (req: Request) => MaybePromise<string | undefined | null>;

  /**
   * Built-in limits for the pre-auth routes (per client IP and per username,
   * per route). On by default: 20 requests per IP and 5 per username per
   * minute. Pass `false` if you already rate limit in front of this handler.
   * The per-IP limits need `ip` or `trustedProxyHops`.
   */
  rateLimit?: RateLimitOptions | false;

  /**
   * End user's IP, for the per-IP limits and Touchque's risk checks. Default:
   * none, unless `trustedProxyHops` is set. Use a preset such as
   * `ipFromVercel` / `ipFromCloudflare`, or your own function reading a header
   * your platform overwrites. Never the leftmost X-Forwarded-For hop.
   */
  ip?: (req: Request) => string | undefined;

  /**
   * How many reverse proxies you run in front of this app. The client is the
   * X-Forwarded-For entry this many hops from the right. Ignored when `ip` is set.
   */
  trustedProxyHops?: number;

  /** Where the handler is mounted: the part of the path before the routes. Default '/touchque'. */
  basePath?: string;

  /**
   * The offline routes (/offline/challenge, /offline/verify, /offline/totp)
   * answer 403 OFFLINE_REQUIRES_FIRST_FACTOR unless `getLoginUser` is set.
   * Set this to `true` only if you really want them to trust the username in
   * the request body (e.g. your own gateway already authenticated the user).
   */
  allowOfflineWithoutFirstFactor?: boolean;

  /** LoginType passed to the classic-2FA POST /login route. Default: 'LOGIN'. */
  actionType?: string;

  /** Silent sign-ins for POST /login (default off); see touchqueRouter's `silentSignIn`. */
  silentSignIn?: boolean | SilentSignInOptions;

  /**
   * Optional transaction context for the classic-2FA POST /login push, shown
   * on the approval screen. Build it from your own server-side state — the
   * request body is attacker-controlled.
   */
  getDetails?: (req: Request) => MaybePromise<LoginRequestDetails | undefined>;

  /**
   * Called right before this handler answers success for POST /login (once
   * approved), the offline routes, or a passkey sign-in — the one place to open
   * your session. `headers` go out on that success response: append your
   * `Set-Cookie` there (or use your framework's cookie API, e.g. Next's `cookies()`).
   */
  onAuthenticated?: (
    req: Request,
    info: { externalUsername: string; requestId?: string; via: 'login' | 'passkey' | 'offline' | 'offline-totp' | 'silent' },
    headers: Headers,
  ) => void | Promise<void>;
}

function json(body: unknown, status = 200, extra?: Headers | Record<string, string>): Response {
  const headers = new Headers(extra);
  headers.set('Content-Type', 'application/json');
  headers.set('Cache-Control', 'no-store');
  return new Response(JSON.stringify(body), { status, headers });
}

/** Same status-code mapping as touchqueRouter (and requireTouchQue) — kept in sync. */
function authResultError(error: unknown, log: SdkLog): Response {
  if (error instanceof TouchQueRejectedError) {
    return json({ error: '2FA_REJECTED', message: 'User rejected the 2FA request on their device.' }, 403);
  }
  if (error instanceof TouchQuePasskeyRequiredError) {
    return json({ error: 'PASSKEY_REQUIRED', requestId: error.requestId, message: 'Approve this sign-in with your passkey.' }, 409);
  }
  if (error instanceof TouchQueTimeoutError) {
    return json({ error: '2FA_TIMEOUT', message: 'User did not respond to the 2FA request in time.' }, 408);
  }
  const apiErr = error as { status?: number; data?: { error?: string; message?: string }; message?: string };
  if (typeof apiErr.status === 'number' && apiErr.status < 500) {
    return json({ error: apiErr.data?.error || apiErr.data?.message || apiErr.message || 'request_failed' }, apiErr.status);
  }
  log.error(`[TouchQue Relay Error] ${describeError(error)}`);
  return json({ error: '2FA_UNAVAILABLE', message: 'The 2FA verification service is temporarily unavailable.' }, 503);
}

/** A client-range Touchque status with its machine-readable code only (never Touchque's message text); anything else 502. */
function relayError(error: unknown): Response {
  if (error instanceof TouchQueAPIError && error.status < 500) {
    return json({ error: error.code || (error.data as { error?: string })?.error || 'request_failed' }, error.status);
  }
  return json({ error: 'relay_error' }, 502);
}

/** The guard's answer while not approved: 202 with the step, or the refusal. */
function guardResponse(result: { status: number; body: GuardBody }): Response {
  const retryAfter = result.body.touchque.retryAfter;
  return json(result.body, result.status, retryAfter ? { 'Retry-After': String(retryAfter) } : undefined);
}

/** The JSON body (application/json only, at most 100 KiB), or the 400/413 to answer. */
async function readBody(req: Request): Promise<Body | Response> {
  const type = (req.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
  if (type !== 'application/json' || !req.body) return {};
  if (Number(req.headers.get('content-length')) > MAX_BODY_BYTES) return json({ error: 'payload_too_large' }, 413);
  const reader = req.body.getReader();
  const decoder = new TextDecoder();
  let size = 0;
  let text = '';
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BODY_BYTES) {
        await reader.cancel().catch(() => undefined);
        return json({ error: 'payload_too_large' }, 413);
      }
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
  } catch {
    return json({ error: 'invalid_body' }, 400);
  }
  if (!text.trim()) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return json({ error: 'invalid_json' }, 400);
  }
  // Like express.json(): an object or an array (which names no fields), nothing else.
  if (Array.isArray(parsed)) return {};
  if (!parsed || typeof parsed !== 'object') return json({ error: 'invalid_json' }, 400);
  return parsed as Body;
}

let warnedPreAuth = false;
let warnedNoIp = false;

export function touchqueRelay(tq: TouchQue, options: TouchQueRelayOptions): (req: Request) => Promise<Response> {
  const { getUserId, getLoginUser, actionType = 'LOGIN', onAuthenticated, getDetails } = options;
  const basePath = (options.basePath ?? '/touchque').replace(/\/+$/, '');
  const limiter = options.rateLimit === false ? null : new FixedWindowLimiter(options.rateLimit || {});
  const offlineEnabled = Boolean(getLoginUser) || options.allowOfflineWithoutFirstFactor === true;
  const ipOf = (req: Request): string | undefined => (options.ip ? options.ip(req) : forwardedFor(req, options.trustedProxyHops ?? 0));

  if (!getLoginUser && !warnedPreAuth) {
    warnedPreAuth = true;
    logOf(tq).warn('[TouchQue] touchqueRelay: POST /login takes the username from the request body'
      + (offlineEnabled ? ', and so do the offline routes' : '; the offline routes are disabled until you set it')
      + '. Set `getLoginUser` to bind them to your first factor (password step) so they cannot be used against arbitrary users.');
  }
  if (limiter && !options.ip && !(options.trustedProxyHops && options.trustedProxyHops > 0) && !warnedNoIp) {
    warnedNoIp = true;
    logOf(tq).warn('[TouchQue] touchqueRelay: no client address (set `ip` or `trustedProxyHops`), so the per-IP limits are off; the per-username limits stay.');
  }

  const requireUserId = async (req: Request): Promise<string | Response> => {
    const userId = await getUserId(req);
    if (!userId) {
      return json({
        error: 'UNAUTHORIZED_FOR_2FA',
        message: 'Could not find user ID in request. Resolve it from your session in getUserId.',
      }, 401);
    }
    return userId;
  };

  /** The 403 when the offline routes are not enabled, otherwise null. */
  const offlineRefused = (): Response | null => (offlineEnabled ? null : json({
    error: 'OFFLINE_REQUIRES_FIRST_FACTOR',
    message: 'Offline sign-in is disabled: configure getLoginUser (or allowOfflineWithoutFirstFactor) on the Touchque relay.',
  }, 403));

  /** The 429 when this IP or this user is over the limit for `route`, otherwise null. */
  const limited = (ip: string | undefined, route: string, user?: string, perIp?: number): Response | null => {
    if (!limiter) return null;
    const ipWait = ip ? limiter.hit(`ip|${route}|${ip}`, perIp ?? limiter.perIp) : 0;
    const userWait = user ? limiter.hit(`user|${route}|${user}`, limiter.perUser) : 0;
    const wait = Math.max(ipWait, userWait);
    if (!wait) return null;
    return json({ error: 'RATE_LIMITED', message: 'Too many attempts. Try again later.', retryAfter: wait }, 429, { 'Retry-After': String(wait) });
  };

  /** Who a pre-auth route acts for: the first-factor user when configured, otherwise the typed username. */
  const loginUser = async (req: Request, body: Body, bodyField: string): Promise<string | Response> => {
    if (getLoginUser) {
      const u = await getLoginUser(req);
      if (!u) return json({ error: 'FIRST_FACTOR_REQUIRED', message: 'Sign in with your password first.' }, 401);
      return String(u).toLowerCase();
    }
    const typed = String(body?.[bodyField] || '').toLowerCase();
    if (!typed) return json({ error: 'externalUsername_required' }, 400);
    return typed;
  };

  /** True when the first-factor user (if configured) is the one Touchque names. */
  const sameLoginUser = async (req: Request, named: string): Promise<boolean> => {
    if (!getLoginUser) return true;
    const expected = await getLoginUser(req);
    return Boolean(expected) && String(expected).toLowerCase() === named.toLowerCase();
  };

  const userAgentOf = (req: Request) => req.headers.get('user-agent') ?? undefined;
  const header = (req: Request) => (name: string) => req.headers.get(name);
  const requestIdOf = (body: Body) => (typeof body?.requestId === 'string' && body.requestId ? body.requestId : undefined);

  type Handler = (req: Request, body: Body, param: string) => Promise<Response>;

  // ── Classic push 2FA: enrollment ──────────────────────────────────────
  const enrollStart: Handler = async (req) => {
    const userId = await requireUserId(req);
    if (typeof userId !== 'string') return userId;
    try {
      return json(await tq.auth.generateSecret({ externalUsername: userId }));
    } catch (error) {
      // 409: a QR not scanned yet (safe to issue a new one) or a phone ALREADY
      // linked, which a plain session must never replace.
      if ((error as { status?: number }).status === 409) {
        try {
          const current = await tq.auth.getUser({ externalUsername: userId });
          if (current.used || current.deviceId) return json({ error: 'already_linked', message: 'A phone is already linked to this account.' }, 409);
          return json(await tq.auth.resetSecret({ externalUsername: userId }));
        } catch (retryError) {
          return relayError(retryError);
        }
      }
      return relayError(error);
    }
  };

  const enrollStatus: Handler = async (req) => {
    const userId = await requireUserId(req);
    if (typeof userId !== 'string') return userId;
    try {
      const u = await tq.auth.getUser({ externalUsername: userId });
      return json({ linked: Boolean(u.used && u.deviceId), used: u.used, deviceId: u.deviceId });
    } catch (error) {
      if ((error as { status?: number }).status === 404) return json({ linked: false, used: false, deviceId: null });
      return relayError(error);
    }
  };

  // ── Classic push 2FA: login (same two-phase contract as requireTouchQue) ──
  const login: Handler = async (req, body) => {
    const externalUsername = await loginUser(req, body, 'externalUsername');
    if (typeof externalUsername !== 'string') return externalUsername;
    const ip = ipOf(req);
    const input = {
      user: externalUsername,
      action: actionType,
      // Pre-auth: a typed username proves nothing, so no linking QR unless
      // getLoginUser ties this route to the password step.
      enroll: Boolean(getLoginUser),
      details: getDetails ? await getDetails(req) : undefined,
      ip,
      userAgent: userAgentOf(req),
      ...guardInputFromHeaders(header(req)),
      ...silentInputFromHeaders(options.silentSignIn, header(req)),
    };
    // Polling an approval already sent is not a new attempt: its own, larger per-IP budget, never the user's.
    const refused = isStatusPoll(tq, input)
      ? limited(ip, 'login-poll', undefined, (limiter?.perIp ?? 0) * POLLS_PER_ATTEMPT)
      : limited(ip, 'login', externalUsername);
    if (refused) return refused;
    const result = await runGuard(tq, input);
    if (!result.approved) return guardResponse(result);
    const headers = new Headers();
    try {
      if (onAuthenticated) {
        const via = result.approved.confirmedVia === 'OFFLINE_TOTP' ? 'offline-totp'
          : result.approved.confirmedVia === 'OFFLINE_CODE' ? 'offline'
            : result.approved.confirmedVia === 'SILENT' ? 'silent' : 'login';
        await onAuthenticated(req, { externalUsername, requestId: result.approved.requestId, via }, headers);
      }
      return json({ status: 'success', requestId: result.approved.requestId, assurance: result.approved.assurance }, 200, headers);
    } catch (error) {
      return authResultError(error, logOf(tq));
    }
  };

  // ── Offline Sign: QR challenge / typed code. The username for onAuthenticated
  //    is the one Touchque returns, never the one in the request body. ──
  const offlineChallenge: Handler = async (req, body) => {
    const off = offlineRefused();
    if (off) return off;
    const externalUsername = await loginUser(req, body, 'externalUsername');
    if (typeof externalUsername !== 'string') return externalUsername;
    const ip = ipOf(req);
    const refused = limited(ip, 'offline-challenge', externalUsername);
    if (refused) return refused;
    try {
      const c = await tq.offline.challenge({
        externalUsername,
        type: actionType,
        clientIp: ip,
        userAgent: userAgentOf(req),
        details: getDetails ? await getDetails(req) : undefined,
        requestId: requestIdOf(body),
      });
      return json({
        challengeId: c.challengeId, qr: c.qr, qrDataUrl: c.qrDataUrl, expiresAt: c.expiresAt, expiresInSeconds: c.expiresInSeconds, totpAvailable: c.totpAvailable,
        ...(c.challengeCode && { challengeCode: c.challengeCode }),
      });
    } catch (error) {
      return relayError(error);
    }
  };

  const offlineVerify: Handler = async (req, body) => {
    const refused = offlineRefused() || limited(ipOf(req), 'offline-verify');
    if (refused) return refused;
    try {
      const r = await tq.offline.verify({ challengeId: String(body?.challengeId || ''), code: String(body?.code || '') });
      if (!r.approved || !r.externalUsername) {
        return json({ approved: false, reason: r.reason, attemptsLeft: r.attemptsLeft }, r.reason === 'invalid_code' ? 401 : 400);
      }
      // With a first factor, the code must belong to the user who passed it.
      if (!(await sameLoginUser(req, r.externalUsername))) return json({ approved: false, reason: 'invalid_code' }, 401);
      const headers = new Headers();
      if (onAuthenticated) await onAuthenticated(req, { externalUsername: r.externalUsername, requestId: r.challengeId, via: 'offline' }, headers);
      return json({ status: 'success', approved: true, requestId: r.challengeId }, 200, headers);
    } catch (error) {
      return relayError(error);
    }
  };

  const offlineTotp: Handler = async (req, body) => {
    const off = offlineRefused();
    if (off) return off;
    const externalUsername = await loginUser(req, body, 'externalUsername');
    if (typeof externalUsername !== 'string') return externalUsername;
    const ip = ipOf(req);
    const refused = limited(ip, 'offline-totp', externalUsername);
    if (refused) return refused;
    try {
      const r = await tq.offline.verifyTotp({
        externalUsername,
        code: String(body?.code || ''),
        type: actionType,
        clientIp: ip,
        requestId: requestIdOf(body),
      });
      if (!r.approved || !r.externalUsername) return json({ approved: false, reason: r.reason }, r.reason === 'invalid_code' ? 401 : 400);
      const headers = new Headers();
      if (onAuthenticated) await onAuthenticated(req, { externalUsername: r.externalUsername, via: 'offline-totp' }, headers);
      return json({ status: 'success', approved: true }, 200, headers);
    } catch (error) {
      return relayError(error);
    }
  };

  // ── Passkey: passwordless sign-in (identity is the typed email, or, with
  //    no email, the passkey the user picks from autofill) ──
  const passkeyOptions: Handler = async (req, body) => {
    const email = String(body?.email || '').toLowerCase();
    const refused = limited(ipOf(req), 'passkey-options', email || undefined);
    if (refused) return refused;
    try {
      return json(await tq.webauthn.primaryOptions(email ? { externalUsername: email } : {}));
    } catch (error) {
      return relayError(error);
    }
  };

  const passkeyVerify: Handler = async (req, body) => {
    const refused = limited(ipOf(req), 'passkey-verify');
    if (refused) return refused;
    try {
      const r = await tq.webauthn.primaryVerify({ attemptId: body?.attemptId, response: body?.response });
      if (r.success) {
        const headers = new Headers();
        if (onAuthenticated) await onAuthenticated(req, { externalUsername: r.externalUsername, requestId: r.requestId, via: 'passkey' }, headers);
        return json({ status: 'success', requestId: r.requestId }, 200, headers);
      }
      if (r.requiresStepUp) return json({ requiresStepUp: true });
      return json({ error: 'verification_failed' }, 401);
    } catch (error) {
      return relayError(error);
    }
  };

  // ── Passkey: approve an already-pending 2FA request (`@touchque/web`'s
  //    `passkeys.approveLogin({ requestId })`) ──
  const passkeyApproveOptions: Handler = async (req, body) => {
    const refused = limited(ipOf(req), 'passkey-approve');
    if (refused) return refused;
    try {
      return json(await tq.webauthn.authenticateOptions({ requestId: body?.requestId }));
    } catch (error) {
      return relayError(error);
    }
  };

  const passkeyApproveVerify: Handler = async (req, body) => {
    const refused = limited(ipOf(req), 'passkey-approve');
    if (refused) return refused;
    try {
      const r = await tq.webauthn.authenticateVerify({ requestId: body?.requestId, response: body?.response });
      // Open the session only for the user Touchque says was approved, never a name the browser sent.
      if (r.success && typeof r.externalUsername === 'string' && !(await sameLoginUser(req, r.externalUsername))) {
        return json({ error: 'verification_failed' }, 401);
      }
      const headers = new Headers();
      if (r.success && onAuthenticated && typeof r.externalUsername === 'string' && r.externalUsername) {
        await onAuthenticated(req, { externalUsername: r.externalUsername, requestId: r.requestId || body?.requestId, via: 'passkey' }, headers);
      }
      return json(r, 200, headers);
    } catch (error) {
      return relayError(error);
    }
  };

  // ── Passkey: enrollment / management. A user with a linked phone approves
  //    adding a passkey there first (same two-phase contract as /login). ──
  const passkeyRegisterOptions: Handler = async (req) => {
    const userId = await requireUserId(req);
    if (typeof userId !== 'string') return userId;
    const ip = ipOf(req);
    const input = {
      user: userId, action: PASSKEY_ENROLL_ACTION, enroll: false, ip, userAgent: userAgentOf(req),
      ...guardInputFromHeaders(header(req)),
    };
    try {
      if (!input.token) {
        try {
          return json(await tq.webauthn.registerOptions({ externalUsername: userId, discoverable: true }));
        } catch (error) {
          if (!(error instanceof TouchQueAPIError && error.status === 403 && error.code === 'enrollment_approval_required')) throw error;
        }
      }
      const refused = isStatusPoll(tq, input)
        ? limited(ip, 'login-poll', undefined, (limiter?.perIp ?? 0) * POLLS_PER_ATTEMPT)
        : limited(ip, 'passkey-enroll', userId);
      if (refused) return refused;
      const result = await runGuard(tq, input);
      if (!result.approved) return guardResponse(result);
      return json(await tq.webauthn.registerOptions({ externalUsername: userId, discoverable: true, approvalRequestId: result.approved.requestId }));
    } catch (error) {
      return relayError(error);
    }
  };

  const passkeyRegisterVerify: Handler = async (req, body) => {
    const userId = await requireUserId(req);
    if (typeof userId !== 'string') return userId;
    try {
      return json(await tq.webauthn.registerVerify({ externalUsername: userId, response: body?.response, label: body?.label }));
    } catch (error) {
      return relayError(error);
    }
  };

  const passkeyCredentials: Handler = async (req) => {
    const userId = await requireUserId(req);
    if (typeof userId !== 'string') return userId;
    try {
      return json(await tq.webauthn.listCredentials({ externalUsername: userId }));
    } catch (error) {
      return relayError(error);
    }
  };

  const passkeyDeleteCredential: Handler = async (req, _body, id) => {
    const userId = await requireUserId(req);
    if (typeof userId !== 'string') return userId;
    try {
      return json(await tq.webauthn.deleteCredential(id, { externalUsername: userId }));
    } catch (error) {
      return relayError(error);
    }
  };

  const routes: Record<string, Record<string, Handler>> = {
    '/enroll/start': { POST: enrollStart },
    '/enroll/status': { GET: enrollStatus },
    '/login': { POST: login },
    '/offline/challenge': { POST: offlineChallenge },
    '/offline/verify': { POST: offlineVerify },
    '/offline/totp': { POST: offlineTotp },
    '/passkey/authenticate/options': { POST: passkeyOptions },
    '/passkey/authenticate/verify': { POST: passkeyVerify },
    '/passkey/login/options': { POST: passkeyApproveOptions },
    '/passkey/login/verify': { POST: passkeyApproveVerify },
    '/passkey/register/options': { POST: passkeyRegisterOptions },
    '/passkey/register/verify': { POST: passkeyRegisterVerify },
    '/passkey/credentials': { GET: passkeyCredentials },
  };
  const CREDENTIAL = /^\/passkey\/credentials\/([^/]+)$/;

  return async (req: Request): Promise<Response> => {
    const pathname = new URL(req.url).pathname;
    if (basePath && pathname !== basePath && !pathname.startsWith(`${basePath}/`)) return json({ error: 'not_found' }, 404);
    const path = pathname.slice(basePath.length).replace(/\/+$/, '') || '/';
    let methods = routes[path];
    let param = '';
    const credential = methods ? null : CREDENTIAL.exec(path);
    if (credential) {
      try {
        param = decodeURIComponent(credential[1]);
      } catch {
        return json({ error: 'not_found' }, 404);
      }
      methods = { DELETE: passkeyDeleteCredential };
    }
    if (!methods) return json({ error: 'not_found' }, 404);
    const handler = methods[req.method.toUpperCase()];
    if (!handler) return json({ error: 'method_not_allowed' }, 405, { Allow: Object.keys(methods).join(', ') });
    const body = req.method.toUpperCase() === 'GET' ? {} : await readBody(req);
    if (body instanceof Response) return body;
    return handler(req, body, param);
  };
}
