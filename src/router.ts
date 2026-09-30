// src/router.ts
//
// A mountable Express Router that wires the ~9 relay routes every partner
// backend needs for classic push 2FA + passkeys — the exact routes
// `@touchque/web`'s README previously told every partner to hand-copy (see
// its "Minimal Express relay" example). Nothing here is
// partner-specific except how you resolve the signed-in user (`getUserId`)
// and what you do once someone is authenticated (`onAuthenticated`).
//
//   app.use('/touchque', touchqueRouter(tq, {
//     getUserId: (req) => req.session.user?.email,
//     onAuthenticated: (req, res, info) => { req.session.authenticated = true; },
//   }));
//
// Endpoints mounted (relative to wherever you app.use() this router):
//   POST   /enroll/start                    (auth required) -> GenerateSecretResponse
//   GET    /enroll/status                   (auth required) -> { linked, used, deviceId }
//   POST   /login                           (pre-auth) -> 202 { touchque: step, token } until approved (same contract as requireTouchQue)
//   POST   /offline/challenge               (pre-auth, body.externalUsername) -> QR for a phone with no internet
//   POST   /offline/verify                  (pre-auth, body.challengeId/code)
//   POST   /offline/totp                    (pre-auth, body.externalUsername/code) -> time-based code fallback
//   POST   /passkey/authenticate/options    (pre-auth, body.externalUsername)
//   POST   /passkey/authenticate/verify     (pre-auth, body.attemptId/response)
//   POST   /passkey/login/options           (pre-auth, body.requestId — approve a pending 2FA request)
//   POST   /passkey/login/verify            (pre-auth, body.requestId/response[/externalUsername])
//   POST   /passkey/register/options        (auth required)
//   POST   /passkey/register/verify         (auth required)
//   GET    /passkey/credentials             (auth required)
//   DELETE /passkey/credentials/:id         (auth required)
//
// "auth required" routes 401 with UNAUTHORIZED_FOR_2FA if `getUserId(req)`
// returns nothing — put your own session/auth middleware in front of this
// router (or have `getUserId` itself check and return undefined).
//
// Pre-auth routes are rate limited per IP and per username by default
// (`rateLimit`), and TouchQue itself caps approval pushes per user. Set
// `getLoginUser` so POST /login and the offline routes only work for a user
// who already passed YOUR first factor (password step): then nobody can make
// TouchQue push to, or lock out, an arbitrary user through your server.
// The offline routes are OFF until you do (or explicitly opt out with
// `allowOfflineWithoutFirstFactor`): with the username taken from the body,
// anyone could burn a user's offline attempts and lock them out.

import { Router, Request, Response } from 'express';
import { TouchQue } from './index';
import { TouchQueRejectedError, TouchQueTimeoutError, TouchQuePasskeyRequiredError, TouchQueAPIError } from './errors';
import { runGuard, guardInputFromHeaders } from './guard';
import type { LoginRequestDetails } from './types';
import { FixedWindowLimiter, RateLimitOptions } from './rateLimiter';

export interface TouchQueRouterOptions {
  /**
   * Resolve the signed-in user's identifier for the "auth required" routes
   * (enrollment, passkey registration/management). Return `undefined` if
   * there is no signed-in user — the route responds 401.
   */
  getUserId: (req: Request) => string | undefined;

  /**
   * STRONGLY RECOMMENDED. The user who has already passed your first factor
   * (e.g. the password step stored in the session). When set, POST /login,
   * POST /offline/challenge and POST /offline/totp use this user and IGNORE any
   * username in the request body; if it returns nothing they answer 401
   * FIRST_FACTOR_REQUIRED. Without it, anyone can type any user's email and
   * make TouchQue push to that user's phone (push-bombing) or spend that
   * user's offline attempts.
   */
  getLoginUser?: (req: Request) => string | undefined | Promise<string | undefined>;

  /**
   * Built-in limits for the pre-auth routes (per client IP and per username,
   * per route). On by default: 20 requests per IP and 5 per username per
   * minute. Pass `false` if you already rate limit in front of this router.
   * `req.ip` must be the real client (configure Express `trust proxy`).
   */
  rateLimit?: RateLimitOptions | false;

  /**
   * The offline routes (/offline/challenge, /offline/verify, /offline/totp)
   * answer 403 OFFLINE_REQUIRES_FIRST_FACTOR unless `getLoginUser` is set.
   * Set this to `true` only if you really want them to trust the username in
   * the request body (e.g. your own gateway already authenticated the user).
   */
  allowOfflineWithoutFirstFactor?: boolean;

  /** LoginType passed to the classic-2FA POST /login route. Default: 'LOGIN'. */
  actionType?: string;

  /** @deprecated no effect — POST /login no longer holds the request open; the page polls with the token. */
  loginTimeout?: number;

  /**
   * Optional transaction context for the classic-2FA POST /login push,
   * shown on the approval screen (see `LoginRequestOptions.details`). Build
   * it from your own server-side state — anything read from `req.body` here
   * is attacker-controlled.
   */
  getDetails?: (req: Request) => LoginRequestDetails | undefined | Promise<LoginRequestDetails | undefined>;

  /**
   * Called right before this router sends its own success response for
   * POST /login (once approved) or POST /passkey/authenticate/verify (once
   * verified) — the one place a partner almost always needs to do
   * something (open a session cookie, etc.). Mutate `res` here (e.g.
   * `res.cookie(...)`); do not call `res.json()`/`res.send()` yourself —
   * the router does that right after.
   */
  onAuthenticated?: (
    req: Request,
    res: Response,
    info: { externalUsername: string; requestId?: string; via: 'login' | 'passkey' | 'offline' | 'offline-totp' }
  ) => void | Promise<void>;
}

/** Same status-code mapping as requireTouchQue's middleware — kept in sync. */
function sendAuthResultError(res: Response, error: unknown): void {
  if (error instanceof TouchQueRejectedError) {
    res.status(403).json({ error: '2FA_REJECTED', message: 'User rejected the 2FA request on their device.' });
    return;
  }
  if (error instanceof TouchQuePasskeyRequiredError) {
    res.status(409).json({ error: 'PASSKEY_REQUIRED', requestId: error.requestId, message: 'Approve this sign-in with your passkey.' });
    return;
  }
  if (error instanceof TouchQueTimeoutError) {
    res.status(408).json({ error: '2FA_TIMEOUT', message: 'User did not respond to the 2FA request in time.' });
    return;
  }
  // A real TouchQueAPIError (e.g. 404 "no linked device for this user")
  // still carries a useful client-range status + message — surface it
  // instead of collapsing every non-reject/timeout error into an opaque
  // "unavailable". Only a genuine network failure or unexpected error
  // falls through to 503.
  const apiErr = error as { status?: number; data?: { error?: string; message?: string }; message?: string };
  if (typeof apiErr.status === 'number' && apiErr.status < 500) {
    res.status(apiErr.status).json({ error: apiErr.data?.error || apiErr.data?.message || apiErr.message || 'request_failed' });
    return;
  }
  console.error('[TouchQue Router Error]', error);
  res.status(503).json({ error: '2FA_UNAVAILABLE', message: 'The 2FA verification service is temporarily unavailable.' });
}

/**
 * For plain relay routes (enroll, passkey): a client-range TouchQue status is
 * forwarded with its machine-readable code only — never TouchQue's internal
 * message text — anything else becomes 502.
 */
function sendRelayError(res: Response, error: unknown): void {
  if (error instanceof TouchQueAPIError && error.status < 500) {
    res.status(error.status).json({ error: error.code || (error.data as { error?: string })?.error || 'request_failed' });
    return;
  }
  res.status(502).json({ error: 'relay_error' });
}

function requireUserId(req: Request, res: Response, getUserId: TouchQueRouterOptions['getUserId']): string | undefined {
  const userId = getUserId(req);
  if (!userId) {
    res.status(401).json({
      error: 'UNAUTHORIZED_FOR_2FA',
      message: 'Could not find user ID in request. Put your own auth middleware in front of this router.',
    });
    return undefined;
  }
  return userId;
}

let warnedPreAuth = false;

export function touchqueRouter(tq: TouchQue, options: TouchQueRouterOptions): Router {
  const { getUserId, getLoginUser, actionType = 'LOGIN', onAuthenticated, getDetails } = options;
  const router = Router();
  const limiter = options.rateLimit === false ? null : new FixedWindowLimiter(options.rateLimit || {});

  const offlineEnabled = Boolean(getLoginUser) || options.allowOfflineWithoutFirstFactor === true;

  if (!getLoginUser && !warnedPreAuth) {
    warnedPreAuth = true;
    console.warn('[TouchQue] touchqueRouter: POST /login takes the username from the request body'
      + (offlineEnabled ? ', and so do the offline routes' : '; the offline routes are disabled until you set it')
      + '. Set `getLoginUser` to bind them to your first factor (password step) so they cannot be used against arbitrary users.');
  }

  /** Answers 403 and returns false when the offline routes are not enabled. */
  const offlineAllowed = (res: Response): boolean => {
    if (offlineEnabled) return true;
    res.status(403).json({
      error: 'OFFLINE_REQUIRES_FIRST_FACTOR',
      message: 'Offline sign-in is disabled: configure getLoginUser (or allowOfflineWithoutFirstFactor) on the TouchQue router.',
    });
    return false;
  };

  /** Answers 429 and returns false when this IP or this user is over the limit for `route`. */
  const allow = (req: Request, res: Response, route: string, user?: string): boolean => {
    if (!limiter) return true;
    const ipWait = limiter.hit(`ip|${route}|${req.ip || 'unknown'}`, limiter.perIp);
    const userWait = user ? limiter.hit(`user|${route}|${user}`, limiter.perUser) : 0;
    const wait = Math.max(ipWait, userWait);
    if (!wait) return true;
    res.set('Retry-After', String(wait));
    res.status(429).json({ error: 'RATE_LIMITED', message: 'Too many attempts. Try again later.', retryAfter: wait });
    return false;
  };

  /** Who a pre-auth route acts for: the first-factor user when configured, otherwise the typed username. */
  const loginUser = async (req: Request, res: Response, bodyField: string): Promise<string | undefined> => {
    if (getLoginUser) {
      const u = await getLoginUser(req);
      if (!u) {
        res.status(401).json({ error: 'FIRST_FACTOR_REQUIRED', message: 'Sign in with your password first.' });
        return undefined;
      }
      return String(u).toLowerCase();
    }
    const typed = String(req.body?.[bodyField] || '').toLowerCase();
    if (!typed) {
      res.status(400).json({ error: 'externalUsername_required' });
      return undefined;
    }
    return typed;
  };

  // ── Classic push 2FA: enrollment ──────────────────────────────────────
  router.post('/enroll/start', async (req, res) => {
    const userId = requireUserId(req, res, getUserId);
    if (!userId) return;
    try {
      res.json(await tq.auth.generateSecret({ externalUsername: userId }));
    } catch (error) {
      const err = error as { status?: number };
      // 409: either a QR was issued and not scanned yet (safe to issue a new
      // one — no phone to lose), or a phone is ALREADY linked. Replacing a
      // linked phone must never happen from a plain session: that is exactly
      // how an attacker with a stolen password would swap in their own phone.
      if (err.status === 409) {
        try {
          const current = await tq.auth.getUser({ externalUsername: userId });
          if (current.used || current.deviceId) {
            res.status(409).json({ error: 'already_linked', message: 'A phone is already linked to this account.' });
            return;
          }
          res.json(await tq.auth.resetSecret({ externalUsername: userId }));
          return;
        } catch (retryError) {
          sendRelayError(res, retryError);
          return;
        }
      }
      sendRelayError(res, error);
    }
  });

  router.get('/enroll/status', async (req, res) => {
    const userId = requireUserId(req, res, getUserId);
    if (!userId) return;
    try {
      const u = await tq.auth.getUser({ externalUsername: userId });
      res.json({ linked: Boolean(u.used && u.deviceId), used: u.used, deviceId: u.deviceId });
    } catch (error) {
      const err = error as { status?: number };
      if (err.status === 404) {
        res.json({ linked: false, used: false, deviceId: null });
        return;
      }
      sendRelayError(res, error);
    }
  });

  // ── Classic push 2FA: login ───────────────────────────────────────────
  router.post('/login', async (req, res) => {
    const externalUsername = await loginUser(req, res, 'externalUsername');
    if (!externalUsername || !allow(req, res, 'login', externalUsername)) return;
    // Same two-phase contract as requireTouchQue: 202 with the step (matching
    // number / first-time QR / offline QR) until approved; the page re-sends
    // with X-TouchQue-Token. `req.ip` is only the real end-user address when
    // this app sets `trust proxy` for its deployment.
    const result = await runGuard(tq, {
      user: externalUsername,
      action: actionType,
      details: getDetails ? await getDetails(req) : undefined,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      ...guardInputFromHeaders((name) => req.get(name)),
    });
    if (!result.approved) {
      if (result.body.touchque.retryAfter) res.set('Retry-After', String(result.body.touchque.retryAfter));
      res.set('Cache-Control', 'no-store');
      res.status(result.status).json(result.body);
      return;
    }
    try {
      if (onAuthenticated) {
        const via = result.approved.confirmedVia === 'OFFLINE_TOTP' ? 'offline-totp' : result.approved.confirmedVia === 'OFFLINE_CODE' ? 'offline' : 'login';
        await onAuthenticated(req, res, { externalUsername, requestId: result.approved.requestId, via });
      }
      res.json({ status: 'success', requestId: result.approved.requestId, assurance: result.approved.assurance });
    } catch (error) {
      sendAuthResultError(res, error);
    }
  });

  // ── Offline Sign: QR challenge / typed code (pre-auth — identity is the typed email) ──
  // The username used for onAuthenticated is the one TouchQue returns for the
  // challenge/code, never the one in the request body.
  router.post('/offline/challenge', async (req, res) => {
    if (!offlineAllowed(res)) return;
    const externalUsername = await loginUser(req, res, 'externalUsername');
    if (!externalUsername || !allow(req, res, 'offline-challenge', externalUsername)) return;
    try {
      // `requestId` (the push this QR follows) makes a phone-side rejection kill the QR and carries the number.
      const requestId = typeof req.body?.requestId === 'string' && req.body.requestId ? req.body.requestId : undefined;
      const c = await tq.offline.challenge({
        externalUsername,
        type: actionType,
        clientIp: req.ip,
        userAgent: req.get('user-agent'),
        details: getDetails ? await getDetails(req) : undefined,
        requestId,
      });
      res.json({
        challengeId: c.challengeId, qr: c.qr, qrDataUrl: c.qrDataUrl, expiresAt: c.expiresAt, expiresInSeconds: c.expiresInSeconds, totpAvailable: c.totpAvailable,
        ...(c.challengeCode && { challengeCode: c.challengeCode }),
      });
    } catch (error) {
      sendRelayError(res, error);
    }
  });

  router.post('/offline/verify', async (req, res) => {
    if (!offlineAllowed(res) || !allow(req, res, 'offline-verify')) return;
    try {
      const r = await tq.offline.verify({ challengeId: String(req.body?.challengeId || ''), code: String(req.body?.code || '') });
      if (!r.approved || !r.externalUsername) {
        res.status(r.reason === 'invalid_code' ? 401 : 400).json({ approved: false, reason: r.reason, attemptsLeft: r.attemptsLeft });
        return;
      }
      // With a first factor, the code must belong to the user who passed it.
      if (getLoginUser) {
        const expected = await getLoginUser(req);
        if (!expected || String(expected).toLowerCase() !== r.externalUsername.toLowerCase()) {
          res.status(401).json({ approved: false, reason: 'invalid_code' });
          return;
        }
      }
      if (onAuthenticated) {
        await onAuthenticated(req, res, { externalUsername: r.externalUsername, requestId: r.challengeId, via: 'offline' });
      }
      res.json({ status: 'success', approved: true, requestId: r.challengeId });
    } catch (error) {
      sendRelayError(res, error);
    }
  });

  router.post('/offline/totp', async (req, res) => {
    if (!offlineAllowed(res)) return;
    const externalUsername = await loginUser(req, res, 'externalUsername');
    if (!externalUsername || !allow(req, res, 'offline-totp', externalUsername)) return;
    try {
      const r = await tq.offline.verifyTotp({
        externalUsername,
        code: String(req.body?.code || ''),
        type: actionType,
        clientIp: req.ip,
        requestId: typeof req.body?.requestId === 'string' && req.body.requestId ? req.body.requestId : undefined,
      });
      if (!r.approved || !r.externalUsername) {
        res.status(r.reason === 'invalid_code' ? 401 : 400).json({ approved: false, reason: r.reason });
        return;
      }
      if (onAuthenticated) {
        await onAuthenticated(req, res, { externalUsername: r.externalUsername, via: 'offline-totp' });
      }
      res.json({ status: 'success', approved: true });
    } catch (error) {
      sendRelayError(res, error);
    }
  });

  // ── Passkey: passwordless sign-in (pre-auth — identity is the typed email) ──
  router.post('/passkey/authenticate/options', async (req, res) => {
    const email = String(req.body?.email || '').toLowerCase();
    if (!allow(req, res, 'passkey-options', email || undefined)) return;
    try {
      res.json(await tq.webauthn.primaryOptions({ externalUsername: email }));
    } catch (error) {
      sendRelayError(res, error);
    }
  });

  router.post('/passkey/authenticate/verify', async (req, res) => {
    if (!allow(req, res, 'passkey-verify')) return;
    try {
      const r = await tq.webauthn.primaryVerify({ attemptId: req.body?.attemptId, response: req.body?.response });
      if (r.success) {
        if (onAuthenticated) {
          await onAuthenticated(req, res, { externalUsername: r.externalUsername, requestId: r.requestId, via: 'passkey' });
        }
        res.json({ status: 'success', requestId: r.requestId });
      } else if (r.requiresStepUp) {
        res.json({ requiresStepUp: true });
      } else {
        res.status(401).json({ error: 'verification_failed' });
      }
    } catch (error) {
      sendRelayError(res, error);
    }
  });

  // ── Passkey: approve an already-pending 2FA request (second-factor,
  //    not passwordless-primary — pair with `@touchque/web`'s
  //    `passkeys.approveLogin({ requestId })`). Matches `@touchque/web`'s
  //    default `approveOptions`/`approveVerify` paths exactly. ──────────
  router.post('/passkey/login/options', async (req, res) => {
    if (!allow(req, res, 'passkey-approve')) return;
    try {
      res.json(await tq.webauthn.authenticateOptions({ requestId: req.body?.requestId }));
    } catch (error) {
      sendRelayError(res, error);
    }
  });

  router.post('/passkey/login/verify', async (req, res) => {
    if (!allow(req, res, 'passkey-approve')) return;
    try {
      const r = await tq.webauthn.authenticateVerify({ requestId: req.body?.requestId, response: req.body?.response });
      // Open the session only for the user TouchQue says was approved. A name sent by the
      // browser is never trusted: anyone could approve their own request and claim to be someone else.
      if (r.success && getLoginUser && typeof r.externalUsername === 'string') {
        const expected = await getLoginUser(req);
        if (!expected || String(expected).toLowerCase() !== r.externalUsername.toLowerCase()) {
          res.status(401).json({ error: 'verification_failed' });
          return;
        }
      }
      if (r.success && onAuthenticated && typeof r.externalUsername === 'string' && r.externalUsername) {
        await onAuthenticated(req, res, { externalUsername: r.externalUsername, requestId: r.requestId || req.body?.requestId, via: 'passkey' });
      }
      res.json(r);
    } catch (error) {
      sendRelayError(res, error);
    }
  });

  // ── Passkey: enrollment / management (auth required) ─────────────────
  router.post('/passkey/register/options', async (req, res) => {
    const userId = requireUserId(req, res, getUserId);
    if (!userId) return;
    try {
      res.json(await tq.webauthn.registerOptions({ externalUsername: userId, discoverable: true }));
    } catch (error) {
      sendRelayError(res, error);
    }
  });

  router.post('/passkey/register/verify', async (req, res) => {
    const userId = requireUserId(req, res, getUserId);
    if (!userId) return;
    try {
      res.json(await tq.webauthn.registerVerify({ externalUsername: userId, response: req.body?.response, label: req.body?.label }));
    } catch (error) {
      sendRelayError(res, error);
    }
  });

  router.get('/passkey/credentials', async (req, res) => {
    const userId = requireUserId(req, res, getUserId);
    if (!userId) return;
    try {
      res.json(await tq.webauthn.listCredentials({ externalUsername: userId }));
    } catch (error) {
      sendRelayError(res, error);
    }
  });

  router.delete('/passkey/credentials/:id', async (req, res) => {
    const userId = requireUserId(req, res, getUserId);
    if (!userId) return;
    try {
      res.json(await tq.webauthn.deleteCredential(req.params.id, { externalUsername: userId }));
    } catch (error) {
      sendRelayError(res, error);
    }
  });

  return router;
}
