// src/guard.ts
// Framework-agnostic step-up guard. The Express middleware, the Next.js wrapper
// and touchqueRouter's /login are thin adapters over runGuard().
//
// Contract (same in every TouchQue server SDK):
//   1st request            → 202 { touchque: step, token }   show the step in your UI
//   repeat with the token  → 202 while waiting, then the protected handler runs once
//   refused                → 403 / 408 / 423 / 429 { touchque: { state, reason?, retryAfter? } }
// Request headers the browser sends back:
//   X-TouchQue-Token       the token from the last response
//   X-TouchQue-Offline: 1  switch to offline approval (phone has no internet)
//   X-TouchQue-Code        the code from the phone (offline QR code, or with
//   X-TouchQue-Code-Type: totp  the rolling time-based code)
//   X-TouchQue-Browser     the browser's device-bound key proof (silent sign-ins,
//                          read only when the adapter's `silentSignIn` is on)

import type { TouchQue } from './index';
import type { LoginRequestDetails } from './types';
import { TouchQueAPIError, TouchQueConfigError, TouchQueNetworkError } from './errors';
import { detailsDigest } from './approvalProof';
import {
  Approval, Step, StepState, GuardTokenClaims,
  start, check, complete, normalizeDetails, signGuardToken, verifyGuardToken,
} from './steps';
import { guardSecret, resources } from './internal';

export const GUARD_HEADERS = {
  token: 'x-touchque-token',
  offline: 'x-touchque-offline',
  code: 'x-touchque-code',
  codeType: 'x-touchque-code-type',
  browser: 'x-touchque-browser',
} as const;

const TOKEN_TTL_MS = 10 * 60 * 1000;
/** A real proof is a few hundred characters; anything far larger is not one. */
const MAX_BROWSER_PROOF = 4096;

/** `silentSignIn: { maxAgeSeconds }`: your own limit on the age of the last phone approval in the browser. */
export interface SilentSignInOptions {
  /** Seconds (integer); 0 = always ask. TouchQue never goes beyond its own limit (7 days). */
  maxAgeSeconds?: number;
}

export interface GuardInput {
  /** The user in YOUR system; undefined = not signed in → 401. */
  user?: string;
  /**
   * Issue a first-time linking QR (and recovery codes) when the user has no
   * phone yet (default true). Pass false whenever `user` is not proven by your
   * own sign-in, e.g. a typed username before the password step: the QR would
   * let anyone link their own phone to that account.
   */
  enroll?: boolean;
  action: string;
  details?: LoginRequestDetails;
  referenceId?: string;
  ip?: string;
  userAgent?: string;
  token?: string;
  offline?: boolean;
  code?: string;
  codeType?: string;
  /**
   * Silent sign-ins: the browser's device-bound key proof (`X-TouchQue-Browser`),
   * passed through untouched. Attached to the push, so its approval makes the
   * browser known.
   */
  browserProof?: string;
  /**
   * Silent sign-ins (default off). A new attempt that carries `browserProof`
   * first asks TouchQue (`risk.check`); when it answers `prompt: false` the
   * guard approves at once, with no push (`assurance.method: 'silent'`,
   * `confirmedVia: 'SILENT'`, `reasons`). Otherwise, and on any error, the
   * usual push starts.
   */
  silentSignIn?: boolean | SilentSignInOptions;
  /** For your TouchQue Actions only (`event.context`). Never shown on the phone. */
  context?: Record<string, unknown>;
}

export interface GuardBody {
  touchque: Step;
  token?: string;
  error?: { code: string; message: string };
}

export type GuardResult =
  | { approved: Approval; status: 200; body?: undefined }
  | { approved?: undefined; status: number; body: GuardBody };

const STATUS: Record<StepState, number> = {
  waiting: 202, enroll: 202, passkey_required: 202, offline: 202,
  approved: 200, rejected: 403, blocked: 403, expired: 408, frozen: 423, rate_limited: 429,
};

export async function runGuard(tq: TouchQue, input: GuardInput): Promise<GuardResult> {
  const r = resources(tq);
  const secret = guardSecret(tq);
  const { action } = input;

  if (!input.user) {
    return { status: 401, body: { touchque: { state: 'blocked', reason: 'unauthenticated' }, error: { code: 'unauthenticated', message: 'Sign in first.' } } };
  }
  const user = String(input.user);
  const details = normalizeDetails(input.details);
  const base = { u: user, a: action, d: detailsDigest(details), r: input.referenceId ?? null };
  const expectations = { user, action, details, referenceId: input.referenceId };

  const issue = (step: Step, extra: Partial<GuardTokenClaims> = {}): GuardResult => {
    if (details.length && !step.details && step.state !== 'blocked') step.details = details;
    const claims: GuardTokenClaims = {
      ...base, st: step.state, rid: step.requestId, n: step.number, oc: step.offline?.challengeId, exp: Date.now() + TOKEN_TTL_MS,
      ...(step.caseCode && { cc: step.caseCode }), ...extra,
    };
    return { status: STATUS[step.state], body: { touchque: step, token: signGuardToken(secret, claims) } };
  };

  try {
    const claims = verifyGuardToken(secret, input.token);
    const bound = claims && claims.u === base.u && claims.a === base.a && claims.d === base.d && claims.r === base.r ? claims : null;

    // Offline: the user typed the code from the phone.
    if (bound && input.code && (bound.st === 'offline' || input.codeType === 'totp')) {
      const totp = input.codeType === 'totp';
      const res = totp
        ? await r.offline.verifyTotp({ externalUsername: user, code: input.code, type: action, clientIp: input.ip, requestId: bound.rid })
        : await r.offline.verify({ challengeId: String(bound.oc), code: input.code });
      const forThis = (!res.externalUsername || res.externalUsername.toLowerCase() === user.toLowerCase()) && (!res.type || res.type === action);
      if (res.approved && forThis) {
        const method = totp ? 'offline_totp' : 'offline_code';
        return {
          status: 200,
          approved: {
            requestId: bound.oc || 'offline-totp', user, action,
            assurance: { phishingResistant: false, method }, confirmedVia: totp ? 'OFFLINE_TOTP' : 'OFFLINE_CODE', approvalProof: null,
          },
        };
      }
      if (res.reason === 'invalid_code' && !totp) {
        return issue({ state: 'offline', offline: { challengeId: String(bound.oc), attemptsLeft: res.attemptsLeft } }, { oc: bound.oc, rid: bound.rid, n: bound.n });
      }
      if (res.reason === 'invalid_code') return issue({ state: 'offline', reason: 'invalid_code' }, { oc: bound.oc, rid: bound.rid, n: bound.n });
      // The phone rejected the push this QR belongs to: the whole sign-in is over, no other factor may finish it.
      if (res.reason === 'request_rejected') return issue({ state: 'rejected', requestId: bound.rid, reason: 'request_rejected' });
      // The push now waits for a passkey (Vishing Shield): no code may finish it.
      if (res.reason === 'passkey_required' && bound.rid) return issue({ state: 'passkey_required', requestId: bound.rid, number: bound.n }, { n: bound.n });
      return issue({ state: res.reason === 'expired' ? 'expired' : 'blocked', reason: res.reason || 'offline_failed' });
    }

    if (input.offline) {
      try {
        // Link the QR to the push it follows: a phone-side rejection then kills it, and a push that asked for
        // number matching makes the QR ask for the same number.
        const ch = await r.offline.challenge({
          externalUsername: user, type: action, details: details.length ? details : undefined, clientIp: input.ip, userAgent: input.userAgent,
          requestId: bound?.rid,
        });
        return issue({
          state: 'offline',
          offline: {
            challengeId: ch.challengeId, qrDataUrl: ch.qrDataUrl || undefined, expiresAt: ch.expiresAt, totpAvailable: ch.totpAvailable,
            ...(ch.challengeCode && { challengeCode: ch.challengeCode }),
          },
        }, { rid: bound?.rid, n: ch.challengeCode || bound?.n });
      } catch (err) {
        if (err instanceof TouchQueAPIError && err.status === 409 && (err.code || (err.data as { error?: string })?.error) === 'request_rejected') {
          return issue({ state: 'rejected', requestId: bound?.rid, reason: 'request_rejected' });
        }
        // The push it would follow now waits for a passkey (Vishing Shield): no QR, run the passkey instead.
        if (err instanceof TouchQueAPIError && bound?.rid && (err.code || (err.data as { error?: string })?.error) === 'passkey_required') {
          return issue({ state: 'passkey_required', requestId: bound.rid, number: bound.n }, { n: bound.n });
        }
        if (err instanceof TouchQueAPIError && err.status < 500) {
          return issue({ state: 'blocked', reason: err.code || (err.data as { error?: string })?.error || 'offline_unavailable' });
        }
        throw err;
      }
    }

    // Waiting on a push / passkey — or showing the offline QR next to a push that is still open: poll,
    // and run the action once it is approved. While the QR is up a phone-side REJECT ends the attempt at once.
    if (bound && bound.rid && (bound.st === 'waiting' || bound.st === 'passkey_required' || bound.st === 'offline')) {
      const now = await check(r, bound.rid);
      if (now.state === 'approved') {
        try {
          return { status: 200, approved: await complete(r, bound.rid, expectations) };
        } catch (err) {
          if (err instanceof TouchQueAPIError && err.status === 409) return issue({ state: 'expired', reason: err.code || 'already_used' });
          throw err;
        }
      }
      // The push behind the QR was moved to a passkey after it was tapped during a call
      // (Vishing Shield): the QR's code would be refused now, so switch to the passkey.
      if (bound.st === 'offline' && now.state === 'passkey_required') {
        return issue({ state: 'passkey_required', requestId: bound.rid, number: bound.n }, { n: bound.n });
      }
      if (bound.st === 'offline' && (now.state === 'waiting' || now.state === 'expired')) {
        // Still (or no longer) pending: nothing changed for the user — keep showing the QR they have.
        return issue({ state: 'offline', offline: { challengeId: String(bound.oc) } }, { oc: bound.oc, rid: bound.rid, n: bound.n });
      }
      if (now.state === 'waiting' || now.state === 'passkey_required') {
        return issue({ state: now.state, requestId: bound.rid, number: bound.n, ...(bound.cc && { caseCode: bound.cc }) }, { n: bound.n });
      }
      return issue({ state: now.state, requestId: bound.rid });
    }

    // Anything else (no/foreign token, enrollment finished, new attempt): start.
    const browserProof = typeof input.browserProof === 'string' && input.browserProof && input.browserProof.length <= MAX_BROWSER_PROOF
      ? input.browserProof : undefined;
    if (input.silentSignIn && browserProof) {
      const silent = await silentApproval(r, { user, action, browserProof, ip: input.ip, userAgent: input.userAgent, silentSignIn: input.silentSignIn, context: input.context });
      if (silent) return { status: 200, approved: silent };
    }
    return issue(await start(r, action, {
      user, details: details.length ? details : undefined, referenceId: input.referenceId, ip: input.ip, userAgent: input.userAgent,
      enroll: input.enroll, browserProof, context: input.context,
    }));
  } catch (err) {
    if (err instanceof TouchQueConfigError) {
      console.error(`[TouchQue] ${err.message}`);
      return { status: 500, body: { touchque: { state: 'blocked', reason: 'misconfigured' }, error: { code: 'misconfigured', message: 'Two-factor approval is not configured correctly.' } } };
    }
    if (!(err instanceof TouchQueNetworkError) && !(err instanceof TouchQueAPIError && err.status >= 500)) {
      console.error('[TouchQue] approval failed:', err instanceof Error ? err.message : err);
    }
    return { status: 503, body: { touchque: { state: 'blocked', reason: 'unavailable' }, error: { code: 'unavailable', message: 'Two-factor approval is temporarily unavailable.' } } };
  }
}

/**
 * Asks TouchQue whether this known browser may sign in without the phone.
 * Fails closed: only an answer of exactly `prompt: false` approves; any error
 * (network, 4xx, 5xx, a server without silent sign-ins) means "ask as usual".
 */
async function silentApproval(
  r: ReturnType<typeof resources>,
  q: { user: string; action: string; browserProof: string; ip?: string; userAgent?: string; silentSignIn: true | SilentSignInOptions; context?: Record<string, unknown> },
): Promise<Approval | null> {
  try {
    const maxAgeSeconds = typeof q.silentSignIn === 'object' ? q.silentSignIn.maxAgeSeconds : undefined;
    const res = await r.risk.check({
      externalUsername: q.user, type: q.action, clientIp: q.ip, userAgent: q.userAgent, browserProof: q.browserProof, maxAgeSeconds, context: q.context,
    });
    if (res.prompt !== false) return null;
    return {
      requestId: 'silent', user: q.user, action: q.action,
      assurance: { phishingResistant: false, method: 'silent' }, confirmedVia: 'SILENT', approvalProof: null,
      reasons: res.reasons,
    };
  } catch {
    return null;
  }
}

/** The guard input an adapter adds for silent sign-ins: the proof header, only when the option is on. */
export function silentInputFromHeaders(
  option: boolean | SilentSignInOptions | undefined,
  get: (name: string) => string | undefined | null,
): Pick<GuardInput, 'silentSignIn' | 'browserProof'> {
  if (!option) return {};
  return { silentSignIn: option, browserProof: get(GUARD_HEADERS.browser) || undefined };
}

/**
 * True when this request only polls an approval that is already on its way:
 * a valid token bound to this user/action/details, still waiting, and no
 * offline switch or typed code. Such a request can only read the status, never
 * start a push, so relays do not count it against the per-user push limit
 * (R1-03: with a 1.5 s poll the 6th poll was refused after 7.5 s).
 */
export function isStatusPoll(tq: TouchQue, input: GuardInput): boolean {
  if (!input.user || !input.token || input.offline || input.code) return false;
  const claims = verifyGuardToken(guardSecret(tq), input.token);
  if (!claims || !claims.rid) return false;
  const details = normalizeDetails(input.details);
  return claims.u === String(input.user) && claims.a === input.action && claims.d === detailsDigest(details)
    && claims.r === (input.referenceId ?? null)
    && (claims.st === 'waiting' || claims.st === 'passkey_required' || claims.st === 'offline');
}

/** Reads the guard headers from any headers object (Node IncomingHttpHeaders or Fetch Headers). */
export function guardInputFromHeaders(get: (name: string) => string | undefined | null) {
  const offline = get(GUARD_HEADERS.offline);
  return {
    token: get(GUARD_HEADERS.token) || undefined,
    offline: offline === '1' || offline === 'true',
    code: get(GUARD_HEADERS.code) || undefined,
    codeType: get(GUARD_HEADERS.codeType) || undefined,
  };
}
