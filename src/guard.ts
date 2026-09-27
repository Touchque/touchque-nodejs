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
} as const;

const TOKEN_TTL_MS = 10 * 60 * 1000;

export interface GuardInput {
  /** The user in YOUR system; undefined = not signed in → 401. */
  user?: string;
  action: string;
  details?: LoginRequestDetails;
  referenceId?: string;
  ip?: string;
  userAgent?: string;
  token?: string;
  offline?: boolean;
  code?: string;
  codeType?: string;
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
      ...base, st: step.state, rid: step.requestId, n: step.number, oc: step.offline?.challengeId, exp: Date.now() + TOKEN_TTL_MS, ...extra,
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
        ? await r.offline.verifyTotp({ externalUsername: user, code: input.code, type: action, clientIp: input.ip })
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
        return issue({ state: 'offline', offline: { challengeId: String(bound.oc), attemptsLeft: res.attemptsLeft } }, { oc: bound.oc });
      }
      if (res.reason === 'invalid_code') return issue({ state: 'offline', reason: 'invalid_code' }, { oc: bound.oc });
      return issue({ state: res.reason === 'expired' ? 'expired' : 'blocked', reason: res.reason || 'offline_failed' });
    }

    if (input.offline) {
      try {
        const ch = await r.offline.challenge({
          externalUsername: user, type: action, details: details.length ? details : undefined, clientIp: input.ip, userAgent: input.userAgent,
        });
        return issue({
          state: 'offline',
          offline: { challengeId: ch.challengeId, qrDataUrl: ch.qrDataUrl || undefined, expiresAt: ch.expiresAt, totpAvailable: ch.totpAvailable },
        });
      } catch (err) {
        if (err instanceof TouchQueAPIError && err.status < 500) {
          return issue({ state: 'blocked', reason: err.code || (err.data as { error?: string })?.error || 'offline_unavailable' });
        }
        throw err;
      }
    }

    // Waiting on a push / passkey: poll, and run the action once it is approved.
    if (bound && bound.rid && (bound.st === 'waiting' || bound.st === 'passkey_required')) {
      const now = await check(r, bound.rid);
      if (now.state === 'approved') {
        try {
          return { status: 200, approved: await complete(r, bound.rid, expectations) };
        } catch (err) {
          if (err instanceof TouchQueAPIError && err.status === 409) return issue({ state: 'expired', reason: err.code || 'already_used' });
          throw err;
        }
      }
      if (now.state === 'waiting' || now.state === 'passkey_required') {
        return issue({ state: now.state, requestId: bound.rid, number: bound.n }, { n: bound.n });
      }
      return issue({ state: now.state, requestId: bound.rid });
    }

    // Anything else (no/foreign token, enrollment finished, new attempt): start.
    return issue(await start(r, action, {
      user, details: details.length ? details : undefined, referenceId: input.referenceId, ip: input.ip, userAgent: input.userAgent,
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
