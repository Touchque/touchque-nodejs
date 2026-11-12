// src/guard.ts
// Framework-agnostic step-up guard. The Express middleware, the Next.js wrapper
// and touchqueRouter's /login are thin adapters over runGuard().
//
// Contract (same in every Touchque server SDK):
//   1st request            → 202 { touchque: step, token }   show the step in your UI
//   repeat with the token  → 202 while waiting (each answer carries the request's current expiresAt),
//                            then the protected handler runs once
//                            (while the first-time QR is up: { state: 'enroll', expiresAt }
//                            without `enroll`, so the page keeps the QR it shows)
//   no phone, enroll: false → 202 { state: 'enroll', reason: 'enrollment_off' }: final, no QR
//   refused                → 403 / 408 / 423 / 429 { touchque: { state, reason?, retryAfter? } }
// Request headers the browser sends back:
//   X-Touchque-Token       the token from the last response
//   X-Touchque-Offline: 1  switch to offline approval (phone has no internet)
//   X-Touchque-Code        the code from the phone (offline QR code, or with
//   X-Touchque-Code-Type: totp  the rolling time-based code)
//   X-Touchque-Browser     the browser's device-bound key proof (silent sign-ins,
//                          read only when the adapter's `silentSignIn` is on)

import { getDefaultClient, type Touchque } from './index';
import type { LoginRequestDetails, TouchqueLogger } from './types';
import { TouchqueAPIError, TouchqueConfigError, TouchqueNetworkError } from './errors';
import { detailsDigest } from './approvalProof';
import {
  Approval, Step, StepState, GuardTokenClaims,
  start, check, complete, normalizeDetails, signGuardToken, verifyGuardToken,
} from './steps';
import { guardSecret, resources } from './internal';
import { describeError, sdkLog, type SdkLog } from './core/HttpClient';

export const GUARD_HEADERS = {
  token: 'x-touchque-token',
  offline: 'x-touchque-offline',
  code: 'x-touchque-code',
  codeType: 'x-touchque-code-type',
  browser: 'x-touchque-browser',
} as const;

const TOKEN_TTL_MS = 10 * 60 * 1000;
/** A first-time QR this close to its expiry is replaced, not kept on screen. */
const ENROLL_QR_MARGIN_MS = 15 * 1000;
/** A real proof is a few hundred characters; anything far larger is not one. */
const MAX_BROWSER_PROOF = 4096;

/** `silentSignIn: { maxAgeSeconds }`: your own limit on the age of the last phone approval in the browser. */
export interface SilentSignInOptions {
  /** Seconds (integer); 0 = always ask. Touchque never goes beyond its own limit (7 days). */
  maxAgeSeconds?: number;
}

export interface GuardInput {
  /** The user in YOUR system; undefined = not signed in → 401. */
  user?: string;
  /**
   * Issue a first-time linking QR (and recovery codes) when the user has no
   * phone yet (default true). Pass false whenever `user` is not proven by your
   * own sign-in, e.g. a typed username before the password step: the QR would
   * let anyone link their own phone to that account. Such a user then gets 202
   * `{ state: 'enroll', reason: 'enrollment_off' }`, a final answer: no QR,
   * nothing to poll.
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
   * Silent sign-ins: the browser's device-bound key proof (`X-Touchque-Browser`),
   * passed through untouched. Attached to the push, so its approval makes the
   * browser known.
   */
  browserProof?: string;
  /**
   * Silent sign-ins (default off). A new attempt that carries `browserProof`
   * first asks Touchque (`risk.check`); when it answers `prompt: false` the
   * guard approves at once, with no push (`assurance.method: 'silent'`,
   * `confirmedVia: 'SILENT'`, `reasons`). Otherwise, and on any error, the
   * usual push starts.
   */
  silentSignIn?: boolean | SilentSignInOptions;
  /** For your Touchque Actions only (`event.context`). Never shown on the phone. */
  context?: Record<string, unknown>;
  /**
   * For relays with a rate limit. Called at most once, only when a poll on a
   * first-time QR token is about to start something instead of keeping the QR
   * (the phone is linked, or the QR expired or is gone), so the relay can charge
   * it like a new attempt. A result it returns is the answer.
   */
  beforeStart?: () => GuardResult | undefined | Promise<GuardResult | undefined>;
}

export interface GuardBody {
  touchque: Step;
  token?: string;
  error?: { code: string; message: string };
}

export type GuardResult =
  | { approved: Approval; status: 200; body?: undefined }
  | { approved?: undefined; status: number; body: GuardBody };

/**
 * What an adapter's `errorBody` gets for every answer of status 400 or more
 * (401, 403, 408, 423, 429, 500, 503); never for a 202 step or an approval.
 */
export interface GuardRefusal {
  status: number;
  /** `error.code` when the guard set one (`unauthenticated`, `misconfigured`, `unavailable`), else the step's `reason`, else its `state`. */
  code: string;
  /** `error.message` when set, else a sentence for the state ("The approval was rejected."). */
  message: string;
  /** A copy of the step as it would be sent. An object answer always carries the step as `touchque`. */
  touchque: Step;
}

const STATUS: Record<StepState, number> = {
  waiting: 202, enroll: 202, passkey_required: 202, offline: 202,
  approved: 200, rejected: 403, blocked: 403, expired: 408, frozen: 423, rate_limited: 429,
};

/** The HTTP answer for a guard result that is not an approval (`guardResponse`). */
export interface GuardResponse {
  status: number;
  /**
   * `Cache-Control: no-store`; `Retry-After` on 423 and 429; on status 400 or
   * more `X-Touchque-State`, and `X-Touchque-Reason` when the step has a reason.
   */
  headers: Record<string, string>;
  /** A JSON value: the guard's body, or your `errorBody` shape. Send it with your framework's JSON. */
  body: unknown;
}

export interface GuardResponseOptions {
  /**
   * Your app's own error shape, as the adapters' `errorBody`: called for an
   * answer of status 400 or more with a `GuardRefusal`. What encodes to a JSON
   * object is sent with `touchque` set to the step; anything else as it is;
   * `undefined`, a throw or a result JSON cannot encode keeps the default body.
   */
  errorBody?: (refusal: GuardRefusal) => unknown;
  /** Gets `[Touchque] errorBody failed: …` when `errorBody` throws (`console`, pino …). Default: nothing is logged. */
  logger?: TouchqueLogger;
}

/**
 * The status, headers and JSON body for a `runGuard` result that is not an
 * approval, exactly as `requireTouchque` and `withTouchque` send them (they use
 * it too). Run the protected action instead when `result.approved` is set.
 *
 * @example
 * const result = await runGuard(null, { user: req.user?.email, action: 'SEND_MONEY', token: req.get(GUARD_HEADERS.token) });
 * if (!result.approved) {
 *   const { status, headers, body } = await guardResponse(result);
 *   return res.status(status).set(headers).json(body);
 * }
 */
export async function guardResponse(result: { status: number; body: GuardBody }, options: GuardResponseOptions = {}): Promise<GuardResponse> {
  return respond(result, options.errorBody, sdkLog({ logger: options.logger }));
}

/**
 * Runs the guard for one request. `tq` null or undefined: the default client,
 * built from TQ_API_KEY / TQ_API_SECRET and kept once built; until it can be
 * built the answer is 401 `unauthenticated` without a `user`, else 500
 * `misconfigured` (nothing is logged: there is no client to log through).
 */
export async function runGuard(tq: Touchque | null | undefined, input: GuardInput): Promise<GuardResult> {
  const client = adapterClient(tq, getDefaultClient);
  if (!client) return withoutClient(input.user);
  const r = resources(client);
  const secret = guardSecret(client);
  const { action } = input;

  if (!input.user) return unauthenticated();
  const user = String(input.user);
  const details = normalizeDetails(input.details);
  const base = { u: user, a: action, d: detailsDigest(details), r: input.referenceId ?? null };
  const expectations = { user, action, details, referenceId: input.referenceId };

  const issue = (step: Step, extra: Partial<GuardTokenClaims> = {}): GuardResult => {
    if (details.length && !step.details && step.state !== 'blocked') step.details = details;
    // A first-time QR: its token keeps the QR's expiry, so the polls that follow keep it on screen.
    const ee = step.enroll?.qrCodeDataUrl && step.enroll.expiresAt ? Date.parse(step.enroll.expiresAt) : NaN;
    // A push or passkey that waits: its token keeps the request's expiry, so every poll answer repeats it.
    const rx = (step.state === 'waiting' || step.state === 'passkey_required') && step.expiresAt ? Date.parse(step.expiresAt) : NaN;
    const claims: GuardTokenClaims = {
      ...base, st: step.state, rid: step.requestId, n: step.number, oc: step.offline?.challengeId, exp: Date.now() + TOKEN_TTL_MS,
      ...(step.caseCode && { cc: step.caseCode }), ...(Number.isFinite(ee) && { ee }), ...(Number.isFinite(rx) && { rx }), ...extra,
    };
    return { status: STATUS[step.state], body: { touchque: step, token: signGuardToken(secret, claims) } };
  };
  // The request's expiry for a step that waits on it: the live one from Touchque's status answer (`now`), which
  // a move to a passkey during a call extends, else the one the token carries.
  const expiryFor = (claims: GuardTokenClaims, now?: Step): number | undefined => {
    const live = now?.expiresAt ? Date.parse(now.expiresAt) : NaN;
    return Number.isFinite(live) ? live : Number.isFinite(claims.rx) ? claims.rx : undefined;
  };
  const expiryOf = (ms: number | undefined): Pick<Step, 'expiresAt'> => (ms === undefined ? {} : { expiresAt: new Date(ms).toISOString() });

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
        return issue({ state: 'offline', offline: { challengeId: String(bound.oc), attemptsLeft: res.attemptsLeft } }, { oc: bound.oc, rid: bound.rid, n: bound.n, rx: bound.rx });
      }
      if (res.reason === 'invalid_code') return issue({ state: 'offline', reason: 'invalid_code' }, { oc: bound.oc, rid: bound.rid, n: bound.n, rx: bound.rx });
      // The phone rejected the push this QR belongs to: the whole sign-in is over, no other factor may finish it.
      if (res.reason === 'request_rejected') return issue({ state: 'rejected', requestId: bound.rid, reason: 'request_rejected' });
      // The push now waits for a passkey (Vishing Shield): no code may finish it.
      if (res.reason === 'passkey_required' && bound.rid) {
        return issue({ state: 'passkey_required', requestId: bound.rid, number: bound.n, ...expiryOf(expiryFor(bound)) }, { n: bound.n });
      }
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
        }, { rid: bound?.rid, n: ch.challengeCode || bound?.n, rx: bound?.rx });
      } catch (err) {
        if (err instanceof TouchqueAPIError && err.status === 409 && (err.code || (err.data as { error?: string })?.error) === 'request_rejected') {
          return issue({ state: 'rejected', requestId: bound?.rid, reason: 'request_rejected' });
        }
        // The push it would follow now waits for a passkey (Vishing Shield): no QR, run the passkey instead.
        if (err instanceof TouchqueAPIError && bound?.rid && (err.code || (err.data as { error?: string })?.error) === 'passkey_required') {
          return issue({ state: 'passkey_required', requestId: bound.rid, number: bound.n, ...expiryOf(expiryFor(bound)) }, { n: bound.n });
        }
        if (err instanceof TouchqueAPIError && err.status < 500) {
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
          if (err instanceof TouchqueAPIError && err.status === 409) return issue({ state: 'expired', reason: err.code || 'already_used' });
          throw err;
        }
      }
      // The push behind the QR was moved to a passkey after it was tapped during a call
      // (Vishing Shield): the QR's code would be refused now, so switch to the passkey.
      if (bound.st === 'offline' && now.state === 'passkey_required') {
        return issue({ state: 'passkey_required', requestId: bound.rid, number: bound.n, ...expiryOf(expiryFor(bound, now)) }, { n: bound.n });
      }
      if (bound.st === 'offline' && (now.state === 'waiting' || now.state === 'expired')) {
        // Still (or no longer) pending: nothing changed for the user — keep showing the QR they have.
        return issue({ state: 'offline', offline: { challengeId: String(bound.oc) } }, { oc: bound.oc, rid: bound.rid, n: bound.n, rx: expiryFor(bound, now) });
      }
      if (now.state === 'waiting' || now.state === 'passkey_required') {
        return issue({
          state: now.state, requestId: bound.rid, number: bound.n, ...expiryOf(expiryFor(bound, now)), ...(bound.cc && { caseCode: bound.cc }),
        }, { n: bound.n });
      }
      return issue({ state: now.state, requestId: bound.rid });
    }

    // The first-time QR is on screen: a poll reads whether the phone is linked yet and keeps that QR
    // (and its recovery codes) up, instead of issuing new ones that would stop the shown QR working.
    if (bound && bound.st === 'enroll' && Number.isFinite(bound.ee)) {
      const ee = bound.ee as number;
      const linked = await r.auth.getUser({ externalUsername: user }).then(
        (u) => Boolean(u.used || u.deviceId),
        (err) => {
          if (err instanceof TouchqueAPIError && err.status === 404) return null; // no phone, and the QR is gone
          throw err;
        },
      );
      if (linked === false && Date.now() < ee - ENROLL_QR_MARGIN_MS) {
        return issue({ state: 'enroll', expiresAt: new Date(ee).toISOString() }, { ee });
      }
      // Linked: the approval starts below. Not linked and the QR (nearly) expired or gone: a new QR.
      // Either is a start, which a relay charges like a new attempt.
      const refused = await input.beforeStart?.();
      if (refused) return refused;
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
    if (err instanceof TouchqueConfigError) {
      r.http.log.error(`[Touchque] ${err.message}`);
      return misconfigured();
    }
    if (!(err instanceof TouchqueNetworkError) && !(err instanceof TouchqueAPIError && err.status >= 500)) {
      r.http.log.error(`[Touchque] approval failed: ${describeError(err)}`);
    }
    return { status: 503, body: { touchque: { state: 'blocked', reason: 'unavailable' }, error: { code: 'unavailable', message: 'Two-factor approval is temporarily unavailable.' } } };
  }
}

function unauthenticated(): GuardResult {
  return { status: 401, body: { touchque: { state: 'blocked', reason: 'unauthenticated' }, error: { code: 'unauthenticated', message: 'Sign in first.' } } };
}

function misconfigured(): GuardResult {
  return { status: 500, body: { touchque: { state: 'blocked', reason: 'misconfigured' }, error: { code: 'misconfigured', message: 'Two-factor approval is not configured correctly.' } } };
}

/**
 * Asks Touchque whether this known browser may sign in without the phone.
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
 * (R1-03: with a 1.5 s poll the 6th poll was refused after 7.5 s). So is a poll
 * while the first-time QR is up (an `enroll` token whose expiry is more than
 * 15 s away): it reads whether the phone is linked and keeps the QR. When it
 * would start something instead (the phone is linked, or the QR is about to
 * expire), runGuard calls `beforeStart`, where the relay charges it like a new
 * attempt. `tq` null or undefined: the default client, as for runGuard; false
 * while it cannot be built.
 */
export function isStatusPoll(tq: Touchque | null | undefined, input: GuardInput): boolean {
  if (!input.user || !input.token || input.offline || input.code) return false;
  const client = adapterClient(tq, getDefaultClient);
  if (!client) return false;
  const claims = verifyGuardToken(guardSecret(client), input.token);
  if (!claims) return false;
  const details = normalizeDetails(input.details);
  const sameAttempt = claims.u === String(input.user) && claims.a === input.action && claims.d === detailsDigest(details)
    && claims.r === (input.referenceId ?? null);
  if (!sameAttempt) return false;
  // Not once the QR is (nearly) expired: that request issues a new one.
  if (claims.st === 'enroll') return Number.isFinite(claims.ee) && Date.now() < (claims.ee as number) - ENROLL_QR_MARGIN_MS;
  return Boolean(claims.rid) && (claims.st === 'waiting' || claims.st === 'passkey_required' || claims.st === 'offline');
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

/**
 * An adapter's client: its own, or the default one, built from TQ_API_KEY /
 * TQ_API_SECRET on a request and kept once built. Null while it cannot be built:
 * the adapter then answers with withoutClient() instead of throwing, and tries
 * again on the next request.
 */
export function adapterClient(own: Touchque | null | undefined, getDefault: () => Touchque): Touchque | null {
  if (own) return own;
  try {
    return getDefault();
  } catch (err) {
    if (err instanceof TouchqueConfigError) return null;
    throw err;
  }
}

/** The answer without a client: 401 without a signed-in user, else 500 misconfigured. The handler never runs. */
export function withoutClient(user: string | null | undefined): GuardResult {
  return user ? misconfigured() : unauthenticated();
}

const REFUSED: Partial<Record<StepState, string>> = {
  rejected: 'The approval was rejected.',
  expired: 'The approval expired. Try again.',
  frozen: 'Too many rejected approvals. Try again later.',
  rate_limited: 'Too many attempts. Try again later.',
};

type JsonReplacer = ((this: any, key: string, value: any) => any) | Array<string | number> | null;

/**
 * What guardResponse() and every adapter send for a result that is not an
 * approval: one implementation, so they cannot drift. `log` gets a failing
 * `errorBody`; `replacer` is the JSON replacer the app sends with (Express),
 * see answerBody().
 */
export async function respond(
  result: { status: number; body: GuardBody },
  errorBody: ((refusal: GuardRefusal) => unknown) | undefined,
  log: SdkLog,
  replacer?: JsonReplacer,
): Promise<GuardResponse> {
  if ((result as { approved?: unknown }).approved) {
    throw new TypeError('Touchque: guardResponse() takes a result that is not approved: run the protected action instead.');
  }
  const { status, body } = result;
  const retryAfter = body.touchque.retryAfter;
  const headers: Record<string, string> = {
    'Cache-Control': 'no-store',
    ...((status === 423 || status === 429) && retryAfter && { 'Retry-After': String(retryAfter) }),
    ...refusalHeaders(result),
  };
  return { status, headers, body: await answerBody(result, errorBody, log, replacer) };
}

/**
 * The JSON an adapter sends for an answer that is not an approval. With
 * `errorBody`, an answer of status 400 or more gets the app's own shape,
 * decided by how it encodes to JSON (a class instance, `toJSON()`, a Map as
 * its entries): an object is sent with `touchque` set to the step (no
 * `token`), anything else as it is. `undefined` keeps the guard's body, and so
 * does a callback that throws or a result JSON cannot encode (logged).
 * `replacer`: the JSON replacer the app sends with (Express's 'json replacer'),
 * so the check sees what the app would send; the result has been through it.
 */
export async function answerBody(
  result: { status: number; body: GuardBody },
  errorBody: ((refusal: GuardRefusal) => unknown) | undefined,
  log: SdkLog,
  replacer?: JsonReplacer,
): Promise<unknown> {
  const { status, body } = result;
  if (!errorBody || status < 400) return body;
  const step = body.touchque;
  let encoded: unknown;
  try {
    const shaped = await errorBody({
      status,
      code: body.error?.code || step.reason || step.state,
      message: body.error?.message || REFUSED[step.state] || 'The approval was refused.',
      touchque: JSON.parse(JSON.stringify(step)) as Step,
    });
    if (shaped === undefined) return body;
    const value = shaped instanceof Map ? Object.fromEntries(shaped) : shaped;
    const text = typeof replacer === 'function' ? JSON.stringify(value, replacer) : JSON.stringify(value, replacer ?? undefined);
    if (text === undefined) throw new TypeError('the result has no JSON form');
    encoded = JSON.parse(text);
  } catch (err) {
    log.error(`[Touchque] errorBody failed: ${describeError(err)}`);
    return body;
  }
  // The SDK's key wins, so @touchque/web still sees the state.
  return encoded !== null && typeof encoded === 'object' && !Array.isArray(encoded) ? { ...encoded, touchque: step } : encoded;
}

const HEADER_VALUE = /^[\x20-\x7e]{1,200}$/;

/**
 * The headers of every guard answer of status 400 or more: `X-Touchque-State`,
 * and `X-Touchque-Reason` when the step has a reason. @touchque/web reads them
 * when the body has no `touchque` (an `errorBody` that returned a non-object).
 */
export function refusalHeaders(result: { status: number; body: GuardBody }): Record<string, string> {
  if (result.status < 400) return {};
  const { state, reason } = result.body.touchque;
  return { 'X-Touchque-State': state, ...(reason && HEADER_VALUE.test(reason) && { 'X-Touchque-Reason': reason }) };
}
