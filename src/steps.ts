// src/steps.ts
// The headless step-up flow shared by every integration (Express, Next.js,
// touchqueRouter, or your own framework): start → show the step in YOUR UI →
// check → complete exactly once.
//
// A "step" is plain JSON that is safe to send to the browser: what state the
// approval is in and whatever the user has to see (the matching number, the
// enrollment QR code, the offline QR code). It never contains API secrets.

import * as crypto from 'crypto';
import type { HttpClient } from './core/HttpClient';
import type { Auth } from './resources/Auth';
import type { Login } from './resources/Login';
import type { Offline } from './resources/Offline';
import type { ApprovalAssurance, LoginRequestDetails } from './types';
import { TouchQueAPIError, TouchQueConfigError, TouchQueError } from './errors';
import { detailsDigest } from './approvalProof';

export type StepState =
  | 'waiting' // push sent — show `number` (if any) and wait
  | 'approved'
  | 'rejected'
  | 'expired'
  | 'enroll' // no phone linked yet — show `enroll.qrCodeDataUrl`
  | 'passkey_required' // policy: approve with a passkey (browser ceremony)
  | 'offline' // offline approval started — show `offline.qrDataUrl` (and `offline.challengeCode`), ask for the code
  | 'blocked' // refused by policy / risk / action disabled — see `reason`
  | 'frozen' // too many rejections — see `retryAfter`
  | 'rate_limited'; // too many requests — see `retryAfter`

export interface Step {
  state: StepState;
  requestId?: string;
  /** Number matching: show this on screen; the user picks it on the phone. */
  number?: string;
  expiresAt?: string;
  /** Transaction details the phone shows (amount, recipient…). */
  details?: Array<{ label: string; value: string }>;
  enroll?: { qrCodeDataUrl: string; recoveryCodes?: string[]; expiresAt?: string };
  offline?: {
    challengeId: string;
    qrDataUrl?: string;
    expiresAt?: string;
    totpAvailable?: boolean;
    attemptsLeft?: number;
    /** Number matching: print this under the QR; the phone offers it among two decoys. */
    challengeCode?: string;
  };
  reason?: string;
  retryAfter?: number;
  assurance?: ApprovalAssurance;
}

export interface StartOptions {
  /** Your user's id in YOUR system (email, user id…). */
  user: string;
  /** Shown on the phone and bound to the approval. Build it from server-side state. */
  details?: LoginRequestDetails;
  /** Your own transaction id, bound to the approval. */
  referenceId?: string;
  /** End user's IP / user agent (location and device shown on the phone). */
  ip?: string;
  userAgent?: string;
  /** Show an enrollment QR when the user has not linked a phone yet (default true). */
  enroll?: boolean;
}

export interface Approval {
  requestId: string;
  user: string;
  action: string;
  /** How it was approved; `phishingResistant` is true only for passkeys. */
  assurance: ApprovalAssurance | null;
  confirmedVia: string | null;
  /** Device-signed proof of what was approved (see verifyApprovalProof). */
  approvalProof: unknown;
}

type Resources = { http: HttpClient; auth: Auth; login: Login; offline: Offline };

/** Normalizes details the same way the API does: object or [{label, value}] → [{label, value}] strings. */
export function normalizeDetails(details?: LoginRequestDetails): Array<{ label: string; value: string }> {
  if (!details) return [];
  const pairs = Array.isArray(details)
    ? details.map((d) => [d.label, d.value] as const)
    : Object.entries(details as Record<string, unknown>);
  return pairs.map(([label, value]) => ({ label: String(label).trim(), value: String(value).trim() }));
}

const codeOf = (err: unknown): string | undefined =>
  err instanceof TouchQueAPIError ? (err.code || (err.data as { error?: string })?.error) : undefined;

/** Starts an approval for `action` — never waits. */
export async function start(r: Resources, action: string, opts: StartOptions): Promise<Step> {
  if (!opts?.user) throw new TouchQueConfigError('start() needs the user id (options.user)');
  const details = normalizeDetails(opts.details);
  try {
    const res = await r.login.request({
      externalUsername: opts.user,
      type: action,
      referenceId: opts.referenceId,
      clientIp: opts.ip,
      userAgent: opts.userAgent,
      details: details.length ? details : undefined,
    });
    if (res.requiresPasskey) {
      return { state: 'passkey_required', requestId: res.requestId, expiresAt: res.expiresAt, details: details.length ? details : undefined };
    }
    return {
      state: 'waiting',
      requestId: res.requestId,
      number: res.challengeCode || undefined,
      expiresAt: res.expiresAt,
      details: details.length ? details : undefined,
    };
  } catch (err) {
    if (!(err instanceof TouchQueAPIError)) throw err;
    const code = codeOf(err);
    const data = err.data as { retryAfter?: number; reason?: string; error?: string };
    if (err.status === 404 && (code === 'device_not_linked' || /linked device/i.test(err.message))) {
      if (opts.enroll === false) return { state: 'enroll' };
      return enrollStep(r, opts.user);
    }
    if (err.status === 423) return { state: 'frozen', retryAfter: data.retryAfter };
    if (err.status === 429) return { state: 'rate_limited', retryAfter: data.retryAfter };
    if (err.status === 400 && (code === 'unknown_action' || /Invalid action type/i.test(err.message))) {
      throw new TouchQueConfigError(
        `Unknown action "${action}". Create it once with tq.actions.define('${action}') or in the Dashboard (Action Types).`,
      );
    }
    if (err.status === 403) {
      const reason = code === 'blocked' ? data.reason || 'policy'
        : code === 'passkey_not_registered' || data.error === 'phishing_resistant_required' ? 'passkey_not_registered'
          : code === 'action_disabled' ? 'action_disabled'
            : code || 'blocked';
      return { state: 'blocked', reason };
    }
    throw err;
  }
}

/**
 * First-time linking: a fresh QR for a user with no phone. Never unlinks a phone:
 * a secret is only re-issued when the account is confirmed NOT linked.
 */
async function enrollStep(r: Resources, user: string): Promise<Step> {
  try {
    const gen = await r.auth.generateSecret({ externalUsername: user });
    return { state: 'enroll', enroll: { qrCodeDataUrl: gen.qrCodeDataUrl, recoveryCodes: gen.recoveryCodes, expiresAt: gen.expiresAt } };
  } catch (err) {
    if (!(err instanceof TouchQueAPIError) || err.status !== 409) throw err;
    const current = await r.auth.getUser({ externalUsername: user }).catch(() => null);
    if (current && (current.used || current.deviceId)) {
      // Linked in the meantime — the caller just starts again.
      return { state: 'enroll', reason: 'already_linked' };
    }
    // A QR was issued earlier and not scanned yet: issue a new one (no device to lose).
    const reset = await r.auth.resetSecret({ externalUsername: user });
    return { state: 'enroll', enroll: { qrCodeDataUrl: reset.qrCodeDataUrl as string, recoveryCodes: reset.recoveryCodes, expiresAt: reset.expiresAt } };
  }
}

/** Current state of a started approval. */
export async function check(r: Resources, requestId: string): Promise<Step> {
  const s = await r.login.status(requestId);
  const map: Record<string, StepState> = { PENDING: 'waiting', CONFIRMED: 'approved', REJECTED: 'rejected', EXPIRED: 'expired' };
  const state: StepState = s.status === 'PENDING' && s.requiresPasskey ? 'passkey_required' : map[s.status] || 'waiting';
  return { state, requestId, ...(state === 'approved' && s.assurance ? { assurance: s.assurance } : {}) };
}

export interface CompleteExpectations {
  user: string;
  action: string;
  details?: LoginRequestDetails;
  referenceId?: string;
}

/**
 * Uses an approved request exactly once and checks it is for THIS user, action and
 * transaction. Throws if it was already used, not approved, or approved for something else.
 */
export async function complete(r: Resources, requestId: string, expect: CompleteExpectations): Promise<Approval> {
  const res = await r.http.post<{
    externalUsername: string; type: string; referenceId: string | null; details: Array<{ label: string; value: string }> | null;
    confirmedVia: string | null; assurance: ApprovalAssurance | null; approvalProof: unknown;
  }>(`/login/${encodeURIComponent(requestId)}/consume`, {});
  const sameUser = String(res.externalUsername).toLowerCase() === String(expect.user).toLowerCase();
  const sameDetails = detailsDigest(normalizeDetails(expect.details)) === detailsDigest(res.details || []);
  const sameRef = (res.referenceId || null) === (expect.referenceId || null);
  if (!sameUser || res.type !== expect.action || !sameDetails || !sameRef) {
    throw new TouchQueError('TouchQue: this approval is for a different user, action or transaction.');
  }
  return {
    requestId,
    user: res.externalUsername,
    action: res.type,
    assurance: res.assurance,
    confirmedVia: res.confirmedVia,
    approvalProof: res.approvalProof,
  };
}

// ─── Guard token ──────────────────────────────────────────────────────────
// The browser echoes this back while it waits. It is signed with a key derived
// from your API secret and binds the approval to one user, action and
// transaction, so it cannot be replayed for another user, amount or route.

export interface GuardTokenClaims {
  u: string; // user
  a: string; // action
  d: string; // details digest
  r: string | null; // referenceId
  st: StepState;
  rid?: string; // requestId
  n?: string; // matching number
  oc?: string; // offline challenge id
  exp: number; // ms
}

const b64u = (b: Buffer) => b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64u = (s: string) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
const tokenKey = (apiSecret: string) => crypto.createHmac('sha256', apiSecret).update('touchque-guard-token-v1').digest();

export function signGuardToken(apiSecret: string, claims: GuardTokenClaims): string {
  const body = b64u(Buffer.from(JSON.stringify(claims), 'utf8'));
  const mac = b64u(crypto.createHmac('sha256', tokenKey(apiSecret)).update(body).digest());
  return `v1.${body}.${mac}`;
}

export function verifyGuardToken(apiSecret: string, token: unknown): GuardTokenClaims | null {
  if (typeof token !== 'string' || token.length > 4096) return null;
  const [v, body, mac] = token.split('.');
  if (v !== 'v1' || !body || !mac) return null;
  const expected = crypto.createHmac('sha256', tokenKey(apiSecret)).update(body).digest();
  const given = fromB64u(mac);
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;
  try {
    const claims = JSON.parse(fromB64u(body).toString('utf8')) as GuardTokenClaims;
    if (typeof claims.exp !== 'number' || claims.exp < Date.now()) return null;
    return claims;
  } catch {
    return null;
  }
}
