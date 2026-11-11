// src/approvalToken.ts
// What a partner's server checks before executing what an AI agent asked
// for: the approval token's claims match the transaction (person, action
// type, authorization details), and, offline, its ES256 signature against
// Touchque's keys (GET /agents/jwks.json). Matching rules (fixtures/agent-vectors.json):
// every expected field must be equal, extra fields are ignored; amounts
// compare as decimals ("500" = "500.00"), IBANs without spaces and in any
// case, currencies in any case; an object matches a token with exactly one
// entry, an array matches entry by entry with the same length.

import * as crypto from 'crypto';
import { TouchqueApprovalMismatchError } from './errors';

export interface AuthorizationDetail {
  type: 'payment_initiation' | 'purchase' | 'data_access' | 'account_change' | 'message_send' | 'generic' | string;
  [field: string]: unknown;
}

export interface ApprovalTokenClaims {
  iss: string;
  aud: string;
  /** The person who approved. */
  sub: string;
  /** The agent that asked. */
  act: { sub: string; name?: string };
  authorization_details: AuthorizationDetail[];
  /** The approval (request) id. */
  txn: string;
  type: string;
  jti: string;
  iat: number;
  exp: number;
  /** The agent's DPoP key thumbprint. */
  cnf: { jkt: string };
  amr: string[];
  number_matched: boolean;
  presence: 'interactive' | 'background';
  /** The rows the phone showed (and, with `proof`, signed). */
  details: Array<{ label: string; value: string }>;
  proof?: Record<string, unknown>;
  cc?: string;
}

/** What the executor is about to do; omitted fields are not checked. */
export interface ApprovalExpectation {
  user?: string;
  type?: string;
  /** One entry (the token must hold exactly one), or every entry in order. */
  authorizationDetails?: Record<string, unknown> | Array<Record<string, unknown>>;
}

function decimal(value: unknown): string | null {
  const text = String(value).trim();
  if (!/^\d+(\.\d+)?$/.test(text)) return null;
  const [whole, frac = ''] = text.split('.');
  const w = whole.replace(/^0+(?=\d)/, '');
  const f = frac.replace(/0+$/, '');
  return f ? `${w}.${f}` : w;
}

function sameValue(key: string, actual: unknown, expected: unknown): boolean {
  if (expected !== null && typeof expected === 'object') return partial(actual, expected);
  if (key === 'amount') return decimal(actual) !== null && decimal(actual) === decimal(expected);
  if (key === 'iban' || key === 'currency') {
    const norm = (v: unknown) => String(v).replace(/\s+/g, '').toUpperCase();
    return typeof actual === 'string' && norm(actual) === norm(expected);
  }
  return actual === expected;
}

function partial(actual: unknown, expected: unknown): boolean {
  if (Array.isArray(expected)) {
    return Array.isArray(actual) && actual.length === expected.length
      && expected.every((e, i) => (e !== null && typeof e === 'object' ? partial(actual[i], e) : actual[i] === e));
  }
  if (!actual || typeof actual !== 'object' || Array.isArray(actual)) return false;
  return Object.entries(expected as Record<string, unknown>)
    .every(([k, v]) => k in (actual as Record<string, unknown>) && sameValue(k, (actual as Record<string, unknown>)[k], v));
}

/** Does `details` (a token's authorization_details) say what `expected` says? */
export function matchesAuthorizationDetails(details: unknown, expected: Record<string, unknown> | Array<Record<string, unknown>>): boolean {
  if (!Array.isArray(details)) return false;
  if (Array.isArray(expected)) return details.length === expected.length && expected.every((e, i) => partial(details[i], e));
  return details.length === 1 && partial(details[0], expected);
}

/** Throws TouchqueApprovalMismatchError unless the claims say what `expect` says. */
export function assertApprovalMatches(claims: { sub?: string; type?: string; authorization_details?: unknown }, expect: ApprovalExpectation = {}): void {
  if (expect.user !== undefined && claims.sub !== expect.user) throw new TouchqueApprovalMismatchError('the approval is for another person');
  if (expect.type !== undefined && claims.type !== expect.type) throw new TouchqueApprovalMismatchError(`the approval is for another action type (${claims.type})`);
  if (expect.authorizationDetails !== undefined && !matchesAuthorizationDetails(claims.authorization_details, expect.authorizationDetails)) {
    throw new TouchqueApprovalMismatchError('the approved details differ from what you are about to execute');
  }
}

const b64json = (part: string) => JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));

/** The claims of an approval token WITHOUT checking its signature (redeemApproval checks it on Touchque). */
export function decodeApprovalToken(token: string): { header: Record<string, any>; claims: ApprovalTokenClaims } {
  const parts = typeof token === 'string' ? token.split('.') : [];
  if (parts.length !== 3) throw new TouchqueApprovalMismatchError('not an approval token');
  try {
    return { header: b64json(parts[0]), claims: b64json(parts[1]) };
  } catch {
    throw new TouchqueApprovalMismatchError('not an approval token');
  }
}

export interface Jwks { keys: Array<Record<string, any>> }

/**
 * Verifies an approval token offline: typ touchque-approval+jwt, ES256 by a
 * key of `jwks`, not expired (30 s leeway), `aud` equal to `audience`, then
 * `expect`. `audience` is required: `/agents/jwks.json` is one key set for
 * every Touchque workspace, so without it a token Touchque signed for another
 * workspace would pass. Pass your own (`await tq.agents.approvalAudience()`,
 * `touchque:workspace:<id>`), or use `tq.agents.verifyApprovalToken`, which
 * fills it in. Does NOT make it single-use: call redeemApproval for that.
 */
export function verifyApprovalTokenWith(token: string, jwks: Jwks, options: { audience: string; expect?: ApprovalExpectation; now?: number }): ApprovalTokenClaims {
  if (typeof options?.audience !== 'string' || !options.audience) {
    throw new TouchqueApprovalMismatchError("audience is required: your workspace's touchque:workspace:<id> (tq.agents.approvalAudience())");
  }
  const { header, claims } = decodeApprovalToken(token);
  if (header.typ !== 'touchque-approval+jwt' || header.alg !== 'ES256') throw new TouchqueApprovalMismatchError('not an approval token (typ/alg)');
  const jwk = (jwks.keys || []).find((k) => k.kid === header.kid && k.kty === 'EC' && k.crv === 'P-256');
  if (!jwk) throw new TouchqueApprovalMismatchError('signed by an unknown key');
  const [h, p, s] = token.split('.');
  const key = crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, format: 'jwk' });
  const sig = Buffer.from(s, 'base64url');
  if (sig.length !== 64 || !crypto.verify('sha256', Buffer.from(`${h}.${p}`), { key, dsaEncoding: 'ieee-p1363' }, sig)) {
    throw new TouchqueApprovalMismatchError('the signature does not verify');
  }
  const now = Math.floor((options.now ?? Date.now()) / 1000);
  if (typeof claims.exp !== 'number' || claims.exp + 30 < now) throw new TouchqueApprovalMismatchError('the approval token expired');
  if (typeof claims.aud !== 'string' || !claims.aud) throw new TouchqueApprovalMismatchError('the approval token names no workspace');
  if (claims.aud !== options.audience) throw new TouchqueApprovalMismatchError('the approval token is for another workspace');
  assertApprovalMatches(claims, options.expect);
  return claims;
}
