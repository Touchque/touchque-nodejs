// src/securityEvents.ts
// Shared Signals (OpenID Shared Signals Framework 1.0): Security Event
// Tokens (SETs, RFC 8417) an identity provider sends when something happens
// to a person's account after sign-in: CAEP session-revoked,
// credential-change, device-compliance-change; RISC account-disabled,
// credential-compromise. TouchQue SSO sends them for an organization's
// members to the receivers its admin adds (Organization > Continuous access).
// Your app ends the person's sessions or asks them to sign in again.
//
// Push delivery (RFC 8935): the SET is the request body (application/secevent+jwt).
//   const verifier = new SecurityEventVerifier({ issuer: 'https://sso.touchque.com', audience: 'https://app.example.com' });
//   app.post('/ssf', express.text({ type: 'application/secevent+jwt' }), async (req, res) => {
//     try {
//       const event = await verifier.verify(req.body);
//       if (event.name === 'session-revoked') await endSessionsOf(event.subject.email);
//       res.status(202).end();
//     } catch (err) {
//       if (err instanceof SecurityEventError) return res.status(400).json({ err: err.code, description: err.message });
//       throw err;
//     }
//   });
// Poll delivery (RFC 8936): pollSecurityEvents({ url, token, ack }) with the stream's token.
//
// A SET does not expire: it says what happened. It carries a jti; keep the
// ones you handled and skip a repeat.

import * as crypto from 'crypto';
import { TouchQueConfigError } from './errors';
import { b64urlJson, getJson, keyOf, safeUrl, verifyJws, type Jwk } from './jwsKeys';

const SET_TYP = 'secevent+jwt';
const NAMESPACE = /^https:\/\/schemas\.openid\.net\/secevent\/(caep|risc|ssf)\/event-type\/([a-z0-9-]+)$/;

/** The event types TouchQue sends, by their short name. */
export const SECURITY_EVENT_TYPES = {
  'session-revoked': 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
  'credential-change': 'https://schemas.openid.net/secevent/caep/event-type/credential-change',
  'device-compliance-change': 'https://schemas.openid.net/secevent/caep/event-type/device-compliance-change',
  'account-disabled': 'https://schemas.openid.net/secevent/risc/event-type/account-disabled',
  'credential-compromise': 'https://schemas.openid.net/secevent/risc/event-type/credential-compromise',
  verification: 'https://schemas.openid.net/secevent/ssf/event-type/verification',
  'stream-updated': 'https://schemas.openid.net/secevent/ssf/event-type/stream-updated',
} as const;

/**
 * A refused SET. `code` is the RFC 8935 error to answer with (HTTP 400 { err: code }):
 * invalid_request, invalid_key, invalid_issuer or invalid_audience; temporarily_unavailable
 * when the issuer's keys could not be read (answer 503: the transmitter tries again).
 */
export class SecurityEventError extends Error {
  constructor(public readonly code: string, message: string) {
    super(message);
    this.name = 'SecurityEventError';
  }
}

export interface SecurityEvent {
  jti: string;
  issuer: string;
  audience: string[];
  /** Seconds since the epoch. */
  issuedAt: number;
  /** TouchQue puts the case code of its decision here ("Why?" in the dashboard). */
  txn: string | null;
  /** The subject as sent (sub_id): { format: 'email', email } for a person, { format: 'opaque', id } for the stream. */
  subject: Record<string, unknown>;
  /** The event type URI. */
  type: string;
  /** Its short name (session-revoked …) for CAEP, RISC and SSF types; null for others. */
  name: string | null;
  /** The event's own claims (event_timestamp, reason_admin, credential_type …). */
  claims: Record<string, unknown>;
}

export interface SecurityEventVerifierOptions {
  /** The transmitter's issuer, e.g. https://sso.touchque.com. */
  issuer: string;
  /** Your stream's audience (aud), as the dashboard shows it. */
  audience: string;
  /** Its JWKS, when not found from the issuer's /.well-known/ssf-configuration. */
  jwksUri?: string;
  /** Fixed keys instead (tests, or keys you pin). */
  jwks?: { keys: Jwk[] };
  /** Seconds of clock skew allowed for iat (default 300). */
  clockSkew?: number;
}

export class SecurityEventVerifier {
  private readonly issuer: string;
  private readonly audience: string;
  private readonly skew: number;
  private jwksUri?: string;
  private keys = new Map<string, crypto.KeyObject>();
  private keysAt = 0;
  private triedAt = 0;
  private readonly pinned: boolean;

  constructor(options: SecurityEventVerifierOptions) {
    if (!options?.issuer || !options?.audience) throw new TouchQueConfigError('SecurityEventVerifier needs issuer (the transmitter) and audience (your stream\'s aud)');
    this.issuer = options.issuer;
    this.audience = options.audience;
    this.jwksUri = options.jwksUri;
    this.skew = options.clockSkew ?? 300;
    this.pinned = !!options.jwks;
    if (options.jwks) this.setKeys(options.jwks);
  }

  private setKeys(jwks: { keys?: Jwk[] }): void {
    const keys = new Map<string, crypto.KeyObject>();
    for (const k of jwks.keys || []) if (k.kid) keys.set(k.kid, keyOf(k));
    this.keys = keys;
    this.keysAt = Date.now();
  }

  private async loadKeys(): Promise<void> {
    if (!this.jwksUri) {
      const meta = await getJson(`${this.issuer.replace(/\/+$/, '')}/.well-known/ssf-configuration`);
      if (meta.issuer !== this.issuer || typeof meta.jwks_uri !== 'string') throw new Error('the transmitter\'s metadata does not match its issuer');
      this.jwksUri = meta.jwks_uri;
    }
    if (!safeUrl(this.jwksUri)) throw new Error(`${this.jwksUri} must be an https URL`);
    this.setKeys(await getJson(this.jwksUri) as { keys?: Jwk[] });
  }

  private async keyFor(kid: string): Promise<crypto.KeyObject | undefined> {
    if (this.pinned) return this.keys.get(kid);
    if (!this.keysAt || Date.now() - this.keysAt > 3600000) await this.loadKeys();
    if (!this.keys.has(kid) && Date.now() - this.triedAt > 300000) {
      this.triedAt = Date.now();
      await this.loadKeys();
    }
    return this.keys.get(kid);
  }

  /** A SET, checked: signature (RS256, the issuer's keys), typ, issuer, audience, one event. */
  async verify(token: string): Promise<SecurityEvent> {
    const bad = (message: string) => new SecurityEventError('invalid_request', message);
    const parts = typeof token === 'string' ? token.trim().split('.') : [];
    if (parts.length !== 3) throw bad('not a JWT');
    let head: Record<string, unknown>;
    let c: Record<string, unknown>;
    try {
      head = b64urlJson(parts[0]);
      c = b64urlJson(parts[1]);
    } catch {
      throw bad('not a JWT');
    }
    if (String(head.typ || '').toLowerCase() !== SET_TYP) throw bad('not a Security Event Token (typ secevent+jwt)');
    if (head.alg !== 'RS256' || typeof head.kid !== 'string') throw new SecurityEventError('invalid_key', 'unsupported signature');
    let key: crypto.KeyObject | undefined;
    try {
      key = await this.keyFor(head.kid);
    } catch (err) {
      throw new SecurityEventError('temporarily_unavailable', `the transmitter's keys could not be read: ${(err as Error).message}`);
    }
    if (!key || !verifyJws(`${parts[0]}.${parts[1]}`, Buffer.from(parts[2], 'base64url'), 'RS256', key)) throw new SecurityEventError('invalid_key', 'signature does not verify');
    if (c.iss !== this.issuer) throw new SecurityEventError('invalid_issuer', 'another issuer');
    const audience = (Array.isArray(c.aud) ? c.aud : [c.aud]).filter((a): a is string => typeof a === 'string');
    if (!audience.includes(this.audience)) throw new SecurityEventError('invalid_audience', 'not for this receiver');
    if (typeof c.jti !== 'string' || typeof c.iat !== 'number') throw bad('jti and iat are required');
    if (c.iat - this.skew > Math.floor(Date.now() / 1000)) throw bad('issued in the future');
    const events = c.events && typeof c.events === 'object' && !Array.isArray(c.events) ? Object.entries(c.events as Record<string, unknown>) : [];
    if (events.length !== 1) throw bad('a SET carries exactly one event');
    const [type, claims] = events[0];
    const m = NAMESPACE.exec(type);
    return {
      jti: c.jti, issuer: c.iss as string, audience, issuedAt: c.iat, txn: typeof c.txn === 'string' ? c.txn : null,
      subject: c.sub_id && typeof c.sub_id === 'object' ? c.sub_id as Record<string, unknown> : {},
      type, name: m ? m[2] : null, claims: claims && typeof claims === 'object' ? claims as Record<string, unknown> : {},
    };
  }
}

export interface PollSecurityEventsOptions {
  /** The stream's poll endpoint (its delivery.endpoint_url). */
  url: string;
  /** The stream's token. */
  token: string;
  /** jtis you handled since the last poll. */
  ack?: string[];
  /** jtis you could not handle: { jti: { err, description } }. */
  setErrs?: Record<string, { err: string; description?: string }>;
  maxEvents?: number;
  returnImmediately?: boolean;
}

/** One poll (RFC 8936): acknowledges what you handled and returns the waiting SETs { jti: token }. */
export async function pollSecurityEvents(o: PollSecurityEventsOptions): Promise<{ sets: Record<string, string>; moreAvailable: boolean }> {
  const u = safeUrl(o.url);
  if (!u) throw new TouchQueConfigError(`${o.url} must be an https URL`);
  if (!o.token) throw new TouchQueConfigError('pollSecurityEvents needs the stream\'s token');
  const res = await fetch(u, {
    method: 'POST', redirect: 'error', signal: AbortSignal.timeout(30000),
    headers: { 'Content-Type': 'application/json', Accept: 'application/json', Authorization: `Bearer ${o.token}` },
    body: JSON.stringify({
      ...(o.ack && { ack: o.ack }), ...(o.setErrs && { setErrs: o.setErrs }),
      ...(o.maxEvents !== undefined && { maxEvents: o.maxEvents }), ...(o.returnImmediately !== undefined && { returnImmediately: o.returnImmediately }),
    }),
  });
  const data = await res.json().catch(() => ({})) as Record<string, unknown>;
  if (!res.ok) throw new SecurityEventError(String(data.error || 'server_error'), `${o.url} answered ${res.status}`);
  return { sets: (data.sets && typeof data.sets === 'object' ? data.sets : {}) as Record<string, string>, moreAvailable: data.moreAvailable === true };
}
