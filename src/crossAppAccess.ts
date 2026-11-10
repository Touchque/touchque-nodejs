// src/crossAppAccess.ts
// Cross App Access: Identity Assertion JWT Authorization Grants (ID-JAG,
// draft-ietf-oauth-identity-assertion-authz-grant, an open standard). An
// organization's identity provider (TouchQue SSO) decides which of its apps
// may reach which other service for its members; the app trades a member's
// ID token for an ID-JAG there, then the ID-JAG for an access token at the
// other service's authorization server, with no consent screen per member.
//
// Your app, signed in with TouchQue SSO (an OpenID Connect app with a secret):
//   const { assertion } = await requestIdJag({ issuer: 'https://sso.touchque.com', clientId, clientSecret,
//                                              idToken, audience: 'https://auth.files.example' });
//   const tokens = await redeemIdJag({ tokenEndpoint: 'https://auth.files.example/token', clientId: 'acme', clientSecret, assertion });
//
// Your own authorization server, taking ID-JAGs from an organization's identity provider:
//   const idJag = new IdJagVerifier({ issuer: 'https://sso.touchque.com', audience: 'https://auth.files.example' });
//   const claims = await idJag.verify(req.body.assertion, { clientId: authenticatedClientId });
//   // claims.sub (the member at that identity provider), claims.email, claims.scopes, claims.resource, claims.tenant

import * as crypto from 'crypto';
import { TouchQueConfigError } from './errors';
import { ALGS, b64urlJson, getJson, keyOf, safeUrl, verifyJws, type Jwk } from './jwsKeys';

export const ID_JAG_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id-jag';
export const ID_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id_token';
export const TOKEN_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';
export const JWT_BEARER_GRANT = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
const ID_JAG_TYP = 'oauth-id-jag+jwt';

/** A refused ID-JAG or exchange; `code` is the OAuth error (invalid_grant for a bad ID-JAG). */
export class IdJagError extends Error {
  constructor(public readonly code: string, message: string, public readonly status?: number) {
    super(message);
    this.name = 'IdJagError';
  }
}

export interface IdJagVerifierOptions {
  /** The identity provider's issuer, e.g. https://sso.touchque.com. */
  issuer: string;
  /** Your authorization server's issuer identifier: the ID-JAG's aud. */
  audience: string;
  /** Its JWKS, when not found from the issuer's /.well-known/openid-configuration. */
  jwksUri?: string;
  /** Seconds of clock skew allowed (default 60). */
  clockSkew?: number;
  /**
   * Records an ID-JAG's jti and says whether it is new (each is used once). Defaults to memory in
   * this process; give a shared store (Redis SET NX) when several processes take ID-JAGs.
   */
  firstUse?: (jti: string, expiresAt: number) => boolean | Promise<boolean>;
}

export interface IdJagClaims {
  iss: string;
  /** The member at the identity provider. */
  sub: string;
  aud: string;
  /** Your client_id of the app that presented it. */
  clientId: string;
  jti: string;
  issuedAt: number;
  expiresAt: number;
  scopes: string[];
  resource?: string;
  tenant?: string;
  email?: string;
  authTime?: number;
  amr?: string[];
  claims: Record<string, unknown>;
}

export class IdJagVerifier {
  private readonly issuer: string;
  private readonly audience: string;
  private readonly skew: number;
  private readonly firstUse: (jti: string, expiresAt: number) => boolean | Promise<boolean>;
  private jwksUri?: string;
  private keys = new Map<string, crypto.KeyObject>();
  private keysAt = 0;
  private triedAt = 0;
  private readonly seen = new Map<string, number>();

  constructor(options: IdJagVerifierOptions) {
    if (!options?.issuer || !options?.audience) throw new TouchQueConfigError('IdJagVerifier needs issuer (the identity provider) and audience (your authorization server\'s issuer)');
    this.issuer = options.issuer;
    this.audience = options.audience;
    this.jwksUri = options.jwksUri;
    this.skew = options.clockSkew ?? 60;
    this.firstUse = options.firstUse || ((jti, exp) => this.rememberOnce(jti, exp));
  }

  private rememberOnce(jti: string, expiresAt: number): boolean {
    const now = Math.floor(Date.now() / 1000);
    for (const [k, exp] of this.seen) if (exp < now) this.seen.delete(k);
    if (this.seen.has(jti)) return false;
    this.seen.set(jti, expiresAt + this.skew);
    return true;
  }

  private async loadKeys(): Promise<void> {
    if (!this.jwksUri) {
      const meta = await getJson(`${this.issuer.replace(/\/+$/, '')}/.well-known/openid-configuration`);
      if (meta.issuer !== this.issuer || typeof meta.jwks_uri !== 'string') throw new Error('the identity provider\'s metadata does not match its issuer');
      this.jwksUri = meta.jwks_uri;
    }
    const jwks = await getJson(this.jwksUri) as { keys?: Jwk[] };
    const keys = new Map<string, crypto.KeyObject>();
    for (const k of jwks.keys || []) if (k.kid) keys.set(k.kid, keyOf(k));
    this.keys = keys;
    this.keysAt = Date.now();
  }

  private async keyFor(kid: string): Promise<crypto.KeyObject | undefined> {
    if (!this.keysAt || Date.now() - this.keysAt > 600000) await this.loadKeys();
    if (!this.keys.has(kid) && Date.now() - this.triedAt > 60000) {
      this.triedAt = Date.now();
      await this.loadKeys();
    }
    return this.keys.get(kid);
  }

  /** The ID-JAG an authenticated client presented (jwt-bearer grant), checked and used once. */
  async verify(assertion: string, expected: { clientId: string }): Promise<IdJagClaims> {
    const bad = (message: string) => new IdJagError('invalid_grant', message);
    const parts = typeof assertion === 'string' ? assertion.split('.') : [];
    if (parts.length !== 3) throw bad('assertion is not a JWT');
    let head: Record<string, unknown>;
    let c: Record<string, unknown>;
    try {
      head = b64urlJson(parts[0]);
      c = b64urlJson(parts[1]);
    } catch {
      throw bad('assertion is not a JWT');
    }
    if (head.typ !== ID_JAG_TYP) throw bad('not an ID-JAG (typ oauth-id-jag+jwt)');
    if (!ALGS.includes(String(head.alg)) || typeof head.kid !== 'string') throw bad('unsupported signature');
    let key: crypto.KeyObject | undefined;
    try {
      key = await this.keyFor(head.kid);
    } catch (err) {
      throw new IdJagError('temporarily_unavailable', `the identity provider's keys could not be read: ${(err as Error).message}`);
    }
    if (!key || !verifyJws(`${parts[0]}.${parts[1]}`, Buffer.from(parts[2], 'base64url'), String(head.alg), key)) throw bad('signature does not verify');
    const now = Math.floor(Date.now() / 1000);
    const auds = Array.isArray(c.aud) ? c.aud : [c.aud];
    if (c.iss !== this.issuer) throw bad('another issuer');
    if (auds.length !== 1 || auds[0] !== this.audience) throw bad('not for this authorization server');
    if (typeof c.client_id !== 'string' || c.client_id !== expected?.clientId) throw bad('issued to another client');
    if (typeof c.exp !== 'number' || c.exp + this.skew < now) throw bad('expired');
    if (typeof c.iat !== 'number' || c.iat - this.skew > now) throw bad('issued in the future');
    if (typeof c.sub !== 'string' || typeof c.jti !== 'string') throw bad('sub and jti are required');
    if (!(await this.firstUse(c.jti, c.exp))) throw bad('already used');
    return {
      iss: c.iss as string, sub: c.sub, aud: auds[0] as string, clientId: c.client_id, jti: c.jti, issuedAt: c.iat, expiresAt: c.exp,
      scopes: typeof c.scope === 'string' && c.scope ? c.scope.split(' ') : [],
      ...(typeof c.resource === 'string' && { resource: c.resource }),
      ...(typeof c.tenant === 'string' && { tenant: c.tenant }),
      ...(typeof c.email === 'string' && { email: c.email }),
      ...(typeof c.auth_time === 'number' && { authTime: c.auth_time }),
      ...(Array.isArray(c.amr) && { amr: c.amr.map(String) }),
      claims: c,
    };
  }
}

async function postForm(url: string, form: Record<string, string | undefined>, basic?: { id: string; secret: string }): Promise<Record<string, unknown>> {
  const u = safeUrl(url);
  if (!u) throw new TouchQueConfigError(`${url} must be an https URL`);
  const body = new URLSearchParams();
  for (const [k, v] of Object.entries(form)) if (v !== undefined) body.set(k, v);
  const res = await fetch(u, {
    method: 'POST', redirect: 'error', signal: AbortSignal.timeout(10000),
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json',
      ...(basic && { Authorization: `Basic ${Buffer.from(`${encodeURIComponent(basic.id)}:${encodeURIComponent(basic.secret)}`).toString('base64')}` }),
    },
    body: body.toString(),
  });
  const data = await res.json().catch(() => ({})) as Record<string, unknown>;
  if (!res.ok) throw new IdJagError(String(data.error || 'server_error'), String(data.error_description || `${url} answered ${res.status}`), res.status);
  return data;
}

const scopeText = (scope?: string | string[]) => (Array.isArray(scope) ? scope.join(' ') : scope);

export interface RequestIdJagOptions {
  /** The identity provider's issuer (its token endpoint is discovered), or give tokenEndpoint. */
  issuer?: string;
  tokenEndpoint?: string;
  /** Your app at the identity provider (tqapp_… at TouchQue SSO) and its secret. */
  clientId: string;
  clientSecret: string;
  /** The member's ID token the identity provider issued to your app. */
  idToken: string;
  /** The other service's authorization server (its issuer). */
  audience: string;
  resource?: string;
  scope?: string | string[];
}

/** Trades a member's ID token for an ID-JAG at the identity provider (token exchange, client_secret_basic). */
export async function requestIdJag(o: RequestIdJagOptions): Promise<{ assertion: string; expiresIn?: number; scope?: string }> {
  let endpoint = o.tokenEndpoint;
  if (!endpoint) {
    if (!o.issuer) throw new TouchQueConfigError('requestIdJag needs issuer or tokenEndpoint');
    const meta = await getJson(`${o.issuer.replace(/\/+$/, '')}/.well-known/openid-configuration`);
    if (meta.issuer !== o.issuer || typeof meta.token_endpoint !== 'string') throw new TouchQueConfigError('the identity provider\'s metadata does not match its issuer');
    endpoint = meta.token_endpoint;
  }
  const data = await postForm(endpoint, {
    grant_type: TOKEN_EXCHANGE_GRANT, requested_token_type: ID_JAG_TOKEN_TYPE, subject_token: o.idToken, subject_token_type: ID_TOKEN_TYPE,
    audience: o.audience, resource: o.resource, scope: scopeText(o.scope),
  }, { id: o.clientId, secret: o.clientSecret });
  if (data.issued_token_type !== ID_JAG_TOKEN_TYPE || typeof data.access_token !== 'string') throw new IdJagError('invalid_response', 'the identity provider did not answer with an ID-JAG');
  return { assertion: data.access_token, ...(typeof data.expires_in === 'number' && { expiresIn: data.expires_in }), ...(typeof data.scope === 'string' && { scope: data.scope }) };
}

/** Trades an ID-JAG for an access token at the other service's authorization server (jwt-bearer). */
export async function redeemIdJag(o: { tokenEndpoint: string; clientId: string; clientSecret?: string; assertion: string; resource?: string; scope?: string | string[] }): Promise<Record<string, unknown>> {
  return postForm(o.tokenEndpoint, {
    grant_type: JWT_BEARER_GRANT, assertion: o.assertion, resource: o.resource, scope: scopeText(o.scope),
    ...(!o.clientSecret && { client_id: o.clientId }),
  }, o.clientSecret ? { id: o.clientId, secret: o.clientSecret } : undefined);
}
