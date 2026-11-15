// src/crossAppAccess.ts
// Cross App Access: Identity Assertion JWT Authorization Grants (ID-JAG,
// draft-ietf-oauth-identity-assertion-authz-grant, an open standard). An
// organization's identity provider (Touchque SSO) decides which of its apps
// may reach which other service for its members; the app trades a member's
// ID token for an ID-JAG there, then the ID-JAG for an access token at the
// other service's authorization server, with no consent screen per member.
//
// Your app, signed in with Touchque SSO (an OpenID Connect app with a secret):
//   const { assertion } = await requestIdJag({ issuer: 'https://sso.touchque.com', clientId, clientSecret,
//                                              idToken, audience: 'https://auth.files.example' });
//   const tokens = await redeemIdJag({ tokenEndpoint: 'https://auth.files.example/token', clientId: 'acme', clientSecret, assertion });
//
// Your own authorization server, taking ID-JAGs from an organization's identity provider (build the
// verifier once, not per request: its used-once jti store and key cache live in it):
//   const idJag = new IdJagVerifier({ issuer: 'https://sso.touchque.com', audience: 'https://auth.files.example' });
//   const claims = await idJag.verify(req.body.assertion, { clientId: authenticatedClientId });
//   // claims.sub (the member at that identity provider), claims.email, claims.scopes, claims.resource, claims.tenant
//
// Sender-constrained with DPoP (RFC 9449), optional: give the same key to both calls. The ID-JAG
// is then bound to it (cnf.jkt) and is useless to anyone who copies it without the key.
//   const dpopKey = createIdJagDpopKey();
//   const { assertion } = await requestIdJag({ ...asAbove, dpopKey });
//   const tokens = await redeemIdJag({ ...asAbove, assertion, dpopKey });
// A token endpoint that asks for a nonce (use_dpop_nonce with a valid DPoP-Nonce header) gets the
// same request once more, with a new proof that carries it. A DPoP-bound access token goes to the
// resource with a proof for that method and URL that carries the token's hash (ath):
//   await fetch(url, { headers: { Authorization: `DPoP ${accessToken}`, DPoP: idJagDpopProof(dpopKey, url, { method: 'GET', accessToken }) } });
// An authorization server that checks DPoP proofs passes the proof key's thumbprint:
//   await idJag.verify(assertion, { clientId, dpopJkt });   // a bound ID-JAG without it is refused

import * as crypto from 'crypto';
import { TouchqueConfigError } from './errors';
import { ALGS, b64urlJson, getJson, keyOf, safeUrl, verifyJws, type Jwk } from './jwsKeys';
import { jwkThumbprint } from './agent';

export const ID_JAG_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id-jag';
export const ID_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id_token';
export const TOKEN_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';
export const JWT_BEARER_GRANT = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
const ID_JAG_TYP = 'oauth-id-jag+jwt';

/**
 * A refused ID-JAG or exchange; `code` is the OAuth error (invalid_grant for a bad ID-JAG,
 * temporarily_unavailable when a server could not be reached or its answer read).
 * `dpopNonce`: the latest valid DPoP-Nonce the server sent during the call (RFC 9449 section 8),
 * if any: the retry's answer's when it had one, else the first answer's. A proof from
 * `idJagDpopProof(key, url, { nonce: err.dpopNonce })` carries it.
 */
export class IdJagError extends Error {
  constructor(public readonly code: string, message: string, public readonly status?: number, public readonly dpopNonce?: string) {
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
  /** The DPoP key thumbprint the ID-JAG is bound to (cnf.jkt), when it is. */
  cnfJkt?: string;
  claims: Record<string, unknown>;
}

/** A DPoP key (RFC 9449, P-256) that binds an ID-JAG to its holder; keep it in this process. */
export interface IdJagDpopKey {
  privateKey: crypto.KeyObject;
  publicJwk: Jwk;
  /** RFC 7638 thumbprint: the ID-JAG's cnf.jkt. */
  thumbprint: string;
}

/** Makes a fresh DPoP key for requestIdJag and redeemIdJag. */
export function createIdJagDpopKey(): IdJagDpopKey {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const pub = publicKey.export({ format: 'jwk' }) as Jwk;
  const publicJwk: Jwk = { kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y };
  return { privateKey, publicJwk, thumbprint: jwkThumbprint(publicJwk) };
}

/** What a proof from idJagDpopProof is for, besides its URL. */
export interface IdJagDpopProofOptions {
  /**
   * The request's HTTP method, sent trimmed and uppercased as htm; empty (or blank) means POST.
   * Anything but RFC 9110 token characters is a TouchqueConfigError.
   */
  method?: string;
  /** The DPoP-bound access token the request carries (Authorization: DPoP <token>): adds ath, its SHA-256. */
  accessToken?: string;
  /** The server's DPoP-Nonce (RFC 9449 section 8): adds the nonce claim. */
  nonce?: string;
}

// RFC 9110 token characters (tchar): an HTTP method, an auth-scheme or a parameter name.
const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

/**
 * A DPoP proof for one request to `url`: a POST to a token endpoint unless `options.method` says
 * otherwise. For a resource, give the method and the access token sent with it.
 * htu: scheme and host lowercased, the default port dropped, "/" for an empty path, the path kept
 * as given (its percent-encoding and case unchanged; like fetch, `new URL()` resolves "." and ".."
 * segments and percent-encodes characters a URL path cannot carry, such as spaces), no query or
 * fragment. The header's jwk is the key's kty, crv, x and y, nothing else.
 */
export function idJagDpopProof(key: IdJagDpopKey, url: string, options?: IdJagDpopProofOptions): string {
  const { method, accessToken, nonce } = options || {};
  // Checked before uppercasing, which can turn a character that is not a token character into ones that are (ß becomes SS).
  const given = String(method ?? '').trim();
  if (given && !TOKEN.test(given)) throw new TouchqueConfigError(`idJagDpopProof: method ${JSON.stringify(given)} is not an HTTP method (RFC 9110 token characters only)`);
  const u = new URL(url);
  // Rebuilt, never passed through: a key made by hand may carry d or other members in publicJwk.
  const { kty, crv, x, y } = key.publicJwk;
  const b64 = (v: string | Buffer) => Buffer.from(v).toString('base64url');
  const input = `${b64(JSON.stringify({ typ: 'dpop+jwt', alg: 'ES256', jwk: { kty, crv, x, y } }))}.${b64(JSON.stringify({
    htm: given ? given.toUpperCase() : 'POST', htu: `${u.protocol}//${u.host}${u.pathname}`, iat: Math.floor(Date.now() / 1000), jti: crypto.randomUUID(),
    ...(accessToken && { ath: b64(crypto.createHash('sha256').update(accessToken).digest()) }),
    ...(nonce && { nonce }),
  }))}`;
  return `${input}.${b64(crypto.sign('sha256', Buffer.from(input), { key: key.privateKey, dsaEncoding: 'ieee-p1363' }))}`;
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
    if (!options?.issuer || !options?.audience) throw new TouchqueConfigError('IdJagVerifier needs issuer (the identity provider) and audience (your authorization server\'s issuer)');
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

  /**
   * The ID-JAG an authenticated client presented (jwt-bearer grant), checked and used once.
   * `dpopJkt`: the thumbprint of the DPoP proof you verified on this request, if any; an ID-JAG
   * bound to a key (cnf.jkt) is refused without a matching one.
   */
  async verify(assertion: string, expected: { clientId: string; dpopJkt?: string }): Promise<IdJagClaims> {
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
    // Before the jti is spent: a copy without the key cannot use the ID-JAG up.
    let cnfJkt: string | undefined;
    if (c.cnf !== undefined) {
      const cnf = c.cnf as Record<string, unknown> | null;
      if (!cnf || typeof cnf !== 'object' || typeof cnf.jkt !== 'string') throw bad('unsupported confirmation method (only DPoP cnf.jkt)');
      if (!expected?.dpopJkt) throw bad('bound to a DPoP key: a DPoP proof with that key is required');
      if (expected.dpopJkt !== cnf.jkt) throw bad('the DPoP proof was made with another key');
      cnfJkt = cnf.jkt;
    }
    if (!(await this.firstUse(c.jti, c.exp))) throw bad('already used');
    return {
      iss: c.iss as string, sub: c.sub, aud: auds[0] as string, clientId: c.client_id, jti: c.jti, issuedAt: c.iat, expiresAt: c.exp,
      scopes: typeof c.scope === 'string' && c.scope ? c.scope.split(' ') : [],
      ...(typeof c.resource === 'string' && { resource: c.resource }),
      ...(typeof c.tenant === 'string' && { tenant: c.tenant }),
      ...(typeof c.email === 'string' && { email: c.email }),
      ...(typeof c.auth_time === 'number' && { authTime: c.auth_time }),
      ...(Array.isArray(c.amr) && { amr: c.amr.map(String) }),
      ...(cnfJkt && { cnfJkt }),
      claims: c,
    };
  }
}

// RFC 9449 section 8: a nonce is 1*NQCHAR, printable ASCII but space, " and \ (%x21 / %x23-5B / %x5D-7E).
const NONCE = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

/**
 * The answer's DPoP-Nonce when it is one valid nonce, else undefined (missing, empty or not nonce
 * syntax). fetch reads a header sent twice as both values joined with ", ", which never is one.
 */
function nonceOf(res: Response): string | undefined {
  const value = res.headers.get('dpop-nonce');
  return value !== null && NONCE.test(value) ? value : undefined;
}

/** The server wants a nonce in the proof (RFC 9449 section 8): 400 or 401 use_dpop_nonce. */
function asksForNonce(res: Response, data: Record<string, unknown>): boolean {
  if (res.status !== 400 && res.status !== 401) return false;
  if (data.error === 'use_dpop_nonce') return true;
  // A 401 may say it only in a DPoP challenge, the resource server's form (section 9): WWW-Authenticate: DPoP error="use_dpop_nonce".
  return res.status === 401 && challengeAsksForNonce(res.headers.get('www-authenticate') || '');
}

/**
 * Whether a WWW-Authenticate value (RFC 9110 section 11.6.1; fetch joins repeated headers with
 * ", ") has a DPoP challenge with error="use_dpop_nonce". Linear in its length: items split at
 * commas outside quoted strings; an item that is not name=value starts a challenge (its scheme,
 * then maybe its first parameter).
 */
function challengeAsksForNonce(header: string): boolean {
  let dpop = false;
  for (const item of splitOutsideQuotes(header)) {
    let [name, rest] = leadingToken(item);
    if (!name && !rest) continue; // an empty list element
    if (rest[0] !== '=') {
      dpop = name.toLowerCase() === 'dpop';
      [name, rest] = leadingToken(rest);
    }
    if (dpop && name.toLowerCase() === 'error' && rest[0] === '=' && paramValue(rest.slice(1).trim()) === 'use_dpop_nonce') return true;
  }
  return false;
}

/** A header list split at the commas outside quoted strings (a quoted-pair's character is skipped). */
function splitOutsideQuotes(s: string): string[] {
  const items: string[] = [];
  let start = 0;
  let quoted = false;
  for (let i = 0; i < s.length; i++) {
    if (quoted && s[i] === '\\') i++;
    else if (s[i] === '"') quoted = !quoted;
    else if (!quoted && s[i] === ',') {
      items.push(s.slice(start, i));
      start = i + 1;
    }
  }
  items.push(s.slice(start));
  return items;
}

/** The leading token of s (RFC 9110 tchar) and the rest, blanks around the token dropped. */
function leadingToken(s: string): [string, string] {
  const m = /^[ \t]*([!#$%&'*+\-.^_`|~0-9A-Za-z]*)[ \t]*/.exec(s) as RegExpExecArray;
  return [m[1], s.slice(m[0].length)];
}

/** An auth-param value: a quoted-string's content with its quoted-pairs undone, or the token as it is. */
const paramValue = (v: string) => (v.length >= 2 && v[0] === '"' && v[v.length - 1] === '"' ? v.slice(1, -1).replace(/\\([\s\S])/g, '$1') : v);

/**
 * POSTs a form to a token endpoint: its answer as a JSON object ({} for anything else), and the
 * latest valid DPoP-Nonce the server sent. A refusal, or no readable answer, is an IdJagError.
 */
async function postForm(url: string, form: Record<string, string | undefined>, basic?: { id: string; secret: string }, dpopKey?: IdJagDpopKey): Promise<{ data: Record<string, unknown>; nonce?: string }> {
  const u = safeUrl(url);
  if (!u) throw new TouchqueConfigError(`${url} must be an https URL`);
  const body = new URLSearchParams();
  for (const [k, v] of Object.entries(form)) if (v !== undefined) body.set(k, v);
  // The latest valid DPoP-Nonce the server sent in this call; the retry's proof carries it.
  let nonce: string | undefined;
  // The same body and client authentication on every send; a new proof (jti, iat) each time.
  const send = async () => {
    const headers = {
      'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json',
      ...(dpopKey && { DPoP: idJagDpopProof(dpopKey, u.toString(), { nonce }) }),
      ...(basic && { Authorization: `Basic ${Buffer.from(`${encodeURIComponent(basic.id)}:${encodeURIComponent(basic.secret)}`).toString('base64')}` }),
    };
    let res: Response;
    try {
      res = await fetch(u, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(10000), headers, body: body.toString() });
    } catch (err) {
      // Not reached, no answer in 10 s, a redirect, or an answer fetch cannot read (by default
      // Node's fetch refuses response headers over 16 KB): an IdJagError, with fetch's error as its cause.
      const why = (err as { cause?: { message?: unknown } } | null)?.cause?.message || (err as { message?: unknown } | null)?.message || err;
      const failed = new IdJagError('temporarily_unavailable', `${url} could not be read: ${String(why)}`, undefined, nonce);
      Object.defineProperty(failed, 'cause', { value: err, configurable: true, writable: true });
      throw failed;
    }
    nonce = nonceOf(res) ?? nonce;
    // Only a JSON object is an answer; anything else (null, a string, an array) reads as {}.
    const json: unknown = await res.json().catch(() => ({}));
    return { res, data: (json && typeof json === 'object' && !Array.isArray(json) ? json : {}) as Record<string, unknown> };
  };
  let { res, data } = await send();
  // Asked for a nonce, with a valid one: once more with it, never in a loop. Without a key there
  // is no proof to retry. Before any retry, nonce is the first answer's.
  if (dpopKey && nonce && asksForNonce(res, data)) ({ res, data } = await send());
  if (!res.ok) throw new IdJagError(String(data.error || 'server_error'), String(data.error_description || `${url} answered ${res.status}`), res.status, nonce);
  return { data, nonce };
}

const scopeText = (scope?: string | string[]) => (Array.isArray(scope) ? scope.join(' ') : scope);

export interface RequestIdJagOptions {
  /** The identity provider's issuer (its token endpoint is discovered), or give tokenEndpoint. */
  issuer?: string;
  tokenEndpoint?: string;
  /** Your app at the identity provider (tqapp_… at Touchque SSO) and its secret. */
  clientId: string;
  clientSecret: string;
  /** The member's ID token the identity provider issued to your app. */
  idToken: string;
  /** The other service's authorization server (its issuer). */
  audience: string;
  resource?: string;
  scope?: string | string[];
  /**
   * Binds the ID-JAG to this key (DPoP, RFC 9449); redeem it with the same key. A token endpoint
   * that asks for a nonce (use_dpop_nonce with a valid DPoP-Nonce) gets the request once more with it.
   */
  dpopKey?: IdJagDpopKey;
}

/** Trades a member's ID token for an ID-JAG at the identity provider (token exchange, client_secret_basic). */
export async function requestIdJag(o: RequestIdJagOptions): Promise<{ assertion: string; expiresIn?: number; scope?: string; dpopBound?: boolean }> {
  let endpoint = o.tokenEndpoint;
  if (!endpoint) {
    if (!o.issuer) throw new TouchqueConfigError('requestIdJag needs issuer or tokenEndpoint');
    const meta = await getJson(`${o.issuer.replace(/\/+$/, '')}/.well-known/openid-configuration`);
    if (meta.issuer !== o.issuer || typeof meta.token_endpoint !== 'string') throw new TouchqueConfigError('the identity provider\'s metadata does not match its issuer');
    endpoint = meta.token_endpoint;
  }
  const { data, nonce } = await postForm(endpoint, {
    grant_type: TOKEN_EXCHANGE_GRANT, requested_token_type: ID_JAG_TOKEN_TYPE, subject_token: o.idToken, subject_token_type: ID_TOKEN_TYPE,
    audience: o.audience, resource: o.resource, scope: scopeText(o.scope),
  }, { id: o.clientId, secret: o.clientSecret }, o.dpopKey);
  if (data.issued_token_type !== ID_JAG_TOKEN_TYPE || typeof data.access_token !== 'string') throw new IdJagError('invalid_response', 'the identity provider did not answer with an ID-JAG', undefined, nonce);
  let dpopBound: boolean | undefined;
  if (o.dpopKey) {
    // An identity provider without DPoP support ignores the proof: say so instead of guessing.
    let cnf: unknown;
    try {
      cnf = (b64urlJson(data.access_token.split('.')[1] || '') as { cnf?: { jkt?: unknown } }).cnf;
    } catch {
      cnf = undefined;
    }
    dpopBound = Boolean(cnf && (cnf as { jkt?: unknown }).jkt === o.dpopKey.thumbprint);
  }
  return {
    assertion: data.access_token, ...(typeof data.expires_in === 'number' && { expiresIn: data.expires_in }), ...(typeof data.scope === 'string' && { scope: data.scope }),
    ...(dpopBound !== undefined && { dpopBound }),
  };
}

/** Trades an ID-JAG for an access token at the other service's authorization server (jwt-bearer). */
// With dpopKey (the key the ID-JAG is bound to), a DPoP proof goes along (once more with a valid nonce
// the server asks for); the access token is then DPoP-bound too: send it with idJagDpopProof(dpopKey, url, { method, accessToken }).
export async function redeemIdJag(o: { tokenEndpoint: string; clientId: string; clientSecret?: string; assertion: string; resource?: string; scope?: string | string[]; dpopKey?: IdJagDpopKey }): Promise<Record<string, unknown>> {
  const { data } = await postForm(o.tokenEndpoint, {
    grant_type: JWT_BEARER_GRANT, assertion: o.assertion, resource: o.resource, scope: scopeText(o.scope),
    ...(!o.clientSecret && { client_id: o.clientId }),
  }, o.clientSecret ? { id: o.clientId, secret: o.clientSecret } : undefined, o.dpopKey);
  return data;
}
