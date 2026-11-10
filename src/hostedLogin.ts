// src/hostedLogin.ts
// TouchQue Login (hosted sign-in) for your app: an OpenID Connect client for
// your tenant (acme.login.touchque.com or your own domain).
//
//   const login = new HostedLogin({ domain: 'acme.login.touchque.com', clientId, clientSecret, redirectUri });
//   const { url, state, nonce, codeVerifier } = login.authorizationUrl();   // keep the three, redirect to url
//   const session = await login.handleCallback(req.url, { state, nonce, codeVerifier });
//   session.claims.sub, session.accessToken, session.refreshToken
//
// PKCE (S256) is always used. ID tokens are checked against the tenant's
// JWKS (signature, issuer, audience, expiry, nonce, at_hash). Your API checks
// access tokens with verifyAccessToken(token, { audience }).
//
// An app acting for a user (an AI agent; a confidential app whose grantTypes
// list the grant, and an API that grants it scopes):
//   const forAda = await login.exchangeToken(adasAccessToken, { audience: 'https://api.acme.com' });   // RFC 8693
//   const ask = await login.askUser({ loginHint: 'ada@acme.com', scope: 'openid payments:create', audience, bindingMessage: 'Pay invoice 42' });
//   reply(`Type ${ask.bindingCode} in the TouchQue app`);
//   const approved = await login.waitForUser(ask);                                                      // CIBA, poll mode

import { createHash, createPublicKey, randomBytes, timingSafeEqual, verify as verifySig, KeyObject } from 'crypto';
import { TouchQueError } from './errors';
import { MyAccount, issuerOf } from './myAccount';

export class HostedLoginError extends TouchQueError {
  public readonly code: string;
  public readonly description: string | undefined;
  public readonly status: number | undefined;
  constructor(code: string, description?: string, status?: number) {
    super(description ? `${code}: ${description}` : code);
    this.name = 'HostedLoginError';
    this.code = code;
    this.description = description;
    this.status = status;
  }
}

export interface HostedLoginConfig {
  /** Your tenant's sign-in domain (acme.login.touchque.com) or full issuer URL (https://; http:// only on localhost). */
  domain: string;
  clientId: string;
  /** Apps with a server: the client secret. SPAs and native apps leave it out. */
  clientSecret?: string;
  /** Where TouchQue sends users back; must be registered on the app. */
  redirectUri?: string;
  /** Default 'openid profile email'. Add 'offline_access' for a refresh token. */
  scope?: string;
  /** Your API's identifier, to get an access token for it. */
  audience?: string;
  /** Seconds of clock difference allowed when checking tokens. Default 60. */
  clockToleranceSec?: number;
  /** For tests or proxies. Defaults to the global fetch. */
  fetch?: typeof fetch;
}

export interface AuthorizationUrlOptions {
  state?: string;
  nonce?: string;
  codeVerifier?: string;
  redirectUri?: string;
  scope?: string;
  audience?: string;
  /** 'login' (always show the page), 'none' (silent), 'consent', 'create' (sign-up page). */
  prompt?: 'none' | 'login' | 'consent' | 'select_account' | 'create';
  /** Pre-fills the email. */
  loginHint?: string;
  /** 'signup' opens the sign-up page. */
  screenHint?: 'signup' | 'login';
  /** 'tr', 'en'… */
  uiLocales?: string;
  /** Seconds since the last real sign-in; older sessions sign in again. */
  maxAge?: number;
  /** Go straight to a connection (google, apple, an enterprise one…). */
  connection?: string;
  organization?: string;
  invitation?: string;
  /** e.g. 'http://schemas.openid.net/pape/policies/2007/06/multi-factor' or 'phr' (passkey). */
  acrValues?: string;
  responseMode?: 'query' | 'form_post';
  extraParams?: Record<string, string>;
}

export interface AuthorizationRequest {
  url: string;
  state: string;
  nonce: string;
  codeVerifier: string;
}

export interface CallbackChecks {
  state: string;
  nonce: string;
  codeVerifier: string;
  redirectUri?: string;
  /** Reject sign-ins older than this many seconds (with authorizationUrl's maxAge). */
  maxAge?: number;
}

export interface IdTokenClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  auth_time?: number;
  nonce?: string;
  amr?: string[];
  acr?: string;
  sid?: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  locale?: string;
  org_id?: string;
  org_name?: string;
  [claim: string]: unknown;
}

/** requested_token_type for the token vault (getConnectionToken). */
export const CONNECTION_TOKEN_TYPE = 'urn:touchque:params:oauth:token-type:connection-access-token';

export interface TokenSet {
  accessToken: string;
  tokenType: string;
  /** Unix seconds. */
  expiresAt: number;
  scope: string;
  idToken?: string;
  refreshToken?: string;
  /** The verified ID token's claims (when an ID token came back). */
  claims?: IdTokenClaims;
  /** What the user approved on the phone (CIBA with authorization_details). */
  authorizationDetails?: unknown[];
  /** Token exchange: always the access token type. */
  issuedTokenType?: string;
  /** getConnectionToken: the connection the provider token is for. */
  connection?: string;
}

export interface AskUserParams {
  /** The user's e-mail or id (usr_…). */
  loginHint: string;
  /** Scopes for the tokens (openid for an ID token too). */
  scope: string;
  /** Your API's identifier, for an access token to call it. */
  audience?: string;
  /** A short text (at most 64 characters) shown on the phone, marked as the app's own. */
  bindingMessage?: string;
  /** RFC 9396 details TouchQue draws on the phone (payment_initiation, …). */
  authorizationDetails?: unknown[];
  /** Seconds the user has to answer: 30 to 300 (default 300). */
  requestedExpiry?: number;
}

export interface UserApprovalRequest {
  authReqId: string;
  /** Unix seconds. */
  expiresAt: number;
  /** Seconds between polls. */
  interval: number;
  /** The number the user picks on the phone: show it in your conversation. */
  bindingCode?: string;
}

export interface AccessTokenClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  client_id: string;
  scope?: string;
  permissions?: string[];
  org_id?: string;
  [claim: string]: unknown;
}

interface Jwk { kty: string; kid?: string; n?: string; e?: string; alg?: string; use?: string }

const b64url = (buf: Buffer) => buf.toString('base64url');
const random = (bytes = 32) => b64url(randomBytes(bytes));

function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

function decodeJwt(token: string): { header: Record<string, unknown>; payload: Record<string, unknown>; input: string; signature: Buffer } {
  const parts = String(token).split('.');
  if (parts.length !== 3) throw new HostedLoginError('invalid_token', 'not a JWT');
  try {
    return {
      header: JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')),
      payload: JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')),
      input: `${parts[0]}.${parts[1]}`,
      signature: Buffer.from(parts[2], 'base64url'),
    };
  } catch {
    throw new HostedLoginError('invalid_token', 'malformed JWT');
  }
}

export class HostedLogin {
  public readonly issuer: string;
  public readonly clientId: string;
  public readonly redirectUri: string | undefined;
  private readonly config: HostedLoginConfig;
  private readonly http: typeof fetch;
  private keys: Map<string, KeyObject> = new Map();
  private keysAt = 0;

  constructor(config: HostedLoginConfig) {
    if (!config?.domain) throw new HostedLoginError('config', 'domain is required');
    if (!config.clientId) throw new HostedLoginError('config', 'clientId is required');
    const issuer = issuerOf(config.domain);
    if (!issuer) throw new HostedLoginError('config', 'domain must be https:// (http:// only on localhost): codes, tokens and the client secret would travel in the clear');
    this.issuer = issuer;
    this.config = config;
    this.clientId = config.clientId;
    this.redirectUri = config.redirectUri;
    const f = config.fetch || (typeof fetch !== 'undefined' ? fetch : undefined);
    if (!f) throw new HostedLoginError('config', 'No fetch available: pass config.fetch');
    this.http = f;
  }

  private get tolerance(): number {
    return this.config.clockToleranceSec ?? 60;
  }

  /** The URL to send the browser to, and the values to keep until the callback. */
  authorizationUrl(opts: AuthorizationUrlOptions = {}): AuthorizationRequest {
    const redirectUri = opts.redirectUri || this.config.redirectUri;
    if (!redirectUri) throw new HostedLoginError('config', 'redirectUri is required');
    const state = opts.state || random();
    const nonce = opts.nonce || random();
    const codeVerifier = opts.codeVerifier || random(48);
    const challenge = b64url(createHash('sha256').update(codeVerifier).digest());
    const p = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: redirectUri,
      scope: opts.scope || this.config.scope || 'openid profile email',
      state,
      nonce,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });
    const audience = opts.audience ?? this.config.audience;
    const optional: Record<string, string | number | undefined> = {
      audience, prompt: opts.prompt, login_hint: opts.loginHint, screen_hint: opts.screenHint, ui_locales: opts.uiLocales,
      max_age: opts.maxAge, connection: opts.connection, organization: opts.organization, invitation: opts.invitation,
      acr_values: opts.acrValues, response_mode: opts.responseMode,
    };
    for (const [k, v] of Object.entries(optional)) if (v !== undefined && v !== null && v !== '') p.set(k, String(v));
    for (const [k, v] of Object.entries(opts.extraParams || {})) p.set(k, v);
    return { url: `${this.issuer}/authorize?${p}`, state, nonce, codeVerifier };
  }

  /**
   * Finishes the sign-in: checks state (and iss), exchanges the code with the
   * PKCE verifier, verifies the ID token. `input` is the callback URL (or its
   * query/form fields).
   */
  async handleCallback(input: string | URL | URLSearchParams | Record<string, string | undefined>, checks: CallbackChecks): Promise<TokenSet> {
    const params = this.callbackParams(input);
    const get = (k: string) => params.get(k) || undefined;
    const state = get('state');
    if (!state || !checks.state || !safeEqual(state, checks.state)) throw new HostedLoginError('state_mismatch', 'The state does not match this sign-in');
    // RFC 9207: a response that carries iss (even an empty one) must name this issuer,
    // the one the ID token is checked against. Servers that do not send iss yet are accepted.
    if (params.has('iss') && params.get('iss') !== this.issuer) {
      const iss = params.get('iss');
      throw new HostedLoginError('issuer_mismatch', iss ? `The response came from ${iss}` : 'The response has an empty iss');
    }
    if (get('error')) throw new HostedLoginError(get('error') as string, get('error_description'));
    const code = get('code');
    if (!code) throw new HostedLoginError('invalid_request', 'The callback has no code');
    const redirectUri = checks.redirectUri || this.config.redirectUri;
    if (!redirectUri) throw new HostedLoginError('config', 'redirectUri is required');
    const tokens = await this.tokenRequest({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, code_verifier: checks.codeVerifier });
    if (!tokens.idToken) throw new HostedLoginError('invalid_token', 'No ID token: ask for the openid scope');
    tokens.claims = await this.verifyIdToken(tokens.idToken, { nonce: checks.nonce, accessToken: tokens.accessToken, maxAge: checks.maxAge });
    return tokens;
  }

  /** A new access token (and a rotated refresh token). Keep the new refresh token. */
  async refresh(refreshToken: string, { scope }: { scope?: string } = {}): Promise<TokenSet> {
    const tokens = await this.tokenRequest({ grant_type: 'refresh_token', refresh_token: refreshToken, ...(scope && { scope }) });
    if (tokens.idToken) tokens.claims = await this.verifyIdToken(tokens.idToken, { accessToken: tokens.accessToken });
    return tokens;
  }

  /**
   * A token for the My Account API (audience https://<domain>/me/) from the
   * refresh token a first-party app holds. The refresh token rotates: keep
   * the returned refreshToken. Scopes: read:me, update:me, manage:me:security, delete:me.
   */
  async myAccountToken(refreshToken: string, scope = 'read:me update:me'): Promise<TokenSet> {
    return this.tokenRequest({ grant_type: 'refresh_token', refresh_token: refreshToken, audience: `${this.issuer}/me/`, scope });
  }

  /** The My Account API for the person holding `accessToken` (from myAccountToken or a sign-in for that audience). */
  myAccount(accessToken: string): MyAccount {
    return new MyAccount({ domain: this.issuer, accessToken, fetch: this.http });
  }

  /** The hosted account page (profile, security, devices, privacy). */
  accountUrl(section?: 'security' | 'devices' | 'privacy'): string {
    return `${this.issuer}/account${section ? `/${section}` : ''}`;
  }

  /** Machine-to-machine: an access token for your API, with the app's own credentials. */
  async clientCredentials({ audience, scope }: { audience: string; scope?: string }): Promise<TokenSet> {
    return this.tokenRequest({ grant_type: 'client_credentials', audience, ...(scope && { scope }) });
  }

  /**
   * RFC 8693: a signed-in user's access token, traded for one to call
   * `audience` on their behalf (sub = the user, act.sub = this app). For a
   * confidential app the API grants scopes to; never longer than the user's token.
   */
  async exchangeToken(subjectToken: string, { audience, scope }: { audience: string; scope?: string }): Promise<TokenSet> {
    return this.tokenRequest({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange', subject_token: subjectToken,
      subject_token_type: 'urn:ietf:params:oauth:token-type:access_token', audience, ...(scope && { scope }),
    });
  }

  /**
   * Token vault: the provider's own access token (Google, Microsoft, GitHub…)
   * for the signed-in user, from a connection that stores tokens. TouchQue
   * refreshes it; the refresh token never leaves. `userAccessToken` is the
   * user's token for this app (or for an app the connection lists).
   * HostedLoginError invalid_grant: the user has not signed in with the
   * connection since it started storing tokens, or they stopped app access.
   */
  async getConnectionToken(userAccessToken: string, { connection, scope }: { connection: string; scope?: string }): Promise<TokenSet> {
    return this.tokenRequest({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange', subject_token: userAccessToken,
      subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      requested_token_type: CONNECTION_TOKEN_TYPE, connection, ...(scope && { scope }),
    });
  }

  /** CIBA: asks the user to approve on their phone. Show `bindingCode`, then `waitForUser`. */
  async askUser(p: AskUserParams): Promise<UserApprovalRequest> {
    const res = await this.post('/bc-authorize', {
      login_hint: p.loginHint, scope: p.scope,
      ...(p.audience && { audience: p.audience }),
      ...(p.bindingMessage && { binding_message: p.bindingMessage }),
      ...(p.authorizationDetails && { authorization_details: JSON.stringify(p.authorizationDetails) }),
      ...(p.requestedExpiry && { requested_expiry: String(p.requestedExpiry) }),
    });
    if (!res.ok) throw await this.error(res);
    const d = (await res.json()) as Record<string, unknown>;
    return {
      authReqId: String(d.auth_req_id),
      expiresAt: Math.floor(Date.now() / 1000) + Number(d.expires_in || 0),
      interval: Number(d.interval ?? 5),
      ...(typeof d.binding_code === 'string' && { bindingCode: d.binding_code }),
    };
  }

  /** Polls until the user answers: the tokens, or HostedLoginError access_denied / expired_token. */
  async waitForUser(r: UserApprovalRequest, { signal }: { signal?: AbortSignal } = {}): Promise<TokenSet> {
    let interval = r.interval;
    for (;;) {
      if (signal?.aborted) throw new HostedLoginError('aborted', 'Stopped waiting');
      if (Math.floor(Date.now() / 1000) > r.expiresAt) throw new HostedLoginError('expired_token', 'The user did not answer in time');
      await new Promise((done) => { setTimeout(done, interval * 1000); });
      try {
        return await this.tokenRequest({ grant_type: 'urn:openid:params:grant-type:ciba', auth_req_id: r.authReqId });
      } catch (err) {
        if (!(err instanceof HostedLoginError)) throw err;
        if (err.code === 'slow_down') interval += 5;
        else if (err.code !== 'authorization_pending') throw err;
      }
    }
  }

  /** Ends a refresh token (and its rotated family). */
  async revoke(token: string): Promise<void> {
    const res = await this.post('/oauth/revoke', { token });
    if (!res.ok) throw await this.error(res);
  }

  async userinfo(accessToken: string): Promise<Record<string, unknown>> {
    const res = await this.http(`${this.issuer}/userinfo`, { headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' } });
    if (!res.ok) throw await this.error(res);
    return res.json() as Promise<Record<string, unknown>>;
  }

  /** Where to send the browser to sign out of the hosted pages too. */
  logoutUrl({ idTokenHint, postLogoutRedirectUri, state }: { idTokenHint?: string; postLogoutRedirectUri?: string; state?: string } = {}): string {
    const p = new URLSearchParams({ client_id: this.config.clientId });
    if (idTokenHint) p.set('id_token_hint', idTokenHint);
    if (postLogoutRedirectUri) p.set('post_logout_redirect_uri', postLogoutRedirectUri);
    if (state) p.set('state', state);
    return `${this.issuer}/oidc/logout?${p}`;
  }

  /**
   * For your API: checks an access token TouchQue issued (signature, issuer,
   * audience, expiry, typ at+jwt) and, optionally, that it carries scopes.
   */
  async verifyAccessToken(token: string, { audience, requiredScopes = [] }: { audience: string; requiredScopes?: string[] }): Promise<AccessTokenClaims> {
    const payload = (await this.verifyJwt(token, { typ: 'at+jwt' })) as AccessTokenClaims;
    const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!auds.includes(audience)) throw new HostedLoginError('invalid_token', 'The token is for another audience');
    const scopes = String(payload.scope || '').split(' ');
    const missing = requiredScopes.filter((s) => !scopes.includes(s));
    if (missing.length) throw new HostedLoginError('insufficient_scope', `Missing scope: ${missing.join(' ')}`, 403);
    return payload;
  }

  /** Verifies an ID token from this tenant for this app. */
  async verifyIdToken(idToken: string, { nonce, accessToken, maxAge }: { nonce?: string; accessToken?: string; maxAge?: number } = {}): Promise<IdTokenClaims> {
    const payload = (await this.verifyJwt(idToken, {})) as IdTokenClaims;
    const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!auds.includes(this.config.clientId)) throw new HostedLoginError('invalid_token', 'The ID token is for another app');
    if (auds.length > 1 && payload.azp !== this.config.clientId) throw new HostedLoginError('invalid_token', 'azp does not name this app');
    if (nonce !== undefined && (typeof payload.nonce !== 'string' || !safeEqual(payload.nonce, nonce))) throw new HostedLoginError('nonce_mismatch', 'The nonce does not match this sign-in');
    if (accessToken && typeof payload.at_hash === 'string') {
      const expected = b64url(createHash('sha256').update(accessToken).digest().subarray(0, 16));
      if (!safeEqual(payload.at_hash, expected)) throw new HostedLoginError('invalid_token', 'at_hash does not match the access token');
    }
    if (maxAge !== undefined && typeof payload.auth_time === 'number' && Date.now() / 1000 - payload.auth_time > maxAge + this.tolerance) {
      throw new HostedLoginError('login_required', 'The sign-in is older than maxAge');
    }
    return payload;
  }

  // ── internals ────────────────────────────────────────────────────────────

  private callbackParams(input: string | URL | URLSearchParams | Record<string, string | undefined>): URLSearchParams {
    if (input instanceof URLSearchParams) return input;
    if (input instanceof URL) return input.searchParams;
    if (typeof input === 'string') {
      const q = input.includes('?') ? input.slice(input.indexOf('?') + 1) : input;
      return new URLSearchParams(q.split('#')[0]);
    }
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(input || {})) if (typeof v === 'string') p.set(k, v);
    return p;
  }

  private post(path: string, fields: Record<string, string>): Promise<Response> {
    const body = new URLSearchParams(fields);
    const headers: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' };
    if (this.config.clientSecret) {
      const enc = (s: string) => encodeURIComponent(s).replace(/%20/g, '+');
      headers.Authorization = `Basic ${Buffer.from(`${enc(this.config.clientId)}:${enc(this.config.clientSecret)}`).toString('base64')}`;
    } else {
      body.set('client_id', this.config.clientId);
    }
    return this.http(`${this.issuer}${path}`, { method: 'POST', headers, body: body.toString() });
  }

  private async error(res: Response): Promise<HostedLoginError> {
    let data: Record<string, string> = {};
    try { data = (await res.json()) as Record<string, string>; } catch { /* not JSON */ }
    return new HostedLoginError(data.error || `http_${res.status}`, data.error_description, res.status);
  }

  private async tokenRequest(fields: Record<string, string>): Promise<TokenSet> {
    const res = await this.post('/oauth/token', fields);
    if (!res.ok) throw await this.error(res);
    const d = (await res.json()) as Record<string, unknown>;
    return {
      accessToken: String(d.access_token),
      tokenType: String(d.token_type || 'Bearer'),
      expiresAt: Math.floor(Date.now() / 1000) + Number(d.expires_in || 0),
      scope: String(d.scope || ''),
      ...(typeof d.id_token === 'string' && { idToken: d.id_token }),
      ...(typeof d.refresh_token === 'string' && { refreshToken: d.refresh_token }),
      ...(Array.isArray(d.authorization_details) && { authorizationDetails: d.authorization_details }),
      ...(typeof d.issued_token_type === 'string' && { issuedTokenType: d.issued_token_type }),
      ...(typeof d.connection === 'string' && { connection: d.connection }),
    };
  }

  private async loadKeys(force = false): Promise<void> {
    // At most one refetch every 30 s, even for tokens with unknown keys.
    if (!force && this.keys.size && Date.now() - this.keysAt < 3600_000) return;
    if (force && Date.now() - this.keysAt < 30_000) return;
    const res = await this.http(`${this.issuer}/.well-known/jwks.json`, { headers: { Accept: 'application/json' } });
    if (!res.ok) throw new HostedLoginError('jwks_unavailable', `JWKS answered ${res.status}`);
    const { keys } = (await res.json()) as { keys: Jwk[] };
    const next = new Map<string, KeyObject>();
    for (const k of keys || []) {
      if (k.kty === 'RSA' && k.kid && k.n && k.e && (!k.use || k.use === 'sig')) {
        next.set(k.kid, createPublicKey({ key: { kty: 'RSA', n: k.n, e: k.e }, format: 'jwk' }));
      }
    }
    this.keys = next;
    this.keysAt = Date.now();
  }

  private async verifyJwt(token: string, { typ }: { typ?: string }): Promise<Record<string, unknown>> {
    const { header, payload, input, signature } = decodeJwt(token);
    if (header.alg !== 'RS256') throw new HostedLoginError('invalid_token', `Unexpected alg ${String(header.alg)}`);
    if (typ && String(header.typ || '').toLowerCase() !== typ) throw new HostedLoginError('invalid_token', 'Wrong token type');
    const kid = String(header.kid || '');
    await this.loadKeys();
    if (!this.keys.has(kid)) await this.loadKeys(true);
    const key = this.keys.get(kid);
    if (!key) throw new HostedLoginError('invalid_token', 'Unknown signing key');
    if (!verifySig('sha256', Buffer.from(input), key, signature)) throw new HostedLoginError('invalid_token', 'Bad signature');
    const now = Math.floor(Date.now() / 1000);
    if (payload.iss !== this.issuer) throw new HostedLoginError('invalid_token', 'Wrong issuer');
    if (typeof payload.exp !== 'number' || now > payload.exp + this.tolerance) throw new HostedLoginError('invalid_token', 'The token expired');
    if (typeof payload.iat === 'number' && payload.iat > now + this.tolerance) throw new HostedLoginError('invalid_token', 'The token is from the future');
    return payload;
  }
}
