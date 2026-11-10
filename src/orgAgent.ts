// src/orgAgent.ts
// An organization's AI agent on TouchQue SSO (Organization → AI agents in
// the dashboard): it gets 5-minute tokens for one of the organization's apps,
// proving who it is with its own key (private_key_jwt) or with the token its
// platform already gives it (GitHub Actions, GitLab, Google Cloud, Azure,
// Kubernetes), and binds each token to a DPoP key made when it starts. The
// app checks the token with TouchQue's JWKS and the DPoP proof on every call.
//
//   const agent = new TouchQueOrgAgent({ agentId: 'oagt_…', privateKey: process.env.TQ_ORG_AGENT_KEY });
//   const res = await agent.fetch('https://payments.acme.com/invoices', { resource: 'tqapp_…' });
//
//   // In a GitHub Actions job (permissions: id-token: write), with no key to store:
//   const agent = new TouchQueOrgAgent({ agentId: 'oagt_…', assertion: githubActionsToken('touchque') });
//
// Acting for a member, when its admin allowed it (Organization → AI agents → Access):
//   const t = await agent.exchangeToken({ subjectToken: membersAccessToken, resource: 'tqapp_…' });   // RFC 8693
//   const ask = await agent.askMember({ loginHint: 'ada@acme.com', bindingMessage: 'Pay invoice 42',
//     authorizationDetails: [{ type: 'payment_initiation', instructedAmount: { currency: 'TRY', amount: '500.00' }, … }] });
//   reply(`Type ${ask.bindingCode} in the TouchQue app.`);
//   const approved = await agent.waitForMember(ask);                                                    // CIBA, poll mode
//
// The token vault: a member's own account at another service they connected on TouchQue
// (Organization → AI agents → Accounts agents may use), a fresh provider token, never the refresh token:
//   const google = await agent.getConnectionToken({ subjectToken: membersAccessToken, connection: 'google' });
//
// A shared account (a site with only a password): the member's own TouchQue extension signs in, in their
// browser, after their phone approves with the agent named; the agent never sees the password:
//   const ask = await agent.askToOpenSharedAccount({ account: 'k3J…', loginHint: 'ada@acme.com', message: 'Post the launch photo' });
//   reply(`Open ${ask.openUrl} in your browser to let me in.`);
//   const result = await agent.waitForSharedAccount(ask);   // 'opened' | 'refused' | 'declined' | 'expired'

import * as crypto from 'crypto';
import { readFileSync } from 'fs';
import axios, { AxiosInstance } from 'axios';
import { TouchQueAPIError, TouchQueConfigError, TouchQueNetworkError, TouchQueTimeoutError, apiError } from './errors';
import { AGENT_ASSERTION_TYPE, jwkThumbprint } from './agent';

type Jwk = crypto.JsonWebKey & { kid?: string; alg?: string };
const b64url = (buf: Buffer | string) => Buffer.from(buf).toString('base64url');

export interface TouchQueOrgAgentConfig {
  /** The agent's id (oagt_…). Default: TQ_ORG_AGENT_ID. */
  agentId?: string;
  /** TouchQue SSO. Default: TQ_SSO_URL or https://sso.touchque.com. */
  issuer?: string;
  /** Its own private key (JWK object or JSON, PEM or KeyObject). Default: TQ_ORG_AGENT_KEY. */
  privateKey?: Jwk | string | crypto.KeyObject;
  kid?: string;
  /** Instead of a key: the platform's token, asked for each time a token is needed (githubActionsToken, fileToken…). */
  assertion?: () => string | Promise<string>;
  /** The app (tqapp_…) to get tokens for when a call does not name one. */
  resource?: string;
  /** The scopes to ask for when a call does not name them (all the agent's scopes by default). */
  scope?: string;
  timeout?: number;
}

export interface OrgAgentToken {
  accessToken: string;
  tokenType: 'DPoP';
  expiresIn: number;
  scope: string;
}

export interface OrgAgentTokenOptions {
  resource?: string;
  scope?: string;
}

/** A token for a member: the agent acts for them (act). */
export interface OrgAgentMemberToken extends OrgAgentToken {
  /** CIBA: exactly what the member approved on the phone. */
  authorizationDetails?: Record<string, unknown>[];
}

/** A member's own access token at another service (the token vault): a Bearer token for that service's API. */
export interface OrgAgentConnectionToken {
  accessToken: string;
  tokenType: 'Bearer';
  /** Seconds; absent when the service does not say. */
  expiresIn?: number;
  scope: string;
  connection: string;
}

/** An agent's ask to open a shared account for a member (askToOpenSharedAccount). */
export interface SharedAccountAsk {
  askId: string;
  /** The page the member opens in the browser where their TouchQue extension is paired. */
  openUrl: string;
  status: SharedAccountAskStatus['status'];
  expiresIn: number;
}

export interface SharedAccountAskStatus {
  status: 'waiting_member' | 'asked_phone' | 'opened' | 'refused' | 'declined' | 'expired';
  /** Why it was refused (e.g. declined_on_phone, checked_out, call_in_progress). */
  reason?: string;
  caseCode?: string;
}

export interface AskMemberParams extends OrgAgentTokenOptions {
  /** The member's e-mail. */
  loginHint: string;
  /** Up to 64 characters, shown on the phone marked unverified. */
  bindingMessage?: string;
  /** RFC 9396 details (payment_initiation, purchase, data_access, account_change, message_send, generic): the phone shows them. */
  authorizationDetails?: Record<string, unknown>[];
  /** Seconds (30-600); the phone request lives at most as long as TouchQue lets a push live. */
  requestedExpiry?: number;
}

export interface MemberRequest {
  authReqId: string;
  expiresIn: number;
  interval: number;
  /** Show it in the conversation: the member picks it on the phone. */
  bindingCode?: string;
}

const CIBA_GRANT = 'urn:openid:params:grant-type:ciba';
const TOKEN_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';
const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
/** requested_token_type of the token vault (getConnectionToken). */
const CONNECTION_TOKEN_TYPE = 'urn:touchque:params:oauth:token-type:connection-access-token';

/** The token a GitHub Actions job may ask for (the job needs `permissions: id-token: write`). */
export function githubActionsToken(audience = 'touchque'): () => Promise<string> {
  return async () => {
    const url = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
    const bearer = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
    if (!url || !bearer) throw new TouchQueConfigError('Not in a GitHub Actions job with `permissions: id-token: write`');
    const u = new URL(url);
    u.searchParams.set('audience', audience);
    const res = await axios.get(u.toString(), { headers: { Authorization: `Bearer ${bearer}` }, timeout: 10000 });
    if (!res.data?.value) throw new TouchQueConfigError('GitHub gave no token');
    return res.data.value as string;
  };
}

/** A token the platform writes to a file and renews (a Kubernetes projected service account token, GitLab's id_tokens…). */
export function fileToken(path: string): () => string {
  return () => readFileSync(path, 'utf8').trim();
}

export class TouchQueOrgAgent {
  readonly agentId: string;
  private readonly issuer: string;
  private readonly key: crypto.KeyObject | null = null;
  private readonly keyAlg: 'ES256' | 'EdDSA' = 'ES256';
  private readonly kid?: string;
  private readonly assertionSource?: () => string | Promise<string>;
  private readonly resource?: string;
  private readonly scope?: string;
  private readonly client: AxiosInstance;
  // The DPoP key: made here, never leaves this process.
  private readonly dpopKey = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  private readonly dpopJwk: Jwk;
  private readonly tokens = new Map<string, { token: OrgAgentToken; expiresAt: number }>();

  constructor(config: TouchQueOrgAgentConfig = {}) {
    const env = typeof process !== 'undefined' ? process.env : {};
    const agentId = config.agentId ?? env.TQ_ORG_AGENT_ID ?? '';
    if (!/^oagt_[a-z2-9]{20}$/.test(agentId)) throw new TouchQueConfigError('Set TQ_ORG_AGENT_ID (or pass { agentId }): the oagt_… id from Organization → AI agents');
    this.agentId = agentId;
    this.issuer = (config.issuer ?? env.TQ_SSO_URL ?? 'https://sso.touchque.com').replace(/\/+$/, '');
    const url = new URL(this.issuer);
    const local = ['localhost', '127.0.0.1', '::1', '[::1]'].includes(url.hostname);
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) throw new TouchQueConfigError(`Refusing a plaintext issuer for "${url.hostname}": use https://`);
    if (config.assertion) {
      this.assertionSource = config.assertion;
    } else {
      const keyInput = config.privateKey ?? env.TQ_ORG_AGENT_KEY;
      if (!keyInput) throw new TouchQueConfigError('Pass { privateKey } (or set TQ_ORG_AGENT_KEY), or { assertion } with the platform\'s token');
      try {
        this.key = keyInput instanceof crypto.KeyObject ? keyInput
          : typeof keyInput === 'string' ? crypto.createPrivateKey(keyInput.trim().startsWith('{') ? { key: JSON.parse(keyInput), format: 'jwk' } : keyInput)
            : crypto.createPrivateKey({ key: keyInput, format: 'jwk' });
      } catch {
        throw new TouchQueConfigError('privateKey must be the agent\'s private key: a JWK (object or JSON), a PEM string or a KeyObject');
      }
      const type = this.key.asymmetricKeyType;
      if (type !== 'ec' && type !== 'ed25519') throw new TouchQueConfigError('The agent key must be EC P-256 or Ed25519');
      this.keyAlg = type === 'ed25519' ? 'EdDSA' : 'ES256';
      const pub = crypto.createPublicKey(this.key).export({ format: 'jwk' }) as Jwk;
      const given = typeof keyInput === 'object' && !(keyInput instanceof crypto.KeyObject) ? keyInput.kid : undefined;
      this.kid = config.kid ?? given ?? jwkThumbprint(type === 'ec' ? { kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y } : { kty: 'OKP', crv: 'Ed25519', x: pub.x });
    }
    this.resource = config.resource;
    this.scope = config.scope;
    const pub = this.dpopKey.publicKey.export({ format: 'jwk' }) as Jwk;
    this.dpopJwk = { kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y };
    this.client = axios.create({ timeout: config.timeout || 10000, maxRedirects: 0, validateStatus: () => true });
  }

  private static jws(alg: 'ES256' | 'EdDSA', key: crypto.KeyObject, header: Record<string, unknown>, payload: Record<string, unknown>): string {
    const input = `${b64url(JSON.stringify({ ...header, alg }))}.${b64url(JSON.stringify(payload))}`;
    const sig = alg === 'ES256' ? crypto.sign('sha256', Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' }) : crypto.sign(null, Buffer.from(input), key);
    return `${input}.${b64url(sig)}`;
  }

  /** A DPoP proof (RFC 9449) for one request: with the token, for a call to the app; without, for the token request. */
  dpopProof(method: string, url: string, accessToken?: string): string {
    const u = new URL(url);
    return TouchQueOrgAgent.jws('ES256', this.dpopKey.privateKey, { typ: 'dpop+jwt', jwk: this.dpopJwk }, {
      htm: method.toUpperCase(), htu: `${u.protocol}//${u.host}${u.pathname}`, iat: Math.floor(Date.now() / 1000), jti: crypto.randomUUID(),
      ...(accessToken && { ath: b64url(crypto.createHash('sha256').update(accessToken).digest()) }),
    });
  }

  private async assertion(tokenUrl: string): Promise<string> {
    if (this.assertionSource) return this.assertionSource();
    const now = Math.floor(Date.now() / 1000);
    return TouchQueOrgAgent.jws(this.keyAlg, this.key as crypto.KeyObject, { typ: 'JWT', kid: this.kid }, {
      iss: this.agentId, sub: this.agentId, aud: tokenUrl, iat: now, exp: now + 60, jti: crypto.randomUUID(),
    });
  }

  /** POST to the SSO with the agent's client assertion (and, at /sso/token, a DPoP proof). */
  private async post(path: string, fields: Record<string, string | undefined>, dpop: boolean): Promise<Record<string, any>> {
    const url = `${this.issuer}${path}`;
    const form = new URLSearchParams({ client_id: this.agentId, client_assertion_type: AGENT_ASSERTION_TYPE, client_assertion: await this.assertion(`${this.issuer}/sso/token`) });
    for (const [k, v] of Object.entries(fields)) if (v !== undefined && v !== '') form.set(k, v);
    let res;
    try {
      res = await this.client.post(url, form.toString(), { headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...(dpop && { DPoP: this.dpopProof('POST', url) }) } });
    } catch (err: any) {
      throw new TouchQueNetworkError(err?.message || String(err), err?.code);
    }
    if (res.status !== 200) {
      const data = res.data || {};
      throw apiError(res.status, { error: data.error, code: data.error, message: data.error_description ?? data.message ?? data.error, feature: data.feature });
    }
    return res.data;
  }

  private static tokenOf(data: Record<string, any>): OrgAgentMemberToken {
    return {
      accessToken: data.access_token, tokenType: 'DPoP', expiresIn: data.expires_in, scope: data.scope || '',
      ...(Array.isArray(data.authorization_details) && { authorizationDetails: data.authorization_details }),
    };
  }

  /** A token for one app (renewed 30 seconds before it expires). */
  async getToken(options: OrgAgentTokenOptions = {}): Promise<OrgAgentToken> {
    const resource = options.resource ?? this.resource;
    const scope = options.scope ?? this.scope;
    const cacheKey = `${resource || ''} ${scope || ''}`;
    const hit = this.tokens.get(cacheKey);
    if (hit && hit.expiresAt - Date.now() > 30000) return hit.token;
    const token = TouchQueOrgAgent.tokenOf(await this.post('/sso/token', { grant_type: 'client_credentials', resource, scope }, true));
    this.tokens.set(cacheKey, { token, expiresAt: Date.now() + token.expiresIn * 1000 });
    return token;
  }

  /**
   * A token for a member, with their own access token for one of the agent's
   * apps (RFC 8693 token exchange): sub is the member, act the agent.
   */
  async exchangeToken(params: OrgAgentTokenOptions & { subjectToken: string }): Promise<OrgAgentMemberToken> {
    return TouchQueOrgAgent.tokenOf(await this.post('/sso/token', {
      grant_type: TOKEN_EXCHANGE_GRANT, subject_token: params.subjectToken, subject_token_type: ACCESS_TOKEN_TYPE,
      resource: params.resource ?? this.resource, scope: params.scope ?? this.scope,
    }, true));
  }

  /**
   * The token vault: a member's own access token at another service (Google,
   * Microsoft 365, GitHub…) they connected on TouchQue, for a connection that
   * names this agent. `subjectToken` is the member's token, as for
   * exchangeToken; `scope` may only narrow what the member granted. TouchQue
   * refreshes the token; the refresh token never leaves. TouchQueAPIError
   * invalid_grant: the member has not connected it (or disconnected, or left).
   */
  async getConnectionToken(params: { subjectToken: string; connection: string; scope?: string }): Promise<OrgAgentConnectionToken> {
    const data = await this.post('/sso/token', {
      grant_type: TOKEN_EXCHANGE_GRANT, subject_token: params.subjectToken, subject_token_type: ACCESS_TOKEN_TYPE,
      requested_token_type: CONNECTION_TOKEN_TYPE, connection: params.connection, scope: params.scope,
    }, true);
    return {
      accessToken: data.access_token, tokenType: 'Bearer', scope: data.scope || '', connection: data.connection || params.connection,
      ...(typeof data.expires_in === 'number' && { expiresIn: data.expires_in }),
    };
  }

  /**
   * Asks to open a shared account (its key, from Organization → AI agents →
   * Access) for a member: they open `openUrl` in the browser where their
   * TouchQue extension is paired, their phone approves with this agent named,
   * and the extension signs in there. The agent never sees the password.
   * `message` (at most 64 characters) is shown to the member marked unverified.
   */
  async askToOpenSharedAccount(params: { account: string; loginHint: string; message?: string }): Promise<SharedAccountAsk> {
    const data = await this.post('/sso/agents/shared-accounts/asks', { account: params.account, login_hint: params.loginHint, binding_message: params.message }, false);
    return { askId: data.ask_id, openUrl: data.open_url, status: data.status, expiresIn: data.expires_in };
  }

  /** Where an ask stands; only whether it opened, never anything of the account. */
  async sharedAccountAskStatus(askId: string): Promise<SharedAccountAskStatus> {
    const data = await this.post(`/sso/agents/shared-accounts/asks/${encodeURIComponent(askId)}`, {}, false);
    return { status: data.status, ...(data.reason && { reason: data.reason }), ...(data.case_code && { caseCode: data.case_code }) };
  }

  /** Polls an ask until it ends (opened, refused, declined or expired), every `intervalMs` (3 s). */
  async waitForSharedAccount(ask: SharedAccountAsk, { intervalMs = 3000 }: { intervalMs?: number } = {}): Promise<SharedAccountAskStatus> {
    const deadline = Date.now() + (ask.expiresIn + 5) * 1000;
    for (;;) {
      const s = await this.sharedAccountAskStatus(ask.askId);
      if (!['waiting_member', 'asked_phone'].includes(s.status) || Date.now() > deadline) return s;
      await new Promise((r) => setTimeout(r, intervalMs));
    }
  }

  /** Asks a member to approve on their phone (CIBA). Show `bindingCode` in the conversation, then waitForMember(). */
  async askMember(params: AskMemberParams): Promise<MemberRequest> {
    const data = await this.post('/sso/bc-authorize', {
      login_hint: params.loginHint, binding_message: params.bindingMessage, resource: params.resource ?? this.resource, scope: params.scope ?? this.scope,
      ...(params.authorizationDetails && { authorization_details: JSON.stringify(params.authorizationDetails) }),
      ...(params.requestedExpiry && { requested_expiry: String(params.requestedExpiry) }),
    }, false);
    return { authReqId: data.auth_req_id, expiresIn: data.expires_in, interval: data.interval || 5, ...(data.binding_code && { bindingCode: data.binding_code }) };
  }

  /**
   * Waits for the member's answer (polling at the interval, slower when asked):
   * the token once they approve; TouchQueAPIError access_denied or
   * expired_token otherwise, TouchQueTimeoutError after the request expired.
   */
  async waitForMember(request: MemberRequest): Promise<OrgAgentMemberToken> {
    let interval = Math.max(1, request.interval) * 1000;
    const deadline = Date.now() + (request.expiresIn + 5) * 1000;
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, interval));
      try {
        return TouchQueOrgAgent.tokenOf(await this.post('/sso/token', { grant_type: CIBA_GRANT, auth_req_id: request.authReqId }, true));
      } catch (err) {
        if (!(err instanceof TouchQueAPIError)) throw err;
        if (err.code === 'authorization_pending') continue;
        if (err.code === 'slow_down') { interval += 5000; continue; }
        throw err;
      }
    }
    throw new TouchQueTimeoutError(request.authReqId, (request.expiresIn + 5) * 1000);
  }

  /** The two headers for one call to the app: Authorization: DPoP <token> and its proof. */
  async authorization(method: string, url: string, options: OrgAgentTokenOptions = {}): Promise<{ Authorization: string; DPoP: string }> {
    const { accessToken } = await this.getToken(options);
    return { Authorization: `DPoP ${accessToken}`, DPoP: this.dpopProof(method, url, accessToken) };
  }

  /** fetch() with the agent's token and a fresh proof. */
  async fetch(url: string, init: RequestInit & OrgAgentTokenOptions = {}): Promise<Response> {
    const { resource, scope, ...rest } = init;
    const method = (rest.method || 'GET').toUpperCase();
    const headers = new Headers(rest.headers);
    const auth = await this.authorization(method, url, { resource, scope });
    headers.set('Authorization', auth.Authorization);
    headers.set('DPoP', auth.DPoP);
    return globalThis.fetch(url, { ...rest, method, headers });
  }
}
