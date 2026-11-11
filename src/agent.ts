// src/agent.ts
// The agent side: an AI agent calls Touchque with its OWN key, never with
// your API key. TouchqueAgent signs a private_key_jwt assertion (RFC 7523)
// for a 10-minute token bound to its key with DPoP (RFC 9449), and proves the
// key on every call, so a stolen token is useless on its own.
//
//   const agent = new TouchqueAgent({ agentId: process.env.TQ_AGENT_ID, privateKey: JSON.parse(process.env.TQ_AGENT_KEY) });
//   const me = await agent.me();

import * as crypto from 'crypto';
import axios, { AxiosInstance } from 'axios';
import { TouchqueAPIError, TouchqueApprovalError, TouchqueConfigError, TouchqueNetworkError, TouchqueTimeoutError, apiError } from './errors';
import type { AuthorizationDetail } from './approvalToken';
import type { AgentPublicJwk } from './resources/Agents';

export const AGENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

type Jwk = crypto.JsonWebKey & { kid?: string; alg?: string };

const b64url = (buf: Buffer | string) => Buffer.from(buf).toString('base64url');

/** RFC 7638 thumbprint of a P-256 or Ed25519 public key (the default kid). */
export function jwkThumbprint(jwk: Jwk): string {
  const members = jwk.kty === 'EC'
    ? { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }
    : { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
  return b64url(crypto.createHash('sha256').update(JSON.stringify(members)).digest());
}

export interface AgentKeyPair {
  /** Keep secret, where the agent runs (a secret store, never a repository). */
  privateJwk: Jwk & { kid: string };
  /** Register this one with tq.agents.create({ publicKey }). */
  publicJwk: AgentPublicJwk & { kid: string; alg: 'ES256' | 'EdDSA' };
}

/** A new key pair for an agent: ES256 (P-256, default) or EdDSA (Ed25519). kid = the RFC 7638 thumbprint. */
export function generateAgentKey(alg: 'ES256' | 'EdDSA' = 'ES256'): AgentKeyPair {
  const { privateKey, publicKey } = alg === 'EdDSA'
    ? crypto.generateKeyPairSync('ed25519')
    : crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const pub = publicKey.export({ format: 'jwk' }) as Jwk;
  const kid = jwkThumbprint(pub);
  return {
    privateJwk: { ...(privateKey.export({ format: 'jwk' }) as Jwk), kid, alg },
    publicJwk: { ...(pub as AgentPublicJwk), kid, alg },
  };
}

function toKeyObject(key: Jwk | string | crypto.KeyObject): crypto.KeyObject {
  try {
    if (key instanceof crypto.KeyObject) return key;
    if (typeof key === 'string') return crypto.createPrivateKey(key.trim().startsWith('{') ? { key: JSON.parse(key), format: 'jwk' } : key);
    return crypto.createPrivateKey({ key, format: 'jwk' });
  } catch {
    throw new TouchqueConfigError('privateKey must be the agent\'s private key: a JWK (object or JSON), a PEM string or a KeyObject');
  }
}

/** The kid written in a JWK given as an object or JSON, if any. */
function kidOf(key: Jwk | string | crypto.KeyObject): string | undefined {
  if (key instanceof crypto.KeyObject) return undefined;
  if (typeof key === 'string') {
    if (!key.trim().startsWith('{')) return undefined;
    try { return JSON.parse(key).kid || undefined; } catch { return undefined; }
  }
  return typeof key.kid === 'string' ? key.kid : undefined;
}

export interface TouchqueAgentConfig {
  /** The agent's id (agt_…). Default: TQ_AGENT_ID. */
  agentId?: string;
  /** The agent's private key: JWK (object or JSON string), PEM or KeyObject. Default: TQ_AGENT_KEY. */
  privateKey?: Jwk | string | crypto.KeyObject;
  /** The kid it was registered with. Default: the key's RFC 7638 thumbprint (what Touchque uses when none was given). */
  kid?: string;
  /** Default: TQ_API_URL or https://api.touchque.com. */
  baseUrl?: string;
  /** Space-separated subset of `agent:read approvals:request approvals:read vault:read`. Default: all. */
  scope?: string;
  timeout?: number;
}

export interface AgentSelf {
  agent: { id: string; name: string; platform: string; allowedTypes: string[]; reviewAt: string; owner: { email: string } };
  workspace: { companyName: string };
  scope: string;
}

export interface AgentApprovalParams {
  /** The person the agent acts for (their phone approves). */
  user: string;
  /** One of the agent's allowed action types. */
  type: string;
  /** What exactly to approve; Touchque draws the phone's rows from it. */
  authorizationDetails: AuthorizationDetail[];
  /** The agent's own words, shown on the phone as unverified. */
  reason?: string;
  /** interactive (default): a person reads the number in your conversation. background: no number, never for critical types. */
  presence?: 'interactive' | 'background';
  /** Seconds the phone may approve it: 60-3600, default 300. */
  expiresIn?: number;
  locale?: 'tr' | 'en';
  referenceId?: string;
  /** The person's own address and browser, when your app knows them. */
  clientIp?: string;
  userAgent?: string;
  /** Approve within this active mandate: no push (see requestMandate). */
  mandateId?: string;
}

export interface MandateParams {
  user: string;
  type: string;
  /** At most this many requests (1-100). */
  maxCount: number;
  /** At most this much in total. */
  maxTotal: { currency: string; amount: string };
  /** At most this much per request, same currency. */
  perRequest?: string;
  /** IBANs / account numbers it may pay; none = any (still within the agent's policy). */
  recipients?: string[];
  /** Seconds it lasts (300-604800, default 86400). */
  validFor?: number;
  reason?: string;
  /** Seconds the phone may approve it (default 300). */
  expiresIn?: number;
  locale?: 'tr' | 'en';
}

export interface Mandate {
  mandateId: string;
  status: 'pending' | 'active' | 'rejected' | 'expired' | 'provisional' | 'revoked' | 'exhausted';
  externalUsername: string;
  type: string;
  maxCount: number;
  usedCount: number;
  maxTotal: { currency: string; amount: string };
  used: { currency: string; amount: string };
  perRequest?: { currency: string; amount: string };
  recipients: string[];
  validUntil: string;
  /** While pending: show it in the conversation. */
  challengeCode?: string;
  approvalExpiresAt?: string;
  revokedAt: string | null;
}

export type AgentApprovalStatus = 'pending' | 'awaiting_second' | 'approved' | 'rejected' | 'blocked' | 'expired' | 'provisional' | 'revoked' | 'stale' | 'redeemed';

export interface AgentApprovalState {
  approvalId: string;
  status: AgentApprovalStatus;
  presence: 'interactive' | 'background';
  /** While pending and interactive: show it in the conversation; the person types it on the phone. */
  challengeCode?: string;
  /** Over the policy's requirePasskeyAbove: the person approves with a passkey on your page (`<touchque-approval request-id="{approvalId}">`), not on the phone. */
  requiresPasskey?: boolean;
  expiresAt: string;
  caseCode?: string;
  reasons?: Array<{ code: string; text: string }>;
  reason?: string;
  /** Once approved: hand it to the service that executes (it redeems it once). */
  approvalToken?: string;
  tokenExpiresIn?: number;
  /** Four eyes: who approves second, and the number they type when their action type needs one. */
  secondApprover?: string;
  secondChallengeCode?: string;
  /** Approved within this mandate (no push). */
  mandateId?: string;
  mandate?: Mandate;
}

const ENDED = new Set(['rejected', 'blocked', 'revoked', 'expired', 'stale', 'redeemed']);

export class TouchqueAgent {
  public readonly agentId: string;
  private readonly key: crypto.KeyObject;
  private readonly alg: 'ES256' | 'EdDSA';
  private readonly kid: string;
  private readonly publicJwk: Jwk;
  private readonly baseUrl: string;
  private readonly scope?: string;
  private readonly client: AxiosInstance;
  private token: { value: string; expiresAt: number } | null = null;
  private pending: Promise<string> | null = null;

  constructor(config: TouchqueAgentConfig = {}) {
    const env = typeof process !== 'undefined' ? process.env : {};
    const agentId = config.agentId ?? env.TQ_AGENT_ID ?? '';
    if (!/^agt_[a-z2-9]{20}$/.test(agentId)) throw new TouchqueConfigError('Set TQ_AGENT_ID (or pass { agentId }): the agt_… id from tq.agents.create()');
    const keyInput = config.privateKey ?? env.TQ_AGENT_KEY;
    if (!keyInput) throw new TouchqueConfigError('Set TQ_AGENT_KEY (or pass { privateKey }): the agent\'s private key');
    this.agentId = agentId;
    this.key = toKeyObject(keyInput);
    const type = this.key.asymmetricKeyType;
    if (type !== 'ec' && type !== 'ed25519') throw new TouchqueConfigError('The agent key must be EC P-256 or Ed25519');
    if (type === 'ec' && (this.key.asymmetricKeyDetails as { namedCurve?: string })?.namedCurve !== 'prime256v1') {
      throw new TouchqueConfigError('An EC agent key must be on P-256');
    }
    this.alg = type === 'ed25519' ? 'EdDSA' : 'ES256';
    const pub = crypto.createPublicKey(this.key).export({ format: 'jwk' }) as Jwk;
    this.publicJwk = type === 'ec' ? { kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y } : { kty: 'OKP', crv: 'Ed25519', x: pub.x };
    this.kid = config.kid ?? kidOf(keyInput) ?? jwkThumbprint(this.publicJwk);
    this.baseUrl = (config.baseUrl ?? env.TQ_API_URL ?? 'https://api.touchque.com').replace(/\/+$/, '');
    const url = new URL(this.baseUrl);
    const local = ['localhost', '127.0.0.1', '::1', '[::1]'].includes(url.hostname);
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) {
      throw new TouchqueConfigError(`Refusing a plaintext baseUrl for "${url.hostname}": use https://`);
    }
    this.scope = config.scope;
    this.client = axios.create({ timeout: config.timeout || 10000, maxRedirects: 0, validateStatus: () => true });
  }

  private sign(header: Record<string, unknown>, payload: Record<string, unknown>): string {
    const input = `${b64url(JSON.stringify({ ...header, alg: this.alg }))}.${b64url(JSON.stringify(payload))}`;
    const sig = this.alg === 'ES256'
      ? crypto.sign('sha256', Buffer.from(input), { key: this.key, dsaEncoding: 'ieee-p1363' })
      : crypto.sign(null, Buffer.from(input), this.key);
    return `${input}.${b64url(sig)}`;
  }

  /** A DPoP proof (RFC 9449) for one call. */
  private dpop(method: string, url: string, accessToken?: string): string {
    return this.sign({ typ: 'dpop+jwt', jwk: this.publicJwk }, {
      htm: method,
      htu: url,
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID(),
      ...(accessToken && { ath: b64url(crypto.createHash('sha256').update(accessToken).digest()) }),
    });
  }

  private fail(status: number, data: Record<string, any>): TouchqueAPIError {
    return apiError(status, {
      error: data.error,
      code: data.code ?? data.error,
      message: data.error_description ?? data.error,
      reason: typeof data.reason === 'string' ? data.reason : undefined,
      retryAfter: typeof data.retry_after === 'number' ? data.retry_after : (typeof data.retryAfter === 'number' ? data.retryAfter : undefined),
      caseCode: typeof data.caseCode === 'string' ? data.caseCode : undefined,
      feature: typeof data.feature === 'string' ? data.feature : undefined,
    });
  }

  private async fetchToken(): Promise<string> {
    const url = `${this.baseUrl}/agents/token`;
    const now = Math.floor(Date.now() / 1000);
    const assertion = this.sign({ typ: 'JWT', kid: this.kid }, { iss: this.agentId, sub: this.agentId, aud: url, iat: now, exp: now + 60, jti: crypto.randomUUID() });
    const form = new URLSearchParams({ grant_type: 'client_credentials', client_assertion_type: AGENT_ASSERTION_TYPE, client_assertion: assertion });
    if (this.scope) form.set('scope', this.scope);
    let res;
    try {
      res = await this.client.post(url, form.toString(), { headers: { 'Content-Type': 'application/x-www-form-urlencoded', DPoP: this.dpop('POST', url) } });
    } catch (err: any) {
      throw new TouchqueNetworkError(err?.message || String(err), err?.code);
    }
    if (res.status !== 200) throw this.fail(res.status, res.data || {});
    this.token = { value: res.data.access_token, expiresAt: Date.now() + (res.data.expires_in || 600) * 1000 };
    return this.token.value;
  }

  /** The agent's current token (renewed a minute before it expires). */
  async accessToken(): Promise<string> {
    if (this.token && this.token.expiresAt - Date.now() > 60000) return this.token.value;
    if (!this.pending) this.pending = this.fetchToken().finally(() => { this.pending = null; });
    return this.pending;
  }

  /** A call with the agent's token and a fresh DPoP proof; one retry with a new token when Touchque no longer knows it. */
  protected async request<T>(method: 'GET' | 'POST', path: string, body?: Record<string, unknown>, retried = false): Promise<T> {
    const token = await this.accessToken();
    const url = `${this.baseUrl}${path}`;
    let res;
    try {
      res = await this.client.request({
        method, url, data: body === undefined ? undefined : JSON.stringify(body),
        headers: { Authorization: `DPoP ${token}`, DPoP: this.dpop(method, url.split('?')[0], token), ...(body !== undefined && { 'Content-Type': 'application/json' }) },
      });
    } catch (err: any) {
      throw new TouchqueNetworkError(err?.message || String(err), err?.code);
    }
    if (res.status === 401 && !retried && (res.data?.code === 'invalid_token')) {
      this.token = null;
      return this.request<T>(method, path, body, true);
    }
    if (res.status < 200 || res.status >= 300) throw this.fail(res.status, res.data || {});
    return res.data as T;
  }

  /** The agent as Touchque sees it: its action types, owner, review date and workspace. */
  async me(): Promise<AgentSelf> {
    return this.request<AgentSelf>('GET', '/agents/me');
  }

  /**
   * Asks the person to approve on their Touchque phone. Show `challengeCode`
   * in your conversation (interactive): the person types it on the phone.
   *
   * @example
   * const ask = await agent.requestApproval({
   *   user: 'jane@example.com', type: 'PAY_INVOICE', reason: 'October rent',
   *   authorizationDetails: [{ type: 'payment_initiation', instructedAmount: { currency: 'TRY', amount: '500.00' },
   *     creditorName: 'Jane Doe', creditorAccount: { iban: 'TR33 0006 1005 1978 6457 8413 26' } }],
   * });
   * say(`Type ${ask.challengeCode} in the Touchque app to approve.`);
   * const { approvalToken } = await agent.waitForApproval(ask.approvalId);
   */
  async requestApproval(params: AgentApprovalParams): Promise<AgentApprovalState> {
    const { user, ...rest } = params;
    return this.request<AgentApprovalState>('POST', '/agents/approvals', { externalUsername: user, ...rest });
  }

  /** Where an approval request is; `approvalToken` once approved. */
  async getApproval(approvalId: string): Promise<AgentApprovalState> {
    return this.request<AgentApprovalState>('GET', `/agents/approvals/${encodeURIComponent(approvalId)}`);
  }

  /**
   * Asks the person for a mandate: one approval on the phone for a bounded
   * series of requests (how many, how much in total and per request, to
   * whom, until when). Show `challengeCode`; once `active`, pass `mandateId`
   * to requestApproval and each request within it is approved without a push.
   */
  async requestMandate(params: MandateParams): Promise<Mandate> {
    const { user, ...rest } = params;
    return this.request<Mandate>('POST', '/agents/mandates', { externalUsername: user, ...rest });
  }

  /**
   * The token vault: a person's own access token at another service, for a
   * connection that names this agent (tq.agents.vault). Touchque refreshes it;
   * the refresh token never leaves. `scope` may only narrow what the person
   * granted. TouchqueAPIError not_connected when nothing is kept for them.
   */
  async getConnectionToken(params: { user: string; connection: string; scope?: string }): Promise<{ accessToken: string; tokenType: 'Bearer'; expiresIn?: number; scope: string; connection: string }> {
    const d = await this.request<Record<string, any>>('POST', '/agents/vault/token', { externalUsername: params.user, connection: params.connection, ...(params.scope && { scope: params.scope }) });
    return { accessToken: d.access_token, tokenType: 'Bearer', scope: d.scope || '', connection: d.connection, ...(typeof d.expires_in === 'number' && { expiresIn: d.expires_in }) };
  }

  /** A mandate's state and what is left. */
  async getMandate(mandateId: string): Promise<Mandate> {
    return this.request<Mandate>('GET', `/agents/mandates/${encodeURIComponent(mandateId)}`);
  }

  /** Gives up a mandate (when the task is done early, for example). */
  async revokeMandate(mandateId: string): Promise<Mandate> {
    return this.request<Mandate>('POST', `/agents/mandates/${encodeURIComponent(mandateId)}/revoke`, {});
  }

  /**
   * Polls until the person approves (resolves with the state holding
   * `approvalToken`). Throws TouchqueApprovalError when it ends otherwise
   * (rejected, blocked, revoked, expired, stale, redeemed) and
   * TouchqueTimeoutError after `timeoutMs`. An approval given during a phone
   * call stays `provisional` until the phone confirms it, and four eyes stay
   * `awaiting_second` until the second person answers, so it keeps waiting.
   */
  async waitForApproval(approvalId: string, options: { timeoutMs?: number; intervalMs?: number } = {}): Promise<AgentApprovalState> {
    const timeoutMs = options.timeoutMs ?? 10 * 60 * 1000;
    const intervalMs = Math.max(500, options.intervalMs ?? 2000);
    const end = Date.now() + timeoutMs;
    for (;;) {
      const state = await this.getApproval(approvalId);
      if (state.status === 'approved' && state.approvalToken) return state;
      if (ENDED.has(state.status)) throw new TouchqueApprovalError(approvalId, state.status, state.reason);
      if (Date.now() + intervalMs > end) throw new TouchqueTimeoutError(approvalId, timeoutMs);
      await new Promise((r) => setTimeout(r, intervalMs));
    }
  }
}
