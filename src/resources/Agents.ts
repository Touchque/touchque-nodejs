// src/resources/Agents.ts
// AI agents as identities of their own (tq.agents): register an agent with
// its PUBLIC key, give it an accountable owner and the action types it may ask
// approvals for, suspend, revoke or stop every agent at once. The agent itself
// never gets your API key: it signs in with its own key (TouchQueAgent).
//
//   const { privateJwk, publicJwk } = generateAgentKey();      // where the agent runs
//   const agent = await tq.agents.create({ name: 'Invoice bot', allowedTypes: ['PAY_INVOICE'], publicKey: publicJwk });
//   // give the agent agent.id and privateJwk (a secret store, never your repository)

import { HttpClient } from '../core/HttpClient';
import { TouchQueApprovalMismatchError, TouchQueConfigError } from '../errors';
import type { Mandate } from '../agent';
import {
  ApprovalExpectation, ApprovalTokenClaims, AuthorizationDetail, Jwks, assertApprovalMatches, decodeApprovalToken, verifyApprovalTokenWith,
} from '../approvalToken';

export type AgentPlatform = 'langchain' | 'llamaindex' | 'openai-agents' | 'claude-agent-sdk' | 'vercel-ai' | 'mcp' | 'custom';
export type AgentStatus = 'active' | 'suspended' | 'revoked';
/** What stops an agent right now (null: it may act). */
export type AgentBlockedReason = 'workspace_paused' | 'suspended' | 'revoked' | 'review_overdue';

/** An agent's public key: EC P-256 (ES256) or Ed25519 (EdDSA). Never a private key. */
export interface AgentPublicJwk {
  kty: 'EC' | 'OKP';
  crv: 'P-256' | 'Ed25519';
  x: string;
  y?: string;
  kid?: string;
  alg?: 'ES256' | 'EdDSA';
}

/** What the agent may ask for beyond its action types; PUT replaces it (left-out fields take the defaults). */
export interface AgentPolicy {
  /** Every request of the agent in 10 minutes (default 60). */
  requestsPer10Min?: number;
  /** Requests to one person in 10 minutes (default 5). */
  requestsPerUserPer10Min?: number;
  /** { TRY: '1000.00' }: the most one approval may move. */
  amountPerRequest?: Record<string, string>;
  /** Over 24 hours, pending and approved requests together. */
  amountPerDay?: Record<string, string>;
  /** Critical action types are never asked in the background. */
  background?: 'non_critical' | 'never';
  /** deny: a recipient this person never approved for this agent is refused. */
  newRecipients?: 'ask' | 'deny';
  /** IBANs / account numbers; any other is refused. */
  recipientAllowlist?: string[] | null;
  /** After the person, a second person approves (never the same one, never the agent's owner) when the type is listed or an amount is over `above`. */
  fourEyes?: { approvers: string[]; above?: Record<string, string>; types?: string[] } | null;
  /** { TRY: '10000.00' }: over it the person approves with a passkey on your page (the approval says `requiresPasskey`), never on the phone or with a mandate; an agent in the background is told to bring the person in (409 interactive_required). */
  requirePasskeyAbove?: Record<string, string>;
}

/** One of the workspace's agent events (AGENT_*, AGENTS_*), as `listEvents` gives it to a SIEM. */
export interface AgentEvent {
  id: string;
  type: string;
  occurredAt: string;
  agent: { id: string; name: string | null } | null;
  externalUsername: string | null;
  approvalId: string | null;
  caseCode: string | null;
  ip: string | null;
  note: string | null;
  data: Record<string, unknown>;
}

/** A page of events, oldest first; ask again with `after: next` (it stays the same while nothing new happened). */
export interface AgentEventPage {
  events: AgentEvent[];
  next: string;
  hasMore: boolean;
}

/** A person who stopped the agent asking them ("this wasn't me", "someone told me to", three rejections in 30 minutes, or Block this agent on their phone). */
export interface AgentBlock {
  externalUsername: string;
  reason: 'not_me' | 'coached' | 'rejections' | 'phone';
  approvalId: string | null;
  createdAt: string;
}

export interface Agent {
  id: string;
  name: string;
  description: string | null;
  platform: AgentPlatform;
  owner: { email: string; userId: string | null };
  status: AgentStatus;
  /** Why it is suspended or revoked; `owner_left` when its owner left the organization. */
  statusReason: string | null;
  blocked: AgentBlockedReason | null;
  allowedTypes: string[];
  /** The policy in force (defaults filled in). */
  policy: Required<AgentPolicy>;
  keys: Array<{ kid: string; kty: string; crv: string; alg: string; addedAt: string }>;
  /** After this the agent stops until renewed (`update(id, { reviewInDays })`). */
  reviewAt: string;
  lastUsedAt: string | null;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}

export interface AgentKillSwitch {
  engaged: boolean;
  since?: string;
  by?: string;
  reason?: string | null;
}

export interface CreateAgentParams {
  name: string;
  /** Active action types of the workspace this agent may ask approvals for. */
  allowedTypes: string[];
  /** The agent's public key (or `publicKeys`, up to 3). */
  publicKey?: AgentPublicJwk;
  publicKeys?: AgentPublicJwk[];
  description?: string;
  /** The accountable person (a member of the organization). Default: the API key's creator. */
  ownerEmail?: string;
  platform?: AgentPlatform;
  /** Days until the next review (1-365, default 90). */
  reviewInDays?: number;
}

export interface UpdateAgentParams {
  name?: string;
  description?: string | null;
  /** A new owner also resumes an agent suspended because its owner left. */
  ownerEmail?: string;
  platform?: AgentPlatform;
  allowedTypes?: string[];
  /** Renews the review date from now. */
  reviewInDays?: number;
}

/** Refuses a private key before it leaves this process. */
function publicOnly(jwk: AgentPublicJwk | undefined): AgentPublicJwk | undefined {
  if (jwk && typeof jwk === 'object' && 'd' in jwk) {
    throw new TouchQueConfigError('Pass the agent\'s PUBLIC key: this one has private parts (d). The private key must stay where the agent runs.');
  }
  return jwk;
}

/** An agent's approval after redeemApproval: what the person approved, now used. */
export interface RedeemedApproval {
  id: string;
  externalUsername: string;
  type: string;
  agent: { id: string; name: string | null };
  authorizationDetails: AuthorizationDetail[];
  /** The rows the phone showed. */
  details: Array<{ label: string; value: string }>;
  presence: 'interactive' | 'background';
  numberMatched: boolean;
  decidedAt: string | null;
  /** The phone's hardware signature over the rows (verifyApprovalProof checks it). */
  approvalProof: Record<string, unknown> | null;
  caseCode?: string;
}

const enc = encodeURIComponent;
const JWKS_TTL_MS = 5 * 60 * 1000;

/** A connection of the agents' token vault: your OAuth app at another service and the agents that may use it. */
export interface AgentVaultConnection {
  name: string;
  provider: 'google' | 'microsoft' | 'github' | 'facebook' | 'linkedin' | 'x' | 'oidc';
  clientId: string;
  hasClientSecret: boolean;
  options: { tenant?: string; issuer?: string };
  agentIds: string[];
  /** People whose tokens are kept (in the list). */
  connected?: number;
  createdAt: string;
  updatedAt: string;
}

/** A person's account kept in the vault (never a token). */
export interface AgentVaultAccount {
  connection: string | null;
  externalUsername: string;
  scopes: string[];
  canRefresh: boolean;
  lastUsedAt: string | null;
  lastAgentId: string | null;
  createdAt: string;
  updatedAt: string;
}

/**
 * The token vault for your agents: after your own OAuth flow with a person,
 * deposit their tokens; TouchQue keeps them sealed and refreshes them, and
 * the agents a connection names get a short-lived access token
 * (TouchQueAgent.getConnectionToken), never the refresh token.
 */
export class AgentVault {
  constructor(private readonly http: HttpClient) {}

  async listConnections(): Promise<AgentVaultConnection[]> {
    return (await this.http.get<{ connections: AgentVaultConnection[] }>('/agents/vault/connections')).connections;
  }

  /** Adds or replaces a connection; `clientSecret` is kept when left out of a replacement. */
  async putConnection(name: string, connection: { provider: AgentVaultConnection['provider']; clientId: string; clientSecret?: string; tenant?: string; issuer?: string; agentIds?: string[] }): Promise<AgentVaultConnection> {
    return (await this.http.put<{ connection: AgentVaultConnection }>(`/agents/vault/connections/${enc(name)}`, connection as unknown as Record<string, unknown>)).connection;
  }

  /** Removes it, and every person's tokens kept for it. */
  async removeConnection(name: string): Promise<{ removed: boolean; tokensDeleted: number }> {
    return this.http.delete<{ removed: boolean; tokensDeleted: number }>(`/agents/vault/connections/${enc(name)}`);
  }

  /** Keeps a person's tokens (replacing earlier ones) after your own OAuth flow with them. */
  async deposit(connection: string, user: string, tokens: { accessToken: string; refreshToken?: string; expiresIn?: number; scope?: string }): Promise<AgentVaultAccount> {
    return (await this.http.put<{ account: AgentVaultAccount }>(`/agents/vault/accounts/${enc(connection)}/${enc(user)}`, tokens as unknown as Record<string, unknown>)).account;
  }

  /** A person's accounts in the vault (never a token). */
  async listAccounts(user: string): Promise<AgentVaultAccount[]> {
    return (await this.http.get<{ accounts: AgentVaultAccount[] }>('/agents/vault/accounts', { externalUsername: user })).accounts;
  }

  /** Deletes a person's tokens: agents get nothing more for them there. */
  async removeAccount(connection: string, user: string): Promise<void> {
    await this.http.delete(`/agents/vault/accounts/${enc(connection)}/${enc(user)}`);
  }
}

export class Agents {
  private jwks: { value: Jwks; at: number } | null = null;
  private audience: string | null = null;
  /** The token vault: people's tokens at other services, for your agents. */
  readonly vault: AgentVault;

  constructor(private readonly http: HttpClient) {
    this.vault = new AgentVault(http);
  }

  /**
   * Uses an agent's approval exactly once, right before you execute: checks
   * `expect` against the token first (nothing is used on a mismatch), then
   * TouchQue checks the token and marks it used, and the answer is checked
   * again. Throws TouchQueApprovalMismatchError or a TouchQueAPIError
   * (`already_redeemed`, `token_expired`, `provisional`…).
   *
   * @example
   * const approval = await tq.agents.redeemApproval(token, {
   *   user: 'jane@example.com', type: 'PAY_INVOICE',
   *   authorizationDetails: { type: 'payment_initiation', instructedAmount: { currency: 'TRY', amount: '500.00' }, creditorAccount: { iban } },
   * });
   */
  async redeemApproval(token: string, expect: ApprovalExpectation = {}): Promise<RedeemedApproval> {
    assertApprovalMatches(decodeApprovalToken(token).claims, expect);
    const { approval } = await this.http.post<{ approval: RedeemedApproval }>('/agents/approvals/redeem', { token });
    assertApprovalMatches({ sub: approval.externalUsername, type: approval.type, authorization_details: approval.authorizationDetails }, expect);
    return approval;
  }

  /**
   * The `aud` of this workspace's approval tokens (`touchque:workspace:<id>`),
   * from GET /agents/approval-audience; asked once, then kept.
   */
  async approvalAudience(): Promise<string> {
    if (!this.audience) {
      const { audience } = await this.http.get<{ audience: string }>('/agents/approval-audience');
      if (typeof audience !== 'string' || !audience) throw new TouchQueApprovalMismatchError('Touchque did not name this workspace\'s approval audience');
      this.audience = audience;
    }
    return this.audience;
  }

  /**
   * Verifies an approval token offline (signature with TouchQue's published
   * keys, expiry, `aud`, `expect`), for a service that executes without
   * calling TouchQue. `aud` must be this workspace's: `audience` defaults to
   * approvalAudience(), and a token without aud or for another workspace is
   * refused. It does not make the token single-use: redeemApproval does.
   */
  async verifyApprovalToken(token: string, options: { audience?: string; expect?: ApprovalExpectation } = {}): Promise<ApprovalTokenClaims> {
    const checks = { ...options, audience: options.audience || await this.approvalAudience() };
    if (!this.jwks || Date.now() - this.jwks.at > JWKS_TTL_MS) {
      this.jwks = { value: await this.http.get<Jwks>('/agents/jwks.json'), at: Date.now() };
    }
    try {
      return verifyApprovalTokenWith(token, this.jwks.value, checks);
    } catch (err) {
      // A rotated key: fetch once more, then decide.
      if (!(err instanceof Error) || !/unknown key/.test(err.message)) throw err;
      this.jwks = { value: await this.http.get<Jwks>('/agents/jwks.json'), at: Date.now() };
      return verifyApprovalTokenWith(token, this.jwks.value, checks);
    }
  }

  /** Registers an agent. Needs the `agents:write` scope. */
  async create(params: CreateAgentParams): Promise<Agent> {
    const body: Record<string, unknown> = { ...params };
    if (params.publicKey) body.publicKey = publicOnly(params.publicKey);
    if (params.publicKeys) body.publicKeys = params.publicKeys.map((k) => publicOnly(k));
    return (await this.http.post<{ agent: Agent }>('/agents', body)).agent;
  }

  /** Every agent of the workspace, and its kill switch. */
  async list(options: { status?: AgentStatus } = {}): Promise<{ agents: Agent[]; killSwitch: AgentKillSwitch }> {
    return this.http.get('/agents', options.status ? { status: options.status } : undefined);
  }

  async get(agentId: string): Promise<Agent> {
    return (await this.http.get<{ agent: Agent }>(`/agents/${enc(agentId)}`)).agent;
  }

  /** Changes, hands over or renews an agent. */
  async update(agentId: string, changes: UpdateAgentParams): Promise<Agent> {
    return (await this.http.patch<{ agent: Agent }>(`/agents/${enc(agentId)}`, { ...changes })).agent;
  }

  /** Adds a key (rotation: add the new one, move the agent to it, then remove the old one). */
  async addKey(agentId: string, publicKey: AgentPublicJwk): Promise<Agent> {
    return (await this.http.post<{ agent: Agent }>(`/agents/${enc(agentId)}/keys`, { publicKey: publicOnly(publicKey) })).agent;
  }

  /** Removes a key; tokens the agent got with it stop at once. */
  async removeKey(agentId: string, kid: string): Promise<Agent> {
    return (await this.http.delete<{ agent: Agent }>(`/agents/${enc(agentId)}/keys/${enc(kid)}`)).agent;
  }

  /** Stops an agent at once (its tokens too) until resumed. */
  async suspend(agentId: string, reason?: string): Promise<Agent> {
    return (await this.http.post<{ agent: Agent }>(`/agents/${enc(agentId)}/suspend`, reason ? { reason } : {})).agent;
  }

  async resume(agentId: string): Promise<Agent> {
    return (await this.http.post<{ agent: Agent }>(`/agents/${enc(agentId)}/resume`, {})).agent;
  }

  /** Revokes an agent for good (the record stays for the audit trail). */
  async revoke(agentId: string): Promise<Agent> {
    return (await this.http.delete<{ agent: Agent }>(`/agents/${enc(agentId)}`)).agent;
  }

  /** Sets the agent's budgets, amounts, recipients and background rule (a full replacement). */
  async setPolicy(agentId: string, policy: AgentPolicy): Promise<Agent> {
    return (await this.http.put<{ agent: Agent }>(`/agents/${enc(agentId)}/policy`, { policy })).agent;
  }

  /** The workspace's policy: every agent's floor (an agent's own policy can only make it stricter). */
  async getWorkspacePolicy(): Promise<AgentPolicy> {
    return (await this.http.get<{ policy: AgentPolicy }>('/agents/workspace-policy')).policy;
  }

  /** Sets the workspace's policy (a full replacement; a field left out sets no floor). */
  async setWorkspacePolicy(policy: AgentPolicy): Promise<AgentPolicy> {
    return (await this.http.put<{ policy: AgentPolicy }>('/agents/workspace-policy', { policy })).policy;
  }

  /**
   * The workspace's agent events for a SIEM, oldest first. Keep `next` and pass it
   * as `after`; the first call reads from `since` (default the last 24 hours).
   */
  async listEvents(options: { after?: string; since?: string | Date; limit?: number } = {}): Promise<AgentEventPage> {
    const params: Record<string, string | number> = {};
    if (options.after) params.after = options.after;
    if (options.since) params.since = options.since instanceof Date ? options.since.toISOString() : options.since;
    if (options.limit !== undefined) params.limit = options.limit;
    return this.http.get<AgentEventPage>('/agents/events', Object.keys(params).length ? params : undefined);
  }

  /** The people who stopped this agent asking them; its requests to them answer 403 blocked_by_person. */
  async listBlocks(agentId: string): Promise<AgentBlock[]> {
    return (await this.http.get<{ blocks: AgentBlock[] }>(`/agents/${enc(agentId)}/blocks`)).blocks;
  }

  /** Lets the agent ask this person again (check with them first). */
  async liftBlock(agentId: string, user: string): Promise<void> {
    await this.http.delete(`/agents/${enc(agentId)}/blocks/${enc(user)}`);
  }

  /** An agent's mandates (active ones first), optionally one person's. */
  async listMandates(agentId: string, options: { user?: string } = {}): Promise<Mandate[]> {
    return (await this.http.get<{ mandates: Mandate[] }>(`/agents/${enc(agentId)}/mandates`, options.user ? { externalUsername: options.user } : undefined)).mandates;
  }

  /** Ends an agent's mandate at once. */
  async revokeMandate(agentId: string, mandateId: string): Promise<Mandate> {
    return this.http.post<Mandate>(`/agents/${enc(agentId)}/mandates/${enc(mandateId)}/revoke`, {});
  }

  /** Stops (true) or restarts (false) every agent of the workspace at once. */
  async setKillSwitch(engaged: boolean, reason?: string): Promise<AgentKillSwitch> {
    return (await this.http.put<{ killSwitch: AgentKillSwitch }>('/agents/kill-switch', { engaged, ...(reason && { reason }) })).killSwitch;
  }
}
