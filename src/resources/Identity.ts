// src/resources/Identity.ts
// Touchque Login Management API (tq.identity): your customers' accounts,
// roles, business-customer organizations, apps, APIs, connections and the
// tenant itself, from your server with your workspace key.
//
//   const { users } = await tq.identity.users.list({ q: 'ayse' });
//   await tq.identity.users.block(userId, { reason: 'chargeback' });
//   const job = await tq.identity.imports.start({ users: [{ email, passwordHash: '$2b$10$…' }] });

import { HttpClient } from '../core/HttpClient';
import { TouchqueAPIError } from '../errors';

const seg = (v: string) => encodeURIComponent(v);

export interface IdentityUser {
  id: string;
  email: string | null;
  emailVerified: boolean;
  name: string | null;
  picture: string | null;
  blocked: boolean;
  hasPassword: boolean;
  connections: string[];
  createdAt: string;
  lastLoginAt: string | null;
  loginsCount: number;
  givenName?: string | null;
  familyName?: string | null;
  phone?: string | null;
  locale?: string | null;
  userMetadata?: Record<string, unknown>;
  appMetadata?: Record<string, unknown>;
  identities?: Array<{ id: string; connection: string; strategy: string; providerUserId: string; email: string | null }>;
  mfa?: { passkeys: number; touchqueApp: boolean; email: boolean };
  roles?: Array<{ id: string; name: string; organizationId: string | null }>;
  organizations?: Array<{ id: string; name: string; displayName: string }>;
}

/** An old system's hash, described the way Auth0's custom_password_hash is. */
export interface CustomPasswordHash {
  algorithm: 'bcrypt' | 'argon2' | 'pbkdf2' | 'scrypt' | 'sha256' | 'sha512' | 'sha1' | 'md5';
  hash: { value: string; encoding?: 'hex' | 'base64' | 'base64url' | 'utf8' };
  salt?: { value: string; encoding?: 'hex' | 'base64' | 'utf8'; position?: 'prefix' | 'suffix' };
  digest?: 'sha1' | 'sha256' | 'sha512';
  iterations?: number;
  keylen?: number;
  cost?: number;
  blockSize?: number;
  parallelization?: number;
}

export interface CreateIdentityUser {
  email: string;
  emailVerified?: boolean;
  password?: string;
  /** bcrypt ($2b$…) or argon2 ($argon2id$…) as it is */
  passwordHash?: string;
  customPasswordHash?: CustomPasswordHash;
  name?: string;
  givenName?: string;
  familyName?: string;
  nickname?: string;
  picture?: string;
  phone?: string;
  locale?: string;
  userMetadata?: Record<string, unknown>;
  appMetadata?: Record<string, unknown>;
  sendVerificationEmail?: boolean;
}

export interface IdentityJob {
  id: string;
  kind: 'users_import' | 'users_export';
  status: 'running' | 'done' | 'failed';
  summary: Record<string, unknown>;
  createdAt: string;
  finishedAt: string | null;
  fileReady?: boolean;
}

/** PUT /identity/delivery/{channel}: provider, from, and that provider's fields. */
export interface DeliveryProvider {
  provider: 'smtp' | 'ses' | 'postmark' | 'sendgrid' | 'twilio' | 'netgsm';
  /** An email address; for SMS the approved sender name, or (Twilio) a phone number. */
  from: string;
  fromName?: string;
  host?: string; port?: number; secure?: boolean; user?: string; password?: string;
  region?: string; accessKeyId?: string; secretAccessKey?: string;
  serverToken?: string; messageStream?: string;
  apiKey?: string;
  accountSid?: string; authToken?: string; messagingServiceSid?: string;
  usercode?: string;
}

type Q = Record<string, string | number | boolean>;
type Body = Record<string, unknown>;

class Users {
  constructor(private http: HttpClient) {}
  list(params: { q?: string; blocked?: boolean; emailVerified?: boolean; connection?: string; organization?: string; limit?: number; cursor?: string } = {}) {
    return this.http.get<{ users: IdentityUser[]; total: number; nextCursor: string | null }>('/identity/users', params as Q);
  }
  get(id: string) { return this.http.get<IdentityUser>(`/identity/users/${seg(id)}`); }
  create(user: CreateIdentityUser) { return this.http.post<IdentityUser>('/identity/users', user as unknown as Body); }
  /** Metadata is merged; a key set to null is removed. */
  update(id: string, changes: Partial<CreateIdentityUser> & { emailVerified?: boolean }) { return this.http.patch<IdentityUser>(`/identity/users/${seg(id)}`, changes as Body); }
  /** Erasure (KVKK/GDPR): the account and every workspace row that names it. */
  delete(id: string) { return this.http.delete<{ deleted: true; removed: Record<string, number> }>(`/identity/users/${seg(id)}`); }
  block(id: string, { reason }: { reason?: string } = {}) { return this.http.post<{ blocked: true; sessions: number; refreshTokens: number }>(`/identity/users/${seg(id)}/block`, { ...(reason && { reason }) }); }
  unblock(id: string) { return this.http.post<{ blocked: false }>(`/identity/users/${seg(id)}/unblock`); }
  /** Everything about the person (KVKK/GDPR access request); never hashes. */
  export(id: string) { return this.http.get<Record<string, unknown>>(`/identity/users/${seg(id)}/export`); }
  sessions(id: string) { return this.http.get<{ sessions: Array<Record<string, unknown>> }>(`/identity/users/${seg(id)}/sessions`); }
  signOutEverywhere(id: string) { return this.http.delete<{ sessions: number; refreshTokens: number }>(`/identity/users/${seg(id)}/sessions`); }
  endSession(id: string, sessionId: string) { return this.http.delete<void>(`/identity/users/${seg(id)}/sessions/${seg(sessionId)}`); }
  /** Removes passkeys, unlinks the Touchque app, turns email codes off, signs out everywhere. */
  resetMfa(id: string) { return this.http.delete<{ passkeysRemoved: number; appsUnlinked: number }>(`/identity/users/${seg(id)}/mfa`); }
  /** Accounts at providers whose tokens the vault keeps for the user (connections with tokenVault on). */
  connectedAccounts(id: string) {
    return this.http.get<{ connectedAccounts: Array<{ id: string; connection: string | null; displayName: string | null; strategy: string | null; scopes: string[]; canRefresh: boolean; createdAt: string; lastUsedAt: string | null }> }>(`/identity/users/${seg(id)}/connected-accounts`);
  }
  /** Deletes the stored tokens: apps stop using the account for the user; signing in with it stays. */
  disconnectAccount(id: string, accountId: string) { return this.http.delete<void>(`/identity/users/${seg(id)}/connected-accounts/${seg(accountId)}`); }
  unlinkIdentity(id: string, identityId: string, { force = false } = {}) { return this.http.delete<void>(`/identity/users/${seg(id)}/identities/${seg(identityId)}${force ? '?force=true' : ''}`); }
  sendVerificationEmail(id: string, { returnTo }: { returnTo?: string } = {}) { return this.http.post<{ sent: boolean }>(`/identity/users/${seg(id)}/verification-email`, { ...(returnTo && { returnTo }) }); }
  /** sendEmail false: the link comes back for you to deliver. */
  passwordReset(id: string, { sendEmail = true, ttlSec }: { sendEmail?: boolean; ttlSec?: number } = {}) {
    return this.http.post<{ sent?: boolean; url?: string }>(`/identity/users/${seg(id)}/password-reset`, { sendEmail, ...(ttlSec && { ttlSec }) });
  }
  roles(id: string) { return this.http.get<{ roles: Array<{ id: string; name: string; organizationId: string | null }> }>(`/identity/users/${seg(id)}/roles`); }
  addRoles(id: string, roleIds: string[], { organizationId }: { organizationId?: string } = {}) { return this.http.post(`/identity/users/${seg(id)}/roles`, { roleIds, ...(organizationId && { organizationId }) }); }
  removeRole(id: string, roleId: string, { organizationId }: { organizationId?: string } = {}) {
    return this.http.delete(`/identity/users/${seg(id)}/roles/${seg(roleId)}${organizationId ? `?organizationId=${seg(organizationId)}` : ''}`);
  }
  logs(id: string, { limit }: { limit?: number } = {}) { return this.http.get<{ logs: Array<Record<string, unknown>> }>(`/identity/users/${seg(id)}/logs`, limit ? { limit } : undefined); }
}

class Jobs {
  constructor(private http: HttpClient, private kind: 'imports' | 'exports') {}
  /** imports: { users, upsert }; exports: { format: 'csv' | 'json' } */
  start(body: { users?: Array<CreateIdentityUser & { blocked?: boolean; createdAt?: string }>; upsert?: boolean; format?: 'csv' | 'json' }) {
    return this.http.post<IdentityJob>(`/identity/users-${this.kind}`, body as Body);
  }
  get(id: string) { return this.http.get<IdentityJob>(`/identity/users-${this.kind}/${seg(id)}`); }
  /** Polls until the job is done or failed. */
  async wait(id: string, { intervalMs = 1000, timeoutMs = 10 * 60 * 1000 } = {}): Promise<IdentityJob> {
    const end = Date.now() + timeoutMs;
    for (;;) {
      const job = await this.get(id);
      if (job.status !== 'running' || Date.now() > end) return job;
      await new Promise((r) => setTimeout(r, intervalMs));
    }
  }
  /** exports only: the file (CSV text or JSON lines). */
  file(id: string) { return this.http.get<string>(`/identity/users-exports/${seg(id)}/file`); }
}

class Crud<T = Record<string, unknown>> {
  constructor(protected http: HttpClient, protected base: string, private listKey: string) {}
  async list(params?: Q): Promise<T[]> { return (await this.http.get<Record<string, T[]>>(this.base, params))[this.listKey]; }
  get(id: string) { return this.http.get<T>(`${this.base}/${seg(id)}`); }
  create(body: Body) { return this.http.post<T>(this.base, body); }
  update(id: string, body: Body) { return this.http.patch<T>(`${this.base}/${seg(id)}`, body); }
  delete(id: string) { return this.http.delete<void>(`${this.base}/${seg(id)}`); }
}

class Organizations extends Crud {
  constructor(http: HttpClient) { super(http, '/identity/organizations', 'organizations'); }
  members(id: string) { return this.http.get<{ members: Array<Record<string, unknown>> }>(`${this.base}/${seg(id)}/members`); }
  addMembers(id: string, userIds: string[]) { return this.http.post<{ added: number }>(`${this.base}/${seg(id)}/members`, { userIds }); }
  removeMember(id: string, userId: string) { return this.http.delete<void>(`${this.base}/${seg(id)}/members/${seg(userId)}`); }
  setConnections(id: string, connections: Array<{ connectionId: string; assignMembershipOnLogin?: boolean }>) { return this.http.put(`${this.base}/${seg(id)}/connections`, { connections }); }
  invitations(id: string) { return this.http.get<{ invitations: Array<Record<string, unknown>> }>(`${this.base}/${seg(id)}/invitations`); }
  /** The link opens the app's sign-in route (initiateLoginUri) with organization and invitation. */
  invite(id: string, body: { email: string; clientId: string; roleIds?: string[]; inviterName?: string; sendEmail?: boolean }) {
    return this.http.post<{ id: string; url: string; emailed: boolean; expiresAt: string }>(`${this.base}/${seg(id)}/invitations`, body);
  }
  revokeInvitation(id: string, invitationId: string) { return this.http.delete<void>(`${this.base}/${seg(id)}/invitations/${seg(invitationId)}`); }
}

/** Custom domains have no read by id: `get` finds the domain in the list. */
class CustomDomains extends Crud {
  constructor(http: HttpClient) { super(http, '/identity/custom-domains', 'domains'); }
  /** The domain with this id (404 `not_found` when the workspace has none). */
  async get(id: string) {
    const domain = (await this.list()).find((d) => d.id === id);
    if (!domain) throw new TouchqueAPIError(404, { code: 'not_found', error: 'No custom domain with this id' });
    return domain;
  }
  /** Checks the DNS TXT record (a domain your organization verified needs none). */
  verify(id: string) { return this.http.post<Record<string, unknown>>(`${this.base}/${seg(id)}/verify`); }
}

class Clients extends Crud {
  constructor(http: HttpClient) { super(http, '/identity/clients', 'clients'); }
  /** The new secret is in the answer, this once. */
  rotateSecret(clientId: string) { return this.http.post<Record<string, unknown> & { clientSecret: string }>(`${this.base}/${seg(clientId)}/rotate-secret`); }
}

export class Identity {
  public readonly users: Users;
  public readonly imports: Jobs;
  public readonly exports: Jobs;
  public readonly roles: Crud;
  public readonly organizations: Organizations;
  public readonly clients: Clients;
  public readonly apis: Crud;
  public readonly connections: Crud;
  public readonly customDomains: CustomDomains;

  constructor(private http: HttpClient) {
    this.users = new Users(http);
    this.imports = new Jobs(http, 'imports');
    this.exports = new Jobs(http, 'exports');
    this.roles = new Crud(http, '/identity/roles', 'roles');
    this.organizations = new Organizations(http);
    this.clients = new Clients(http);
    this.apis = new Crud(http, '/identity/apis', 'apis');
    this.connections = new Crud(http, '/identity/connections', 'connections');
    this.customDomains = new CustomDomains(http);
  }

  /** The tenant (404 not_enabled until it is set up). */
  getTenant() { return this.http.get<Record<string, unknown>>('/identity/tenant'); }
  /** Turns Touchque Login on ({ slug, displayName }) or changes its settings. */
  updateTenant(body: Body) { return this.http.put<Record<string, unknown>>('/identity/tenant', body); }
  rotateSigningKey() { return this.http.post<{ kid: string }>('/identity/tenant/signing-keys/rotate'); }
  /**
   * The phone app the hosted pages tell customers to approve on ("Approve on the Acme app").
   * null: your brand name when the Mobile SDK is set up, else Touchque (`approverApp` in the tenant shows which).
   */
  setApproverAppName(name: string | null) { return this.http.put<Record<string, unknown>>('/identity/tenant', { branding: { approverAppName: name } }); }
  /**
   * Serve sign-in only on the primary custom domain: {slug}.login.touchque.com redirects page loads there and
   * refuses other calls. Turning it on needs a verified primary domain with a working certificate.
   */
  setCustomDomainOnly(on: boolean) { return this.http.put<Record<string, unknown>>('/identity/tenant', { customDomainOnly: on }); }
  /** Checks a verified custom domain's certificate at the sign-in edge now (`certificate`: pending | active | error). */
  checkDomainCertificate(domainId: string) { return this.http.post<Record<string, unknown>>(`/identity/custom-domains/${seg(domainId)}/check-certificate`); }
  /** The delivery log. Message text only in the local dev inbox: real providers' codes and links are not kept. */
  outbox(params: { to?: string; limit?: number } = {}) { return this.http.get<{ messages: Array<Record<string, unknown>> }>('/identity/outbox', params as Q); }
  /** Attack protection: wrong passwords, suspicious addresses, bot challenge, breached passwords, new-browser notices, the risk engine. */
  getAttackProtection() { return this.http.get<Record<string, unknown>>('/identity/attack-protection'); }
  /** Partial; the bot challenge's `secret` is write-only. */
  setAttackProtection(settings: Body) { return this.http.put<Record<string, unknown>>('/identity/attack-protection', settings); }
  /** What attack protection caught lately. */
  attackEvents(params: { limit?: number } = {}) { return this.http.get<{ events: Array<{ id: string; at: string; kind: string | null; note: string; ip: string | null; userId: string | null }> }>('/identity/attack-protection/events', params as Q); }
  /** The email and SMS providers; secrets never come back (`secretsSet`). */
  getDelivery() { return this.http.get<Record<string, unknown>>('/identity/delivery'); }
  /** Your own provider: email smtp | ses | postmark | sendgrid; sms twilio | netgsm. A secret left out keeps its stored value. */
  setDelivery(channel: 'email' | 'sms', provider: DeliveryProvider) { return this.http.put<Record<string, unknown>>(`/identity/delivery/${channel}`, provider as unknown as Body); }
  /** Back to Touchque's transport. */
  removeDelivery(channel: 'email' | 'sms') { return this.http.delete<Record<string, unknown>>(`/identity/delivery/${channel}`); }
  /** One test message through the provider in use. */
  testDelivery(channel: 'email' | 'sms', to: string) { return this.http.post<{ ok: boolean; queued: boolean; status: string | null; provider: string | null; error: string | null }>(`/identity/delivery/${channel}/test`, { to }); }
}
