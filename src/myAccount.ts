// src/myAccount.ts
// The TouchQue Login My Account API (/me/v1) from your server: the signed-in
// customer's own profile, sign-in methods, devices, apps and data, called
// with their access token for audience https://<domain>/me/.
//
//   const me = await login.myAccountToken(session.refreshToken, 'read:me update:me');  // keep me.refreshToken
//   const account = login.myAccount(me.accessToken);
//   const { profile } = await account.get();
//
// Security changes, the data export and deletion need a recent sign-in; when
// it is too old the call throws MyAccountError with stepUp true: send the
// person through authorizationUrl({ maxAge: 0 }) again.

import { TouchQueError } from './errors';

export class MyAccountError extends TouchQueError {
  public readonly code: string;
  public readonly status: number;
  /** True when the sign-in is too old for this change (RFC 9470). */
  public readonly stepUp: boolean;
  public readonly maxAge: number | undefined;
  constructor(code: string, status: number, description?: string, maxAge?: number) {
    super(description ? `${code}: ${description}` : code);
    this.name = 'MyAccountError';
    this.code = code;
    this.status = status;
    this.stepUp = code === 'insufficient_user_authentication';
    this.maxAge = maxAge;
  }
}

export interface MyAccountConfig {
  /** acme.login.touchque.com, your custom domain, or a full issuer URL. */
  domain: string;
  /** The person's access token for audience https://<domain>/me/. */
  accessToken: string;
  fetch?: typeof fetch;
}

export interface MyAccountProfile {
  id: string;
  email: string | null;
  emailVerified: boolean;
  name: string | null;
  givenName: string | null;
  familyName: string | null;
  nickname: string | null;
  picture: string | null;
  locale: string | null;
  phone: string | null;
  phoneVerified: boolean;
  userMetadata: Record<string, unknown>;
  createdAt: string;
}

export interface MyAccountMethods {
  password: { set: boolean; updatedAt: string | null };
  passkeys: Array<{ id: string; label: string | null; synced: boolean; host: string; usableHere: boolean; createdAt: string; lastUsedAt: string | null }>;
  passkeysOffered: boolean;
  touchqueApp: { offered: boolean; linked: boolean; since: string | null };
  emailCodes: { offered: boolean; enabled: boolean; available: boolean };
  smsCodes: { offered: boolean; enabled: boolean; phone: string | null };
  /** appAccess: apps may use this account for the person (token vault); stopAppAccess(appAccess.id) ends that. */
  identities: Array<{ id: string; connection: string; provider: string; strategy: string; email: string | null; linkedAt: string; lastLoginAt: string | null; appAccess: { id: string; lastUsedAt: string | null } | null }>;
}

export type MyAccountProfileChanges = Partial<Pick<MyAccountProfile, 'name' | 'givenName' | 'familyName' | 'nickname' | 'locale'>> & {
  /** Merged into the stored object; a key set to null is removed. */
  userMetadata?: Record<string, unknown>;
};

const seg = (v: string) => encodeURIComponent(v);

/**
 * The issuer for a sign-in domain (`acme.login.touchque.com`) or a full URL, or null for a
 * plaintext http:// one off this machine: like the API baseUrl, http:// only on localhost,
 * 127.0.0.1, ::1 and *.localhost. Codes, tokens and client secrets must not travel in the clear.
 */
export function issuerOf(domain: string): string | null {
  const raw = domain.replace(/\/+$/, '');
  const issuer = /^https?:\/\//.test(raw) ? raw : `https://${raw}`;
  if (!issuer.startsWith('http://')) return issuer;
  let host: string;
  try {
    host = new URL(issuer).hostname.toLowerCase();
  } catch {
    return null;
  }
  return ['localhost', '127.0.0.1', '::1', '[::1]'].includes(host) || host.endsWith('.localhost') ? issuer : null;
}

export class MyAccount {
  public readonly issuer: string;
  private readonly token: string;
  private readonly http: typeof fetch;

  constructor(config: MyAccountConfig) {
    if (!config?.domain || !config.accessToken) throw new MyAccountError('config', 0, 'domain and accessToken are required');
    const issuer = issuerOf(config.domain);
    if (!issuer) throw new MyAccountError('config', 0, 'domain must be https:// (http:// only on localhost): the access token would travel in the clear');
    this.issuer = issuer;
    this.token = config.accessToken;
    const f = config.fetch || (typeof fetch !== 'undefined' ? fetch : undefined);
    if (!f) throw new MyAccountError('config', 0, 'No fetch available: pass config.fetch');
    this.http = f;
  }

  /** The hosted account page, optionally at a section. */
  accountPageUrl(section?: 'security' | 'devices' | 'privacy'): string {
    return `${this.issuer}/account${section ? `/${section}` : ''}`;
  }

  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await this.http(`${this.issuer}/me/v1${path}`, {
      method,
      headers: { Authorization: `Bearer ${this.token}`, Accept: 'application/json', ...(body !== undefined && { 'Content-Type': 'application/json' }) },
      ...(body !== undefined && { body: JSON.stringify(body) }),
    });
    if (res.status === 204) return undefined as T;
    let data: Record<string, unknown> = {};
    try { data = (await res.json()) as Record<string, unknown>; } catch { /* not JSON */ }
    if (!res.ok) {
      const maxAge = /max_age="?(\d+)"?/.exec(res.headers.get('www-authenticate') || '')?.[1];
      throw new MyAccountError(String(data.error || `http_${res.status}`), res.status, data.error_description ? String(data.error_description) : undefined, maxAge ? Number(maxAge) : undefined);
    }
    return data as T;
  }

  get() { return this.call<{ profile: MyAccountProfile; authenticationMethods: MyAccountMethods; accountPageUrl: string }>('GET', ''); }
  getProfile() { return this.call<MyAccountProfile>('GET', '/profile'); }
  updateProfile(changes: MyAccountProfileChanges) { return this.call<MyAccountProfile>('PATCH', '/profile', changes); }

  authenticationMethods() { return this.call<MyAccountMethods & { addPasskeyUrl: string }>('GET', '/authentication-methods'); }
  renamePasskey(id: string, label: string) { return this.call<void>('PATCH', `/authentication-methods/passkeys/${seg(id)}`, { label }); }
  /** Needs a recent sign-in. */
  removePasskey(id: string) { return this.call<void>('DELETE', `/authentication-methods/passkeys/${seg(id)}`); }
  /** Needs a recent sign-in. */
  unlinkTouchQueApp() { return this.call<void>('DELETE', '/authentication-methods/touchque'); }
  /** Email codes as a second step. Needs a recent sign-in. */
  setEmailCodes(enabled: boolean) { return this.call<{ enabled: boolean }>('PUT', '/authentication-methods/email', { enabled }); }
  /** Texts a code to a new number for text-message codes. Needs a recent sign-in. */
  startSmsEnrollment(phone: string) { return this.call<{ phone: string }>('POST', '/authentication-methods/sms', { phone }); }
  /** The code from that text: text-message codes are on. Needs a recent sign-in. */
  verifySmsEnrollment(code: string) { return this.call<{ phone: string }>('POST', '/authentication-methods/sms/verify', { code }); }
  /** Needs a recent sign-in. */
  removeSmsCodes() { return this.call<void>('DELETE', '/authentication-methods/sms'); }
  /** Needs a recent sign-in. */
  unlinkIdentity(id: string) { return this.call<void>('DELETE', `/identities/${seg(id)}`); }
  /** Apps stop using a linked account for the person (token vault); signing in with it stays. */
  stopAppAccess(id: string) { return this.call<void>('DELETE', `/app-access/${seg(id)}`); }
  /** Sets or changes the password; other sessions end. Needs a recent sign-in. */
  setPassword(password: string) { return this.call<{ changed: true; sessions: number; refreshTokens: number; warning?: 'breached' }>('PUT', '/password', { password }); }
  /** Needs a recent sign-in and another way to sign in. */
  removePassword() { return this.call<void>('DELETE', '/password'); }
  /** A confirmation link goes to the new address. Needs a recent sign-in. */
  changeEmail(email: string) { return this.call<{ sent: true; email: string }>('POST', '/email', { email }); }
  sendVerificationEmail() { return this.call<{ sent: true }>('POST', '/email/verification'); }

  sessions() { return this.call<{ sessions: Array<Record<string, unknown> & { id: string; current: boolean }> }>('GET', '/sessions'); }
  endSession(id: string) { return this.call<void>('DELETE', `/sessions/${seg(id)}`); }
  endOtherSessions() { return this.call<{ sessions: number; refreshTokens: number }>('DELETE', '/sessions'); }

  apps() { return this.call<{ apps: Array<Record<string, unknown> & { clientId: string; name: string }> }>('GET', '/apps'); }
  revokeApp(clientId: string) { return this.call<{ consents: number; refreshTokens: number }>('DELETE', `/apps/${seg(clientId)}`); }
  consents() { return this.call<Record<string, unknown>>('GET', '/consents'); }
  setMarketing(granted: boolean) { return this.call<{ granted: boolean }>('PUT', '/consents/marketing', { granted }); }

  /** Everything about the person (KVKK/GDPR). Needs a recent sign-in. */
  exportData() { return this.call<Record<string, unknown>>('GET', '/export'); }
  /** Erases the account at once. Needs delete:me and a recent sign-in. */
  deleteAccount() { return this.call<{ deleted: true }>('DELETE', ''); }
}
