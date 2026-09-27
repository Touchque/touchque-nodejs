// WebAuthn/FIDO2 (passkey) — a phishing-resistant approval path alongside the
// push+device flow (tq.login.verify). Server-to-server, like every other
// resource here: the passkey ceremony runs in the browser
// (navigator.credentials.create()/get(), or the @touchque/web SDK), your
// backend collects that JSON and relays it through these methods.

import { HttpClient } from '../core/HttpClient';

export interface WebAuthnRegisterOptionsRequest {
  externalUsername: string;
  /**
   * Register a *resident* (discoverable) credential with forced user
   * verification and a stable WebAuthn user handle — the shape a
   * passwordless-primary login (see `primaryOptions`) authenticates against.
   * Omit for the classic second-factor credential.
   */
  discoverable?: boolean;
}

/** Passed straight through to navigator.credentials.create() in the browser. */
export type WebAuthnRegistrationOptions = Record<string, unknown>;

export interface WebAuthnRegisterVerifyRequest {
  externalUsername: string;
  /** The RegistrationResponseJSON returned by navigator.credentials.create(). */
  response: Record<string, unknown>;
  /** Optional display label for this credential (e.g. "MacBook Touch ID"). */
  label?: string;
}

export interface WebAuthnRegisterVerifyResponse {
  verified: boolean;
  credentialId: string;
}

export interface WebAuthnAuthenticateOptionsRequest {
  /** The pending LoginRequest id this WebAuthn assertion will approve. */
  requestId: string;
}

/** Passed straight through to navigator.credentials.get() in the browser. */
export type WebAuthnAuthenticationOptions = Record<string, unknown>;

export interface WebAuthnAuthenticateVerifyRequest {
  requestId: string;
  /** The AuthenticationResponseJSON returned by navigator.credentials.get(). */
  response: Record<string, unknown>;
}

export interface WebAuthnAuthenticateVerifyResponse {
  success: boolean;
  message: string;
  /** The user whose login request was approved (set by TouchQue, not by the browser). */
  externalUsername?: string;
  requestId?: string;
}

export interface WebAuthnPrimaryOptionsRequest {
  /** The account to authenticate (username-first passwordless-primary login). */
  externalUsername: string;
}

export interface WebAuthnPrimaryOptionsResponse {
  /** Opaque id tying the browser assertion back to this attempt. */
  attemptId: string;
  /** Passed straight through to navigator.credentials.get() in the browser. */
  options: Record<string, unknown>;
}

export interface WebAuthnPrimaryVerifyRequest {
  attemptId: string;
  /** The AuthenticationResponseJSON returned by navigator.credentials.get(). */
  response: Record<string, unknown>;
}

export interface WebAuthnPrimaryVerifyResponse {
  success: boolean;
  /** Present when success:false — risk/policy demands a step-up (push/number-match). */
  requiresStepUp?: boolean;
  externalUsername: string;
  riskScore: number;
  /** Present when success:true — the CONFIRMED LoginRequest id. */
  requestId?: string;
}

export interface WebAuthnCredentialSummary {
  id: string;
  credentialId: string;
  deviceType: string | null;
  backedUp: boolean;
  label: string | null;
  createdAt: string;
  lastUsedAt: string | null;
}

export class WebAuthn {
  constructor(private readonly http: HttpClient) {}

  /**
   * Step 1 of registering a passkey: get options for `navigator.credentials.create()`.
   *
   * @example
   * const options = await tq.webauthn.registerOptions({ externalUsername: 'user@company.com' });
   * // send `options` to the browser, call navigator.credentials.create({ publicKey: options })
   */
  async registerOptions(options: WebAuthnRegisterOptionsRequest): Promise<WebAuthnRegistrationOptions> {
    return this.http.post<WebAuthnRegistrationOptions>('/webauthn/register/options', {
      externalUsername: options.externalUsername,
      ...(options.discoverable ? { discoverable: true } : {}),
    });
  }

  /**
   * Step 2: verify the browser's registration response and store the credential.
   *
   * @example
   * const { verified, credentialId } = await tq.webauthn.registerVerify({
   *   externalUsername: 'user@company.com',
   *   response: browserRegistrationResponseJSON,
   *   label: 'MacBook Touch ID',
   * });
   */
  async registerVerify(options: WebAuthnRegisterVerifyRequest): Promise<WebAuthnRegisterVerifyResponse> {
    return this.http.post<WebAuthnRegisterVerifyResponse>('/webauthn/register/verify', {
      externalUsername: options.externalUsername,
      response: options.response,
      ...(options.label && { label: options.label }),
    });
  }

  /**
   * Step 1 of approving a pending login with a passkey: get options for
   * `navigator.credentials.get()`, scoped to a specific `requestId` (from
   * `tq.login.request()`).
   *
   * @example
   * const loginReq = await tq.login.request({ externalUsername: 'user@company.com', type: 'LOGIN' });
   * const options = await tq.webauthn.authenticateOptions({ requestId: loginReq.requestId });
   */
  async authenticateOptions(options: WebAuthnAuthenticateOptionsRequest): Promise<WebAuthnAuthenticationOptions> {
    return this.http.post<WebAuthnAuthenticationOptions>('/webauthn/login/options', {
      requestId: options.requestId,
    });
  }

  /**
   * Step 2: verify the browser's assertion — approves the LoginRequest on success.
   *
   * @example
   * const result = await tq.webauthn.authenticateVerify({
   *   requestId: loginReq.requestId,
   *   response: browserAuthenticationResponseJSON,
   * });
   */
  async authenticateVerify(options: WebAuthnAuthenticateVerifyRequest): Promise<WebAuthnAuthenticateVerifyResponse> {
    return this.http.post<WebAuthnAuthenticateVerifyResponse>('/webauthn/login/verify', {
      requestId: options.requestId,
      response: options.response,
    });
  }

  /**
   * Step 1 of a PASSWORDLESS-PRIMARY login: authenticate a user *from zero*
   * (no password, no prior `tq.login.request()`, no mobile device) with a
   * passkey registered via `registerOptions({ discoverable: true })`.
   *
   * Requires `TenantPolicy.passwordlessLoginEnabled` for the integration.
   * Returns `404 no_passkey_registered` if the user has no passkey — the
   * caller should then fall back to password login.
   *
   * @example
   * const { attemptId, options } = await tq.webauthn.primaryOptions({ externalUsername: 'user@company.com' });
   * // browser: const assertion = await navigator.credentials.get({ publicKey: options });
   */
  async primaryOptions(options: WebAuthnPrimaryOptionsRequest): Promise<WebAuthnPrimaryOptionsResponse> {
    return this.http.post<WebAuthnPrimaryOptionsResponse>('/webauthn/authenticate/primary/options', {
      externalUsername: options.externalUsername,
    });
  }

  /**
   * Step 2 of a passwordless-primary login: verify the browser assertion.
   *
   * On `success:true` the returned `requestId` is a CONFIRMED LoginRequest —
   * the login is done. On `success:false` with `requiresStepUp:true`, risk
   * or policy demands a second factor: start the normal `tq.login.request()`
   * / number-match flow instead of trusting this assertion alone.
   */
  async primaryVerify(options: WebAuthnPrimaryVerifyRequest): Promise<WebAuthnPrimaryVerifyResponse> {
    return this.http.post<WebAuthnPrimaryVerifyResponse>('/webauthn/authenticate/primary/verify', {
      attemptId: options.attemptId,
      response: options.response,
    });
  }

  /**
   * List a user's registered WebAuthn credentials (labels/metadata only, no key material).
   */
  async listCredentials(options: { externalUsername: string }): Promise<{ credentials: WebAuthnCredentialSummary[] }> {
    return this.http.get<{ credentials: WebAuthnCredentialSummary[] }>('/webauthn/credentials', {
      externalUsername: options.externalUsername,
    });
  }

  /**
   * Remove a registered credential (e.g. the user lost that device).
   * Pass `externalUsername` so only that user's credential can be removed.
   */
  async deleteCredential(credentialRecordId: string, options: { externalUsername?: string } = {}): Promise<{ deleted: boolean }> {
    const query = options.externalUsername ? `?externalUsername=${encodeURIComponent(options.externalUsername)}` : '';
    return this.http.delete<{ deleted: boolean }>(`/webauthn/credentials/${encodeURIComponent(credentialRecordId)}${query}`);
  }
}
