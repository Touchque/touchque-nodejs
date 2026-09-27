// src/types.ts
// All TypeScript types and interfaces for the TouchQue Node.js SDK

export interface TouchQueConfig {
  /** Your TouchQue API key (starts with `tq_`) */
  apiKey: string;
  /** Your TouchQue API secret */
  apiSecret: string;
  /**
   * Optional base URL override (default: https://api.touchque.com, or the
   * TQ_API_URL environment variable). Must be `https://` unless it
   * points at localhost — the SDK refuses plaintext `http://` to any other
   * host so the API key / signature are never sent in the clear.
   */
  baseUrl?: string;
  /** Request timeout in ms (default: 10000) */
  timeout?: number;
}

// ─── Auth Resource ───────────────────────────────────────────────

export interface GenerateSecretOptions {
  /** The user's unique identifier in YOUR system (email, userId, etc.) */
  externalUsername: string;
}

export interface GenerateSecretResponse {
  /** New setup secret — show to user once (e.g. as QR code) */
  secret: string;
  externalUsername: string;
  /** ISO string of when this secret expires if not used */
  expiresAt: string;
  ttlMs: number;
  /**
   * A ready-to-render `data:image/png;base64,...` QR code encoding `secret`
   * for the TouchQue mobile app to scan. Show this directly in an `<img>`
   * src — no client-side QR generation needed.
   */
  qrCodeDataUrl: string;
  /**
   * 10 one-time recovery codes to be shown to the user.
   * If the user loses their device, they can use one of these codes to bypass 2FA.
   */
  recoveryCodes: string[];
}

export interface UnlinkSecretOptions {
  externalUsername: string;
}

export interface UnlinkSecretResponse {
  success: boolean;
  externalUsername: string;
  message: string;
}

export interface ValidateSecretOptions {
  secret: string;
}

export interface ValidateSecretResponse {
  valid: boolean;
  externalUsername?: string;
  integrationId?: string;
  integration?: {
    companyName: string;
    icon: string;
    color: string;
  };
  message?: string;
  reason?: string;
  usedAt?: string;
  expiredAt?: string;
}
export interface ResetSecretOptions {
  externalUsername: string;
}

export interface ResetSecretResponse {
  /** New setup secret — show to user once */
  secret: string;
  externalUsername: string;
  expiresAt?: string;
  /** See GenerateSecretResponse.qrCodeDataUrl. */
  qrCodeDataUrl?: string;
  recoveryCodes?: string[];
}

export interface GetUserResponse {
  externalUsername: string;
  /** Set once the mobile app has linked (scanned) the secret. */
  deviceId: string | null;
  /** true once the secret has been linked to a device via /auth/secret/link. */
  used: boolean;
  frozen: boolean;
  createdAt: string;
  expireAt: string | null;
}

// ─── Offline Sign ────────────────────────────────────────────────

export interface OfflineChallengeOptions {
  /** User identifier in YOUR system */
  externalUsername: string;
  /** The action being approved (an Action Type slug/id from your Dashboard) */
  type: string;
  /**
   * What the user is approving, shown on the phone (see LoginRequestOptions.details).
   * REQUIRED for critical action types.
   */
  details?: LoginRequestDetails;
  /** End user's IP / User-Agent: shown to the user as "where the request came from". */
  clientIp?: string;
  userAgent?: string;
  /** Seconds the challenge stays valid (30–300, default 120). */
  ttlSeconds?: number;
  /** Set false to skip the ready-made QR image (`qrDataUrl` is then null). */
  includeQrImage?: boolean;
}

export interface OfflineChallengeResponse {
  challengeId: string;
  /** QR text (`TQ2.…`, encrypted for the user's phone; nothing in it is readable) — draw it as a QR code if you don't use `qrDataUrl`. */
  qr: string;
  /** `data:image/png;base64,…` ready for `<img src>`; null when `includeQrImage: false`. */
  qrDataUrl: string | null;
  expiresAt: string;
  expiresInSeconds: number;
  /** True when the workspace allows the time-based code fallback (no camera). */
  totpAvailable: boolean;
}

export interface OfflineVerifyOptions {
  challengeId: string;
  /** The 7 characters shown on the phone; dashes/spaces/case are ignored. */
  code: string;
}

export interface OfflineTotpVerifyOptions {
  externalUsername: string;
  code: string;
  /** The action the code is for; critical actions are refused. */
  type?: string;
  clientIp?: string;
}

export interface OfflineVerifyResult {
  approved: boolean;
  /** When not approved: invalid_code | locked | expired | used | unknown_challenge | too_many_failures | frozen | … */
  reason?: string;
  /** Wrong codes left before the challenge locks (only with reason `invalid_code`). */
  attemptsLeft?: number;
  challengeId?: string;
  externalUsername?: string;
  type?: string;
}

// ─── Login Resource ──────────────────────────────────────────────

export type LoginType = 'LOGIN' | 'DISABLE_2FA' | string;

/** Label → value pairs, or an explicit ordered list of `{ label, value }`. */
export type LoginRequestDetails =
  | Record<string, string | number>
  | Array<{ label: string; value: string | number }>;

export interface LoginRequestOptions {
  /** User identifier in YOUR system */
  externalUsername: string;
  /**
   * The type of action requiring 2FA confirmation.
   * Built-in types: 'LOGIN', 'DISABLE_2FA'
   * Custom types can be created/configured in your TouchQue Dashboard.
   */
  type: LoginType;
  /** Optional reference (e.g. your internal transaction ID) */
  referenceId?: string;
  
  /** The IP address of the user initiating the request. TouchQue will resolve this to a City/Country. */
  clientIp?: string;
  /**
   * The User-Agent string of the user's browser/device. Shown on the approval
   * screen as the requesting browser and device (e.g. "Chrome · macOS").
   */
  userAgent?: string;
  /**
   * Transaction context shown on the approval screen, so the user sees what
   * they are approving — e.g. `{ Amount: '1,250.00 USD', Recipient: 'Jane Doe' }`.
   * Keys and values are displayed as-is, in the order given.
   *
   * Limits (the request is rejected with a 400 otherwise — never truncated):
   * at most 8 entries, labels up to 40 characters, values up to 120
   * characters, strings or numbers only, no control characters.
   *
   * Always set this from your server-side state, never from browser input.
   */
  details?: LoginRequestDetails;
  /** Require the user to authenticate with FaceID / TouchID on their device to approve this request. */
  requireBiometric?: boolean;
  /**
   * Force Number Matching (anti-push-bombing).
   * When true, the user must type a matching code shown on their screen to approve.
   * The backend also auto-enables this if MFA fatigue is detected (2+ failed requests in 10 min).
   */
  requireNumberMatch?: boolean;
}

export interface LoginRequestResponse {
  requestId: string;
  /** Challenge code for number matching UI (if enabled for this integration) */
  challengeCode?: string;
  message: string;
  expiresAt: string;
  /**
   * Present only when this integration has behavioral biometrics enabled
   * (TenantPolicy.behavioralBiometricsEnabled). Pass this down to your
   * frontend along with `requestId` to initialize the behavioral widget in
   * `@touchque/web` (`tq.behavioral.attach(...)`), scoped to your 2FA
   * challenge UI. Single-purpose and short-lived — do not reuse across requests.
   */
  telemetryToken?: string;
  /**
   * The workspace policy requires a phishing-resistant factor for this action:
   * no push was sent. Approve it with a passkey in the browser
   * (`@touchque/web` `passkeys.approveLogin({ requestId })`).
   */
  requiresPasskey?: boolean;
}

/** How an approved request was confirmed, and whether that is phishing-resistant. */
export interface ApprovalAssurance {
  /** true only for passkeys (WebAuthn): the signature is bound to your site's origin. */
  phishingResistant: boolean;
  /** 'passkey' | 'push' | 'recovery_code' | ... */
  method: string | null;
}

export type LoginStatus = 'PENDING' | 'CONFIRMED' | 'REJECTED' | 'EXPIRED';

export interface LoginStatusResponse {
  status: LoginStatus;
  /** How the request was confirmed ('DEVICE', 'WEBAUTHN', ...); null until confirmed */
  confirmedVia?: string | null;
  /**
   * Device-signed proof of what was approved (only when the approving phone
   * holds a Secure Enclave key). Check it with `verifyApprovalProof`.
   */
  approvalProof?: import('./approvalProof').ApprovalProof | null;
  /** Set once CONFIRMED: rely on `assurance.phishingResistant` for high-assurance sessions. */
  assurance?: ApprovalAssurance | null;
  /** The request can only be approved with a passkey (phishing-resistant policy). */
  requiresPasskey?: boolean;
}

export interface WaitForApprovalOptions {
  requestId: string;
  /** How long to poll in total, ms (default: 30000 = 30s) */
  timeout?: number;
  /** Polling interval, ms (default: 1500) */
  pollInterval?: number;
}

export interface WaitForApprovalResult {
  approved: boolean;
  status: LoginStatus;
}

// ─── Webhook Resource ────────────────────────────────────────────

export interface VerifyWebhookOptions {
  /** Raw request body as string, exactly as received (before JSON.parse). */
  rawBody: string;
  /**
   * The signature to check against. Pass the value of the `x-signature`
   * header. Optional: if omitted, the SDK falls back to the `signature`
   * field TouchQue also embeds in the JSON body.
   */
  signature?: string;
  /**
   * Reject the webhook if its `timestamp` is more than this many seconds
   * from now (replay protection). Default 300 (5 minutes). Set to 0 to
   * disable the freshness check.
   */
  toleranceSeconds?: number;
}

export interface WebhookPayload {
  event: string;
  requestId: string;
  externalUsername: string;
  status: LoginStatus;
  timestamp: string;
  /**
   * On a SUCCESS webhook, the approving phone's device-signed proof of what
   * was approved (when it holds a Secure Enclave key). Check it with
   * `verifyApprovalProof` before releasing money or data.
   */
  approvalProof?: import('./approvalProof').ApprovalProof;
  /** On SUCCESS: how it was approved and whether that was phishing-resistant. */
  assurance?: ApprovalAssurance;
  [key: string]: unknown;
}

// ─── Protect Wrapper ─────────────────────────────────────────────

export interface ProtectOptions<TArgs extends any[]> {
  /** The action type (e.g. 'WITHDRAW', 'LOGIN') */
  type: string;
  /** Function to extract the externalUsername from the wrapped function's arguments */
  getUserIdentifier: (...args: TArgs) => string;
  /** Optional function to extract a referenceId from the arguments */
  getReferenceId?: (...args: TArgs) => string | undefined;
  /**
   * Optional function returning the end user's request context (IP address,
   * User-Agent) and transaction details shown on the approval screen.
   */
  getContext?: (...args: TArgs) => Pick<LoginRequestOptions, 'clientIp' | 'userAgent' | 'details'> | undefined;
  /** Timeout in ms */
  timeout?: number;
  /** Polling interval in ms */
  pollInterval?: number;
}

// ─── Errors ──────────────────────────────────────────────────────

export interface TouchQueErrorData {
  error?: string;
  message?: string;
  code?: string;
  /** Offline sign: why a code was not approved (`invalid_code`, `locked`, `expired`, `used`, …). */
  reason?: string;
  /** Offline sign: wrong codes left before the challenge locks. */
  attemptsLeft?: number;
  /** Seconds to wait before retrying (429 / 423). */
  retryAfter?: number;
}
