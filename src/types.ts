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
  /**
   * The push request (`requestId` from `login.request` / `tq.start`) this QR is a fallback for.
   * TouchQue then treats them as ONE sign-in: once the phone REJECTS the push the QR is dead
   * (no new QR is issued, a code for the old one is refused), and if the push asked for number
   * matching the QR asks for the same number. Always pass it when the QR follows a push.
   */
  requestId?: string;
  /** Ask for number matching on a standalone QR (implied when `requestId` points at a push that has one). */
  requireNumberMatch?: boolean;
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
  /**
   * Number matching: print this number under the QR. The phone shows three numbers (this one and
   * two decoys) after scanning and the user taps the one that matches the page. Absent when the
   * QR needs no number matching.
   */
  challengeCode?: string;
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
  /** The push request this sign-in belongs to: a code is refused once the phone rejected it. */
  requestId?: string;
}

export interface OfflineVerifyResult {
  approved: boolean;
  /** When not approved: invalid_code | locked | expired | used | unknown_challenge | request_rejected | too_many_failures | frozen | … */
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
  /**
   * Silent sign-ins: the browser's device-bound key proof, exactly as the
   * browser sent it (`X-TouchQue-Browser` header, made by `@touchque/web`).
   * When the user approves this request on the phone (or with a passkey),
   * TouchQue remembers the browser, so a later `risk.check` can let the same
   * browser in without asking. Pass it through untouched; an invalid proof
   * only means "a browser TouchQue does not know".
   */
  browserProof?: string;
  /**
   * For your TouchQue Actions only (`event.context`): roles, plan, amount…
   * Any JSON object up to 4 KB. Never shown on the phone.
   */
  context?: Record<string, unknown>;
}

export interface LoginRequestResponse {
  requestId: string;
  /** Challenge code for number matching UI (if enabled for this integration) */
  challengeCode?: string;
  /**
   * "Why?" case code of this decision (`K7P-2QX`). Show it to the user ("Tell
   * your support team: K7P-2QX"); your team opens the whole decision (each
   * check, the rule that matched, what would have let it through) by this code
   * in the dashboard (Logs → Look up a case).
   */
  caseCode?: string;
  /** Why number matching or a passkey is needed (a fixed list, never a score); absent for a plain push. */
  reasons?: RiskReason[];
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
  /**
   * Mirror Alarm: have the page that shows this sign-in load `url` (a hidden
   * image) and send a beacon to it (`@touchque/web` does both). A page that is
   * not on your site, i.e. a real-time phishing proxy, gets the approval
   * refused (webhook reason `phishing_origin`). Allow its host in your CSP
   * `img-src` and `connect-src`.
   */
  canary?: { url: string };
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
  /**
   * The request can only be approved with a passkey: a phishing-resistant
   * policy, or the Vishing Shield moved it to a passkey at the phone tap
   * because the user was on a call (it is still PENDING then).
   */
  requiresPasskey?: boolean;
  /**
   * Vishing Shield: approved on the phone during a call. Still CONFIRMED;
   * the user's critical actions are refused (`blocked` / `provisional`) until
   * the phone re-confirms it after the call (`reconfirmedAt`) or the user
   * takes it back (`revoked`).
   */
  provisional?: boolean;
  /** When the phone re-confirmed a provisional approval after the call. */
  reconfirmedAt?: string | null;
  /** The user took this approval back on the phone: end what was built on it. */
  revoked?: boolean;
  /** `COACHED`: someone on the phone told the user to approve. `UNDO`: the user undid it. */
  revokeReason?: 'UNDO' | 'COACHED' | null;
}

export interface WaitForApprovalOptions {
  requestId: string;
  /** How long to poll in total, ms (default: 30000 = 30s) */
  timeout?: number;
  /** Polling interval, ms (default: 1500) */
  pollInterval?: number;
}

/**
 * What `login.verify()` hands `onChallenge` as soon as the request exists,
 * before it waits: show `challengeCode` to the user now; the phone asks for it.
 */
export interface VerifyChallenge {
  requestId: string;
  /** The number to show when number matching is on (absent otherwise). */
  challengeCode?: string;
  expiresAt: string;
  /** Why number matching is needed (absent for a plain push). */
  reasons?: RiskReason[];
  /** The "Why?" case code of this decision. */
  caseCode?: string;
}

/** Options of `login.verify()` on top of the request's own. */
export interface VerifyOptions extends LoginRequestOptions {
  /** How long to wait for the user, in ms (default 30 000). */
  timeout?: number;
  pollInterval?: number;
  /**
   * Called once, right after the request is created and before any waiting,
   * with the number to show (number matching: the phone asks the user for
   * it). Not called when only a passkey can approve (verify() then throws
   * TouchQuePasskeyRequiredError at once). An error it throws, or a promise
   * it returns that rejects, is logged and ignored: verify() keeps waiting.
   * Its return value is otherwise ignored.
   */
  onChallenge?: (challenge: VerifyChallenge) => unknown;
}

export interface WaitForApprovalResult {
  approved: boolean;
  status: LoginStatus;
}

// ─── Risk Resource (silent sign-ins) ─────────────────────────────

export interface RiskCheckOptions {
  /** User identifier in YOUR system */
  externalUsername: string;
  /** The action the user is about to do (default `'LOGIN'`). A critical action always asks. */
  type?: LoginType;
  /** End user's IP address: compared with the networks of the user's earlier approved sign-ins. */
  clientIp?: string;
  userAgent?: string;
  /** The browser's device-bound key proof (`X-TouchQue-Browser`), passed through untouched. */
  browserProof?: string;
  /**
   * Your own limit on how long ago the last phone approval in this browser
   * may be, in seconds (integer, 0 = always ask). TouchQue never goes beyond
   * its own limit (7 days).
   */
  maxAgeSeconds?: number;
  /** For your TouchQue Actions only (`event.context`). Any JSON object up to 4 KB. */
  context?: Record<string, unknown>;
}

/** One reason behind a `risk.check` answer. Show `text` or translate `code`. */
export interface RiskReason {
  /**
   * Why it was silent: `known_browser`, `recent_approval`, `same_phone`,
   * `familiar_network`, `no_risk_signal`. Why it asks: `no_browser_key`,
   * `new_browser`, `approval_too_old`, `policy_every_sign_in`, `other_phone`,
   * `new_country`, `new_network`, `network_unknown`, `hosting_network`,
   * `critical_action`, `sensitive_action`, `risk_signal`, `push_fatigue`,
   * `fraud_report`, `new_factor`, `vishing_shield`, `checks_incomplete`,
   * `silent_mode_shadow`, `phone_not_linked`, `frozen`, … New codes are added
   * in minor versions. `action`: one of your TouchQue Actions asked
   * (`text` is its reason, `action` its slug).
   */
  code: string;
  /** English text. */
  text: string;
  /** With `code: 'action'`: the slug of the Action. */
  action?: string;
}

export interface RiskCheckResult {
  /**
   * `false` only when TouchQue answered exactly `prompt: false`: nothing
   * about this sign-in is new, let the user in without a push. Anything else
   * (including an unreadable answer) is `true`: ask on the phone as usual.
   */
  prompt: boolean;
  reasons: RiskReason[];
  /**
   * "Why?" case code of this decision (`K7P-2QX`). Show it to the user ("Tell
   * your support team: K7P-2QX"); your team opens the whole decision (each
   * check, the rule that matched, what would have let it through) by this code
   * in the dashboard (Logs → Look up a case).
   */
  caseCode?: string;
  /** How sure TouchQue is that this is the user (default `'normal'`). */
  assurance: 'high' | 'normal' | 'low';
  /**
   * `'shadow'`: silent sign-ins are only measured for this workspace, so
   * `prompt` is always true and the reasons say what would have happened.
   */
  silentMode: 'enforce' | 'shadow';
}

export interface RiskBrowsersOptions {
  externalUsername: string;
}

/** A browser TouchQue knows for a user: one the user approved on the phone (or with a passkey). */
export interface RiskBrowser {
  /** RFC 7638 thumbprint of the browser's key: pass it to `forgetBrowsers` to forget this one. */
  thumbprint: string;
  label: string | null;
  createdAt: string;
  /** Last phone or passkey approval in this browser. */
  lastMfaAt: string | null;
  /** How that approval was given, e.g. `'push'` or `'passkey'`. */
  lastMfaMethod: string | null;
  lastSeenAt: string | null;
  /** Last sign-in TouchQue let through without asking. */
  lastSilentAt: string | null;
}

export interface RiskBrowsersResponse {
  browsers: RiskBrowser[];
}

export interface ForgetBrowsersOptions {
  externalUsername: string;
  /** One browser; leave out to forget every browser of the user (e.g. after a password reset). */
  thumbprint?: string;
}

export interface ForgetBrowsersResponse {
  forgotten: number;
}

// ─── Recovery Resource (Never Locked Out) ────────────────────────

export type RecoveryStatus = 'AWAITING_DEVICE' | 'VOUCHING' | 'COOLING' | 'COMPLETED' | 'VETOED' | 'EXPIRED' | 'FAILED';

export interface RecoveryVoucherEligibility {
  externalUsername: string;
  /** Can vouch today: a linked phone with a hardware key, not frozen, not on probation. */
  eligible: boolean;
  /** Why not: `no_phone`, `no_hardware_key`, `keys_lost`, `frozen`, `on_probation`, `same_phone`. */
  reason?: string;
}

export interface RecoveryVouchersResponse {
  externalUsername: string;
  vouchers: RecoveryVoucherEligibility[];
  updatedAt: string | null;
  /** The user's own account is on probation after a vouch recovery until then. */
  probationUntil: string | null;
}

export interface SetRecoveryVouchersOptions {
  externalUsername: string;
  /** Other users of your workspace; at most 5 are kept. Ask for the user's phone before you change it. */
  vouchers: string[];
}

export interface StartRecoveryOptions {
  externalUsername: string;
  /** The user's IP address (the risk engine and the vouchers see it). */
  clientIp?: string;
  userAgent?: string;
  /** How the vouchers know the user. */
  displayName?: string;
  /** Fill up a short named list, e.g. with the organization's admins. */
  fallbackVouchers?: string[];
  /** More vouchers than the floor of 2. */
  required?: number;
  /** A longer cooling-off than the floor of 15 minutes (default 60). */
  coolOffMinutes?: number;
  /** What the vouchers' phones show instead of the default English lines. */
  details?: Array<{ label: string; value: string }>;
  /** What the old phone shows (approve to move now, reject to stop) instead of the default English lines. */
  noticeDetails?: Array<{ label: string; value: string }>;
}

export interface RecoveryVoucherState {
  externalUsername: string;
  source?: 'nominated' | 'fallback';
  state: 'waiting' | 'pending' | 'approved' | 'expired' | 'unreachable';
  /** The number this voucher must type, while their request is open. */
  code: string | null;
}

export interface RecoveryReceipt {
  seq: number;
  at: string;
  step: string;
  actor: Record<string, unknown>;
  data: Record<string, unknown>;
  prev: string | null;
  hash: string;
}

export interface RecoveryCase {
  recoveryId: string;
  externalUsername: string;
  method: 'vouch' | 'old_phone' | 'transfer';
  status: RecoveryStatus;
  required: number;
  approvals: number;
  vouchers: RecoveryVoucherState[];
  oldPhone: { notified: boolean; code: string | null };
  coolOffMinutes: number;
  coolOffUntil: string | null;
  elevated: boolean;
  reasons: string[];
  location: string | null;
  newPhoneBound: boolean;
  expiresAt: string;
  completedAt: string | null;
  endedReason: string | null;
  endedBy: string | null;
  createdAt: string;
  receipts: RecoveryReceipt[];
}

export interface RecoveryStarted extends RecoveryCase {
  /** One-time; shown once. */
  bindCode: string;
  /** Show it as a QR: the TouchQue app on the new phone scans it. */
  bindUri: string;
}

export interface VetoRecoveryOptions {
  /** Who stopped it, e.g. the admin's e-mail (shown in the receipts). */
  by?: string;
  /** Default `partner_veto`. */
  reason?: string;
}

export interface ListRecoveriesOptions {
  externalUsername?: string;
  /** Only running recoveries of the workspace. */
  open?: boolean;
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
  /**
   * De-duplicates deliveries by their signed `jti`. A second delivery with
   * the same `jti` throws `TouchQueWebhookReplayError`. Use
   * `MemoryWebhookReplayCache` for a single process, or implement this
   * interface over Redis / your database when you run several instances.
   */
  replayCache?: WebhookReplayCache;
}

/**
 * Storage for webhook `jti`s already accepted. `checkAndSet` must atomically
 * record `jti` for `ttlSeconds` and return `true` if it was NOT seen before.
 */
export interface WebhookReplayCache {
  checkAndSet(jti: string, ttlSeconds: number): boolean;
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
  /** On REJECTED: why (see `WebhookReasons`). Treat unknown values as a rejection. */
  reason?: string;
  /** On SUCCESS: approved during a call (Vishing Shield); an `APPROVAL_RECONFIRMED` or `APPROVAL_REVOKED` event follows. */
  provisional?: boolean;
  [key: string]: unknown;
}

/**
 * `reason` values of a REJECTED login webhook. Treat a value you do not know
 * as a rejection: new ones are added in minor versions.
 */
export const WebhookReasons = {
  /** The user tapped Reject. */
  USER_REJECTED: 'user_rejected',
  /** The user said "this wasn't me": 2FA is frozen. */
  USER_REPORTED_FRAUD: 'user_reported_fraud',
  /** The user said someone on the phone told them to approve: 2FA is frozen; treat it as a takeover in progress. */
  USER_REPORTED_COACHED: 'user_reported_coached',
  /** Approved, then refused by the risk engine on evidence seen at the tap. */
  RISK_REVERSED: 'risk_reversed',
  /** Refused for now; the user's next request asks for number matching. */
  RISK_STEP_UP: 'risk_step_up',
  /** The approval carried a device signature that did not verify. */
  APPROVAL_SIGNATURE_INVALID: 'approval_signature_invalid',
  /** The phone reports itself jailbroken or tampered and the action is critical. */
  DEVICE_INTEGRITY_FAILED: 'device_integrity_failed',
  /** Vishing Shield: approved during a call (or with the screen shared / remote-controlled), critical, and no passkey to fall back on. */
  VISHING_SUSPECTED: 'vishing_suspected',
  /** Mirror Alarm: the sign-in page was not on your site (a real-time phishing proxy). */
  PHISHING_ORIGIN: 'phishing_origin',
} as const;

/**
 * `event` values of TouchQue's event webhooks (same `callbackUrl` as the
 * login results). Ignore types you do not know.
 */
export const WebhookEvents = {
  DEVICE_LINKED: 'DEVICE_LINKED',
  DEVICE_UNLINKED: 'DEVICE_UNLINKED',
  PASSKEY_REGISTERED: 'PASSKEY_REGISTERED',
  PASSKEY_DELETED: 'PASSKEY_DELETED',
  /** After the call, the user confirmed a provisional approval was theirs: critical actions are allowed again. */
  APPROVAL_RECONFIRMED: 'APPROVAL_RECONFIRMED',
  /** The user took an approval back (`reason`: `COACHED` or `UNDO`): end the session or stop the action built on it. */
  APPROVAL_REVOKED: 'APPROVAL_REVOKED',
} as const;

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
  /** Show the number to the user as soon as the request exists (see `VerifyOptions.onChallenge`). */
  onChallenge?: VerifyOptions['onChallenge'];
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
  /** "Why?" case code of a refusal (`K7P-2QX`), to show the user. */
  caseCode?: string;
}
