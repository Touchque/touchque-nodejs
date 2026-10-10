import { Request as Request$1, Response as Response$1, NextFunction, Router } from 'express';

interface ApprovalProof {
    version: 'v2';
    algorithm: 'ECDSA-P256-SHA256';
    /** The exact text the device signed */
    message: string;
    /** base64 DER signature */
    signature: string;
    /** base64 X9.63 Secure Enclave public key of the approving device */
    publicKey: string;
}
interface VerifyApprovalProofOptions {
    /** The request id returned by login.request() */
    requestId: string;
    /** The action type you sent (e.g. 'WITHDRAW') */
    type: string;
    /**
     * The details you sent with login.request(), exactly as you sent them.
     * Pass undefined when you sent none.
     */
    details?: LoginRequestDetails;
    /**
     * The challenge code login.request() returned, when number matching was
     * used for this request.
     */
    challengeCode?: string;
    /**
     * Pin the device: the base64 public key you stored for this user (e.g. the
     * `proof.publicKey` of their first verified approval). A proof from any
     * other key is rejected. Required unless `allowUnpinnedKey` is set.
     */
    expectedPublicKey?: string;
    /**
     * Accept a proof from whatever key it carries. Without a pinned key the
     * proof only shows that *some* key signed these details — anyone able to
     * forge the webhook or status response could bring their own. Only for
     * trust-on-first-use: store `proof.publicKey` after this first check and
     * pass it as `expectedPublicKey` from then on.
     */
    allowUnpinnedKey?: boolean;
}
/** SHA-256 hex of the details as displayed on the phone ('' when none). */
declare function detailsDigest(details?: LoginRequestDetails): string;
/**
 * Returns true only if the proof was signed by the device's key over exactly
 * the request, type, challenge code and details you expect. Fails closed:
 * without `expectedPublicKey` (or an explicit `allowUnpinnedKey: true`) it
 * returns false. Never throws for malformed input; returns false.
 */
declare function verifyApprovalProof(proof: ApprovalProof | null | undefined, options: VerifyApprovalProofOptions): boolean;

interface TouchQueConfig {
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
interface GenerateSecretOptions {
    /** The user's unique identifier in YOUR system (email, userId, etc.) */
    externalUsername: string;
}
interface GenerateSecretResponse {
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
interface UnlinkSecretOptions {
    externalUsername: string;
}
interface UnlinkSecretResponse {
    success: boolean;
    externalUsername: string;
    message: string;
}
interface ValidateSecretOptions {
    secret: string;
}
interface ValidateSecretResponse {
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
interface ResetSecretOptions {
    externalUsername: string;
}
interface ResetSecretResponse {
    /** New setup secret — show to user once */
    secret: string;
    externalUsername: string;
    expiresAt?: string;
    /** See GenerateSecretResponse.qrCodeDataUrl. */
    qrCodeDataUrl?: string;
    recoveryCodes?: string[];
}
interface GetUserResponse {
    externalUsername: string;
    /** Set once the mobile app has linked (scanned) the secret. */
    deviceId: string | null;
    /** true once the secret has been linked to a device via /auth/secret/link. */
    used: boolean;
    frozen: boolean;
    createdAt: string;
    expireAt: string | null;
}
interface OfflineChallengeOptions {
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
interface OfflineChallengeResponse {
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
interface OfflineVerifyOptions {
    challengeId: string;
    /** The 7 characters shown on the phone; dashes/spaces/case are ignored. */
    code: string;
}
interface OfflineTotpVerifyOptions {
    externalUsername: string;
    code: string;
    /** The action the code is for; critical actions are refused. */
    type?: string;
    clientIp?: string;
    /** The push request this sign-in belongs to: a code is refused once the phone rejected it. */
    requestId?: string;
}
interface OfflineVerifyResult {
    approved: boolean;
    /** When not approved: invalid_code | locked | expired | used | unknown_challenge | request_rejected | too_many_failures | frozen | … */
    reason?: string;
    /** Wrong codes left before the challenge locks (only with reason `invalid_code`). */
    attemptsLeft?: number;
    challengeId?: string;
    externalUsername?: string;
    type?: string;
}
type LoginType = 'LOGIN' | 'DISABLE_2FA' | string;
/** Label → value pairs, or an explicit ordered list of `{ label, value }`. */
type LoginRequestDetails = Record<string, string | number> | Array<{
    label: string;
    value: string | number;
}>;
interface LoginRequestOptions {
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
interface LoginRequestResponse {
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
interface ApprovalAssurance {
    /** true only for passkeys (WebAuthn): the signature is bound to your site's origin. */
    phishingResistant: boolean;
    /** 'passkey' | 'push' | 'recovery_code' | ... */
    method: string | null;
}
type LoginStatus = 'PENDING' | 'CONFIRMED' | 'REJECTED' | 'EXPIRED';
interface LoginStatusResponse {
    status: LoginStatus;
    /** How the request was confirmed ('DEVICE', 'WEBAUTHN', ...); null until confirmed */
    confirmedVia?: string | null;
    /**
     * Device-signed proof of what was approved (only when the approving phone
     * holds a Secure Enclave key). Check it with `verifyApprovalProof`.
     */
    approvalProof?: ApprovalProof | null;
    /** Set once CONFIRMED: rely on `assurance.phishingResistant` for high-assurance sessions. */
    assurance?: ApprovalAssurance | null;
    /** The request can only be approved with a passkey (phishing-resistant policy). */
    requiresPasskey?: boolean;
}
interface WaitForApprovalOptions {
    requestId: string;
    /** How long to poll in total, ms (default: 30000 = 30s) */
    timeout?: number;
    /** Polling interval, ms (default: 1500) */
    pollInterval?: number;
}
interface WaitForApprovalResult {
    approved: boolean;
    status: LoginStatus;
}
interface VerifyWebhookOptions {
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
interface WebhookReplayCache {
    checkAndSet(jti: string, ttlSeconds: number): boolean;
}
interface WebhookPayload {
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
    approvalProof?: ApprovalProof;
    /** On SUCCESS: how it was approved and whether that was phishing-resistant. */
    assurance?: ApprovalAssurance;
    [key: string]: unknown;
}
interface ProtectOptions<TArgs extends any[]> {
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
interface TouchQueErrorData {
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

declare class HttpClient {
    private readonly client;
    private readonly apiKey;
    private readonly apiSecret;
    constructor(config: TouchQueConfig);
    /**
     * Canonical signature.
     * Format: HMAC(apiSecret, "METHOD:pathWithQuery:timestamp:nonce:bodyHash")
     *
     * `pathWithQuery` includes the sorted query string so GET/DELETE query
     * params are covered by the signature (older SDKs signed the path only;
     * the backend accepts either form).
     */
    private sign;
    private generateNonce;
    private authHeaders;
    post<T>(path: string, body?: Record<string, unknown>): Promise<T>;
    get<T>(path: string, params?: Record<string, string | number | boolean>): Promise<T>;
    delete<T>(path: string): Promise<T>;
    private handleError;
}

declare class Auth {
    private readonly http;
    constructor(http: HttpClient);
    /**
     * Generate a new setup secret for a user.
     * Show this secret to the user ONCE (e.g. as a QR code) so they can
     * link their TouchQue app.
     *
     * The secret expires after 60 seconds if not used (scanned by the mobile app).
     * After expiry, calling this method again will automatically rotate the secret.
     *
     * @example
     * const { secret, expiresAt } = await tq.auth.generateSecret({
     *   externalUsername: 'user@company.com'
     * });
     * // Show `secret` to user as QR code
     * // Secret expires at `expiresAt` if not scanned
     */
    generateSecret(options: GenerateSecretOptions): Promise<GenerateSecretResponse>;
    /**
     * Reset (regenerate) a user's secret.
     * This invalidates the old secret and generates a new one.
     * Show the new secret to the user.
     *
     * @example
     * const { secret } = await tq.auth.resetSecret({
     *   externalUsername: 'user@company.com'
     * });
     * // Show new secret to user
     */
    resetSecret(options: ResetSecretOptions): Promise<ResetSecretResponse>;
    /**
     * Validate a secret code.
     * Useful if you want to verify the user entered the correct setup secret.
     * Note: The backend allows this without an API key, but the SDK sends it for consistency.
     */
    validateSecret(options: ValidateSecretOptions): Promise<ValidateSecretResponse>;
    /**
     * Look up a user's current link status — no push notification is sent.
     * Useful for detecting "the mobile app just linked this secret" (`used`
     * flips true, `deviceId` gets set) without sending a LOGIN challenge to
     * their device, e.g. while polling during enrollment.
     *
     * @example
     * const { used, deviceId } = await tq.auth.getUser({
     *   externalUsername: 'user@company.com'
     * });
     * if (used && deviceId) {
     *   // Device has linked — no approval push needed to confirm this.
     * }
     */
    getUser(options: {
        externalUsername: string;
    }): Promise<GetUserResponse>;
}

declare class Login {
    private readonly http;
    constructor(http: HttpClient);
    /**
     * Request 2FA confirmation from a user's TouchQue app.
     *
     * The user will receive a push notification on their device.
     * They can then approve or reject the request.
     *
     * Built-in `type` values:
     * - `'LOGIN'` — User is logging in
     * - `'DISABLE_2FA'` — User is disabling 2FA
     * - Custom action type IDs or slugs configured in your TouchQue Dashboard
     *
     * @example
     * // Basic login verification
     * const response = await tq.login.request({
     *   externalUsername: 'user@company.com',
     *   type: 'LOGIN'
     * });
     *
     * @example
     * // Protect a custom action using its Dashboard-configured ID or slug
     * const response = await tq.login.request({
     *   externalUsername: 'user@company.com',
     *   type: 'action_type_slug_or_id',
     *   referenceId: 'txn_abc123' // Your internal transaction ID
     * });
     *
     * @example
     * // Show the user what they are approving, where it came from
     * const response = await tq.login.request({
     *   externalUsername: 'user@company.com',
     *   type: 'WITHDRAW',
     *   clientIp: req.ip,
     *   userAgent: req.get('user-agent'),
     *   details: { Amount: '1,250.00 USD', Recipient: 'Jane Doe' },
     * });
     */
    request(options: LoginRequestOptions): Promise<LoginRequestResponse>;
    /**
     * Check the current status of a login request.
     *
     * Returns: `'PENDING'` | `'CONFIRMED'` | `'REJECTED'` | `'EXPIRED'`
     *
     * @example
     * const { status } = await tq.login.status('request_id_here');
     * if (status === 'CONFIRMED') {
     *   // User approved — proceed with action
     * }
     */
    status(requestId: string): Promise<LoginStatusResponse>;
    /**
     * Wait for the user to approve or reject a login request.
     *
     * This is a convenience method that polls the status endpoint
     * until the request is approved, rejected, or times out.
     *
     * **This is the recommended way to integrate TouchQue into your routes.**
     *
     * @throws {TouchQueRejectedError} If the user rejects the request
     * @throws {TouchQueTimeoutError} If the request times out (user didn't respond)
     *
     * @example
     * // Simple: Send request and wait for approval in one step
     * try {
     *   const loginReq = await tq.login.request({
     *     externalUsername: 'user@company.com',
     *     type: 'LOGIN'
     *   });
     *
     *   const result = await tq.login.waitForApproval({
     *     requestId: loginReq.requestId,
     *     timeout: 30000  // Wait up to 30 seconds
     *   });
     *
     *   if (result.approved) {
     *     // ✅ User approved — proceed
     *     proceedWithAction();
     *   }
     * } catch (err) {
     *   if (err instanceof TouchQueRejectedError) {
     *     // ❌ User rejected — cancel the action
     *   } else if (err instanceof TouchQueTimeoutError) {
     *     // ⏰ User didn't respond in time
     *   }
     * }
     */
    waitForApproval(options: WaitForApprovalOptions): Promise<WaitForApprovalResult>;
    /**
     * Convenience: Send a 2FA request AND wait for approval in one call.
     *
     * Perfect for protecting any action with a single function call.
     *
     * @throws {TouchQueRejectedError} User rejected
     * @throws {TouchQueTimeoutError} User didn't respond in time
     *
     * @example
     * // Protect an action with 2FA — ONE LINE!
     * const result = await tq.login.verify({
     *   externalUsername: 'user@company.com',
     *   type: 'action_type_slug_or_id',
     *   referenceId: 'action_789'
     * });
     * // If we reach here, user approved ✅
     * executeAction();
     */
    verify(options: LoginRequestOptions & {
        timeout?: number;
        pollInterval?: number;
    }): Promise<WaitForApprovalResult & {
        requestId: string;
        challengeCode?: string;
    }>;
    /**
     * Approve a pending 2FA request using a Recovery Code.
     * Useful when a user loses their phone and needs to bypass 2FA
     * using one of the backup codes generated during setup.
     */
    approveWithRecoveryCode(options: {
        requestId: string;
        code: string;
    }): Promise<{
        success: boolean;
        message: string;
    }>;
    /**
     * Report a request you later learned was fraud — a chargeback, a confirmed
     * account takeover, a scam the user was talked into. TouchQue's risk engine
     * learns from it (it is the strongest signal it gets) and the report is
     * kept in your audit log. The request's status does not change. Safe to
     * call more than once: a repeat answers `alreadyReported: true`.
     */
    reportFraud(requestId: string, options?: ReportFraudOptions): Promise<ReportFraudResponse>;
}
type FraudReason = 'chargeback' | 'account_takeover' | 'social_engineering' | 'other';
interface ReportFraudOptions {
    /** Default 'other'. */
    reason?: FraudReason;
    /** Free text for your audit log, at most 500 characters. */
    note?: string;
}
interface ReportFraudResponse {
    reported: true;
    /** true when this request had already been reported. */
    alreadyReported: boolean;
    requestId: string;
}

/**
 * In-process `WebhookReplayCache`. Entries expire after their TTL and the map
 * is capped, so it can't grow without bound. Not shared between processes.
 */
declare class MemoryWebhookReplayCache implements WebhookReplayCache {
    private readonly maxEntries;
    private readonly seen;
    constructor(maxEntries?: number);
    checkAndSet(jti: string, ttlSeconds: number): boolean;
}
declare class Webhook {
    private readonly apiSecret;
    constructor(apiSecret: string);
    /**
     * Verify that an incoming webhook request is genuinely from TouchQue and
     * return its parsed payload. Throws `TouchQueWebhookSignatureError` if the
     * signature is invalid, the body is malformed, or the webhook is stale.
     *
     * **Always verify before processing.** Pass `replayCache` (e.g. a shared
     * `MemoryWebhookReplayCache`, or your own Redis-backed one) so a replayed
     * delivery throws `TouchQueWebhookReplayError` instead of re-running your
     * logic; without it, de-duplicate on `payload.jti` yourself.
     *
     * @throws {TouchQueWebhookSignatureError}
     *
     * @example
     * // Express.js — mount with a raw body parser on this route
     * app.post('/webhooks/touchque', express.raw({ type: 'application/json' }), (req, res) => {
     *   try {
     *     const event = tq.webhook.verify({
     *       rawBody: req.body.toString('utf8'),
     *       signature: req.headers['x-signature'] as string,
     *       replayCache, // const replayCache = new MemoryWebhookReplayCache();
     *     });
     *     // ... handle event
     *     res.sendStatus(200);
     *   } catch (err) {
     *     if (err instanceof TouchQueWebhookReplayError) return res.sendStatus(200); // already handled
     *     res.sendStatus(403); // not from TouchQue, tampered, or stale
     *   }
     * });
     */
    verify(options: VerifyWebhookOptions): WebhookPayload;
    /**
     * Check a webhook signature without throwing. Returns `true` / `false`.
     *
     * @example
     * if (tq.webhook.isValid({ rawBody, signature })) {
     *   // process
     * }
     */
    isValid(options: VerifyWebhookOptions): boolean;
}

interface WebAuthnRegisterOptionsRequest {
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
type WebAuthnRegistrationOptions = Record<string, unknown>;
interface WebAuthnRegisterVerifyRequest {
    externalUsername: string;
    /** The RegistrationResponseJSON returned by navigator.credentials.create(). */
    response: Record<string, unknown>;
    /** Optional display label for this credential (e.g. "MacBook Touch ID"). */
    label?: string;
}
interface WebAuthnRegisterVerifyResponse {
    verified: boolean;
    credentialId: string;
}
interface WebAuthnAuthenticateOptionsRequest {
    /** The pending LoginRequest id this WebAuthn assertion will approve. */
    requestId: string;
}
/** Passed straight through to navigator.credentials.get() in the browser. */
type WebAuthnAuthenticationOptions = Record<string, unknown>;
interface WebAuthnAuthenticateVerifyRequest {
    requestId: string;
    /** The AuthenticationResponseJSON returned by navigator.credentials.get(). */
    response: Record<string, unknown>;
}
interface WebAuthnAuthenticateVerifyResponse {
    success: boolean;
    message: string;
    /** The user whose login request was approved (set by TouchQue, not by the browser). */
    externalUsername?: string;
    requestId?: string;
}
interface WebAuthnPrimaryOptionsRequest {
    /** The account to authenticate (username-first passwordless-primary login). */
    externalUsername: string;
}
interface WebAuthnPrimaryOptionsResponse {
    /** Opaque id tying the browser assertion back to this attempt. */
    attemptId: string;
    /** Passed straight through to navigator.credentials.get() in the browser. */
    options: Record<string, unknown>;
}
interface WebAuthnPrimaryVerifyRequest {
    attemptId: string;
    /** The AuthenticationResponseJSON returned by navigator.credentials.get(). */
    response: Record<string, unknown>;
}
interface WebAuthnPrimaryVerifyResponse {
    success: boolean;
    /** Present when success:false — risk/policy demands a step-up (push/number-match). */
    requiresStepUp?: boolean;
    externalUsername: string;
    riskScore: number;
    /** Present when success:true — the CONFIRMED LoginRequest id. */
    requestId?: string;
}
interface WebAuthnCredentialSummary {
    id: string;
    credentialId: string;
    deviceType: string | null;
    backedUp: boolean;
    label: string | null;
    createdAt: string;
    lastUsedAt: string | null;
}
declare class WebAuthn {
    private readonly http;
    constructor(http: HttpClient);
    /**
     * Step 1 of registering a passkey: get options for `navigator.credentials.create()`.
     *
     * @example
     * const options = await tq.webauthn.registerOptions({ externalUsername: 'user@company.com' });
     * // send `options` to the browser, call navigator.credentials.create({ publicKey: options })
     */
    registerOptions(options: WebAuthnRegisterOptionsRequest): Promise<WebAuthnRegistrationOptions>;
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
    registerVerify(options: WebAuthnRegisterVerifyRequest): Promise<WebAuthnRegisterVerifyResponse>;
    /**
     * Step 1 of approving a pending login with a passkey: get options for
     * `navigator.credentials.get()`, scoped to a specific `requestId` (from
     * `tq.login.request()`).
     *
     * @example
     * const loginReq = await tq.login.request({ externalUsername: 'user@company.com', type: 'LOGIN' });
     * const options = await tq.webauthn.authenticateOptions({ requestId: loginReq.requestId });
     */
    authenticateOptions(options: WebAuthnAuthenticateOptionsRequest): Promise<WebAuthnAuthenticationOptions>;
    /**
     * Step 2: verify the browser's assertion — approves the LoginRequest on success.
     *
     * @example
     * const result = await tq.webauthn.authenticateVerify({
     *   requestId: loginReq.requestId,
     *   response: browserAuthenticationResponseJSON,
     * });
     */
    authenticateVerify(options: WebAuthnAuthenticateVerifyRequest): Promise<WebAuthnAuthenticateVerifyResponse>;
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
    primaryOptions(options: WebAuthnPrimaryOptionsRequest): Promise<WebAuthnPrimaryOptionsResponse>;
    /**
     * Step 2 of a passwordless-primary login: verify the browser assertion.
     *
     * On `success:true` the returned `requestId` is a CONFIRMED LoginRequest —
     * the login is done. On `success:false` with `requiresStepUp:true`, risk
     * or policy demands a second factor: start the normal `tq.login.request()`
     * / number-match flow instead of trusting this assertion alone.
     */
    primaryVerify(options: WebAuthnPrimaryVerifyRequest): Promise<WebAuthnPrimaryVerifyResponse>;
    /**
     * List a user's registered WebAuthn credentials (labels/metadata only, no key material).
     */
    listCredentials(options: {
        externalUsername: string;
    }): Promise<{
        credentials: WebAuthnCredentialSummary[];
    }>;
    /**
     * Remove a registered credential (e.g. the user lost that device).
     * Pass `externalUsername` so only that user's credential can be removed.
     */
    deleteCredential(credentialRecordId: string, options?: {
        externalUsername?: string;
    }): Promise<{
        deleted: boolean;
    }>;
}

declare class Offline {
    private readonly http;
    constructor(http: HttpClient);
    /**
     * Issue a challenge (encrypted for the user's phone) and get the QR to show.
     *
     * `qrDataUrl` is a ready-to-render PNG (`<img src={qrDataUrl}>`); `qr` is the
     * raw text if you draw the QR yourself. The challenge expires after
     * `expiresInSeconds` (default 120) — enforced by TouchQue, not by the phone.
     *
     * @example
     * const ch = await tq.offline.challenge({
     *   externalUsername: 'user@company.com',
     *   type: 'WITHDRAW',
     *   clientIp: req.ip,
     *   userAgent: req.get('user-agent'),
     *   details: { Amount: '1,250.00 USD', Recipient: 'Jane Doe' },
     * });
     * // show ch.qrDataUrl (and ch.challengeCode under it when present), then later:
     * const { approved } = await tq.offline.verify({ challengeId: ch.challengeId, code });
     */
    challenge(options: OfflineChallengeOptions): Promise<OfflineChallengeResponse>;
    /**
     * Check the code the user typed. Resolves `{ approved: true }` on success and
     * `{ approved: false, reason }` for a wrong / expired / used / locked
     * challenge (never throws for those); other failures (network, 5xx) throw.
     * A challenge locks after 5 wrong codes and a code works once.
     */
    verify(options: OfflineVerifyOptions): Promise<OfflineVerifyResult>;
    /**
     * Check a time-based code typed from the app (no QR). Requires the workspace
     * policy `offlineTotpEnabled`. Pass `type` when the code is for a specific
     * action so critical actions are refused.
     */
    verifyTotp(options: OfflineTotpVerifyOptions): Promise<OfflineVerifyResult>;
    private notApprovedAsResult;
}

interface ActionType {
    id: string;
    type: string;
    name: string;
    description: string;
    /** Critical actions always use number matching and never accept recovery / offline time-based codes. */
    critical: boolean;
    active: boolean;
}
interface DefineActionOptions {
    /** Shown on the phone and in the Dashboard (default: the slug). */
    name?: string;
    description?: string;
    /** Leave undefined to keep what the Dashboard has. */
    critical?: boolean;
}
declare class Actions {
    private readonly http;
    constructor(http: HttpClient);
    /**
     * Creates the action type, or updates its name/description/critical flag.
     * Safe to call on every start-up: it never re-enables a type an admin disabled.
     *
     * @example
     * await tq.actions.define('SEND_MONEY', { name: 'Send money', critical: true });
     */
    define(type: string, options?: DefineActionOptions): Promise<ActionType>;
    list(): Promise<ActionType[]>;
}

type StepState = 'waiting' | 'approved' | 'rejected' | 'expired' | 'enroll' | 'passkey_required' | 'offline' | 'blocked' | 'frozen' | 'rate_limited';
interface Step {
    state: StepState;
    requestId?: string;
    /** Number matching: show this on screen; the user picks it on the phone. */
    number?: string;
    expiresAt?: string;
    /** Transaction details the phone shows (amount, recipient…). */
    details?: Array<{
        label: string;
        value: string;
    }>;
    enroll?: {
        qrCodeDataUrl: string;
        recoveryCodes?: string[];
        expiresAt?: string;
    };
    offline?: {
        challengeId: string;
        qrDataUrl?: string;
        expiresAt?: string;
        totpAvailable?: boolean;
        attemptsLeft?: number;
        /** Number matching: print this under the QR; the phone offers it among two decoys. */
        challengeCode?: string;
    };
    reason?: string;
    retryAfter?: number;
    assurance?: ApprovalAssurance;
}
interface StartOptions {
    /** Your user's id in YOUR system (email, user id…). */
    user: string;
    /** Shown on the phone and bound to the approval. Build it from server-side state. */
    details?: LoginRequestDetails;
    /** Your own transaction id, bound to the approval. */
    referenceId?: string;
    /** End user's IP / user agent (location and device shown on the phone). */
    ip?: string;
    userAgent?: string;
    /** Show an enrollment QR when the user has not linked a phone yet (default true). */
    enroll?: boolean;
}
interface Approval {
    requestId: string;
    user: string;
    action: string;
    /** How it was approved; `phishingResistant` is true only for passkeys. */
    assurance: ApprovalAssurance | null;
    confirmedVia: string | null;
    /** Device-signed proof of what was approved (see verifyApprovalProof). */
    approvalProof: unknown;
}
/** Normalizes details the same way the API does: object or [{label, value}] → [{label, value}] strings. */
declare function normalizeDetails(details?: LoginRequestDetails): Array<{
    label: string;
    value: string;
}>;
interface CompleteExpectations {
    user: string;
    action: string;
    details?: LoginRequestDetails;
    referenceId?: string;
}
interface GuardTokenClaims {
    u: string;
    a: string;
    d: string;
    r: string | null;
    st: StepState;
    rid?: string;
    n?: string;
    oc?: string;
    exp: number;
}
declare function signGuardToken(apiSecret: string, claims: GuardTokenClaims): string;
declare function verifyGuardToken(apiSecret: string, token: unknown): GuardTokenClaims | null;

/**
 * Base error class for all TouchQue SDK errors.
 */
declare class TouchQueError extends Error {
    constructor(message: string);
}
/**
 * Thrown when the TouchQue API returns a non-2xx HTTP response.
 * Contains the HTTP status code and the raw API error data.
 */
declare class TouchQueAPIError extends TouchQueError {
    readonly status: number;
    readonly code: string | undefined;
    readonly data: TouchQueErrorData;
    constructor(status: number, data: TouchQueErrorData);
}
/**
 * Thrown when a request never reached TouchQue at all — no HTTP response
 * was received (connection refused, DNS failure, client-side timeout).
 * Distinct from TouchQueAPIError, which means TouchQue DID respond, just
 * with a non-2xx status. A TouchQueNetworkError is generally safe to
 * retry; a TouchQueAPIError often is not (e.g. a validation error will
 * fail again identically).
 */
declare class TouchQueNetworkError extends TouchQueError {
    readonly code: string | undefined;
    constructor(message: string, code?: string);
}
/**
 * Thrown when the waitForApproval() polling method times out
 * before the user approves or rejects the request.
 */
declare class TouchQueTimeoutError extends TouchQueError {
    readonly requestId: string;
    constructor(requestId: string, timeoutMs: number);
}
/**
 * Thrown when a login request is explicitly rejected by the user.
 */
declare class TouchQueRejectedError extends TouchQueError {
    readonly requestId: string;
    constructor(requestId: string);
}
/**
 * Thrown when webhook signature verification fails.
 * This means the incoming webhook is not from TouchQue (potential forgery).
 */
declare class TouchQueWebhookSignatureError extends TouchQueError {
    constructor();
}
/**
 * Thrown when a correctly signed webhook has already been accepted once (same
 * `jti`). Usually a TouchQue retry of a delivery you already processed —
 * answer 200 so it stops, but do not run your side effects again. Extends
 * `TouchQueWebhookSignatureError`, so existing `catch` blocks still reject it.
 */
declare class TouchQueWebhookReplayError extends TouchQueWebhookSignatureError {
    readonly jti: string;
    constructor(jti: string);
}
/**
 * Thrown when SDK is used before being properly configured.
 */
declare class TouchQueConfigError extends TouchQueError {
    constructor(message: string);
}
/**
 * Thrown by `login.verify()` when the workspace requires a phishing-resistant
 * factor for this action: no push was sent. Approve `requestId` with a passkey
 * in the browser (`@touchque/web` `passkeys.approveLogin({ requestId })`, relayed
 * by `touchqueRouter`'s `/passkey/login/*` routes), then check `login.status()`.
 */
declare class TouchQuePasskeyRequiredError extends TouchQueError {
    readonly requestId: string;
    constructor(requestId: string);
}

type MaybePromise$1<T> = T | Promise<T>;
interface TouchQueMiddlewareOptions {
    /** Client to use (default: one built from TQ_API_KEY / TQ_API_SECRET). */
    client?: TouchQue;
    /**
     * Who is approving. Default: `req.user.email || req.user.id || req.user.username`
     * (set by your auth). For the login step, return the user who just passed
     * your password check, e.g. `(req) => req.session.passwordOk`.
     */
    user?: (req: Request$1) => MaybePromise$1<string | undefined | null>;
    /** What the phone shows and the approval is bound to (amount, recipient…). Build it from server-side state. */
    details?: (req: Request$1) => MaybePromise$1<LoginRequestDetails | undefined>;
    /** Your own transaction id, bound to the approval. */
    referenceId?: (req: Request$1) => MaybePromise$1<string | undefined>;
    /** @deprecated use `user` */
    getUserId?: (req: Request$1) => string | undefined;
    /** @deprecated use `details` */
    getDetails?: (req: Request$1) => MaybePromise$1<LoginRequestDetails | undefined>;
    /** @deprecated use `referenceId` */
    getReferenceId?: (req: Request$1) => string | undefined;
    /** @deprecated no effect — the page polls instead of the server holding the request open */
    timeout?: number;
}
/**
 * Protects a route with TouchQue approval.
 *
 * @example
 * app.post('/transfer',
 *   requireTouchQue('SEND_MONEY', { details: (req) => ({ Amount: `${req.body.amount} EUR`, To: req.body.iban }) }),
 *   (req, res) => res.json({ ok: true }));
 */
declare function requireTouchQue(action: string, options?: TouchQueMiddlewareOptions): (req: Request$1, res: Response$1, next: NextFunction) => Promise<void>;
/** @deprecated pass the client as `options.client` (or rely on the environment) */
declare function requireTouchQue(client: TouchQue, action: string, options?: TouchQueMiddlewareOptions): (req: Request$1, res: Response$1, next: NextFunction) => Promise<void>;

type MaybePromise<T> = T | Promise<T>;
interface WithTouchQueOptions {
    client?: TouchQue;
    /** Who is approving — read it from YOUR session (required). */
    user: (req: Request) => MaybePromise<string | undefined | null>;
    /** What the phone shows and the approval is bound to. Build it from server-side state. */
    details?: (req: Request) => MaybePromise<LoginRequestDetails | undefined>;
    referenceId?: (req: Request) => MaybePromise<string | undefined>;
    /** End user's IP (default: first X-Forwarded-For hop, which your platform must set). */
    ip?: (req: Request) => string | undefined;
}
declare function withTouchQue<Ctx = unknown>(action: string, handler: (req: Request, ctx: Ctx & {
    touchque: Approval;
}) => MaybePromise<Response>, options: WithTouchQueOptions): (req: Request, ctx?: Ctx) => Promise<Response>;

declare const GUARD_HEADERS: {
    readonly token: "x-touchque-token";
    readonly offline: "x-touchque-offline";
    readonly code: "x-touchque-code";
    readonly codeType: "x-touchque-code-type";
};
interface GuardInput {
    /** The user in YOUR system; undefined = not signed in → 401. */
    user?: string;
    action: string;
    details?: LoginRequestDetails;
    referenceId?: string;
    ip?: string;
    userAgent?: string;
    token?: string;
    offline?: boolean;
    code?: string;
    codeType?: string;
}
interface GuardBody {
    touchque: Step;
    token?: string;
    error?: {
        code: string;
        message: string;
    };
}
type GuardResult = {
    approved: Approval;
    status: 200;
    body?: undefined;
} | {
    approved?: undefined;
    status: number;
    body: GuardBody;
};
declare function runGuard(tq: TouchQue, input: GuardInput): Promise<GuardResult>;

interface RateLimitOptions {
    /** Window length in ms. Default 60000. */
    windowMs?: number;
    /** Requests per client IP per route per window. Default 20. */
    perIp?: number;
    /** Requests per username per route per window (routes that name a user). Default 5. */
    perUser?: number;
}

interface TouchQueRouterOptions {
    /**
     * Resolve the signed-in user's identifier for the "auth required" routes
     * (enrollment, passkey registration/management). Return `undefined` if
     * there is no signed-in user — the route responds 401.
     */
    getUserId: (req: Request$1) => string | undefined;
    /**
     * STRONGLY RECOMMENDED. The user who has already passed your first factor
     * (e.g. the password step stored in the session). When set, POST /login,
     * POST /offline/challenge and POST /offline/totp use this user and IGNORE any
     * username in the request body; if it returns nothing they answer 401
     * FIRST_FACTOR_REQUIRED. Without it, anyone can type any user's email and
     * make TouchQue push to that user's phone (push-bombing) or spend that
     * user's offline attempts.
     */
    getLoginUser?: (req: Request$1) => string | undefined | Promise<string | undefined>;
    /**
     * Built-in limits for the pre-auth routes (per client IP and per username,
     * per route). On by default: 20 requests per IP and 5 per username per
     * minute. Pass `false` if you already rate limit in front of this router.
     * `req.ip` must be the real client (configure Express `trust proxy`).
     */
    rateLimit?: RateLimitOptions | false;
    /**
     * The offline routes (/offline/challenge, /offline/verify, /offline/totp)
     * answer 403 OFFLINE_REQUIRES_FIRST_FACTOR unless `getLoginUser` is set.
     * Set this to `true` only if you really want them to trust the username in
     * the request body (e.g. your own gateway already authenticated the user).
     */
    allowOfflineWithoutFirstFactor?: boolean;
    /** LoginType passed to the classic-2FA POST /login route. Default: 'LOGIN'. */
    actionType?: string;
    /** @deprecated no effect — POST /login no longer holds the request open; the page polls with the token. */
    loginTimeout?: number;
    /**
     * Optional transaction context for the classic-2FA POST /login push,
     * shown on the approval screen (see `LoginRequestOptions.details`). Build
     * it from your own server-side state — anything read from `req.body` here
     * is attacker-controlled.
     */
    getDetails?: (req: Request$1) => LoginRequestDetails | undefined | Promise<LoginRequestDetails | undefined>;
    /**
     * Called right before this router sends its own success response for
     * POST /login (once approved) or POST /passkey/authenticate/verify (once
     * verified) — the one place a partner almost always needs to do
     * something (open a session cookie, etc.). Mutate `res` here (e.g.
     * `res.cookie(...)`); do not call `res.json()`/`res.send()` yourself —
     * the router does that right after.
     */
    onAuthenticated?: (req: Request$1, res: Response$1, info: {
        externalUsername: string;
        requestId?: string;
        via: 'login' | 'passkey' | 'offline' | 'offline-totp';
    }) => void | Promise<void>;
}
declare function touchqueRouter(tq: TouchQue, options: TouchQueRouterOptions): Router;

declare const DEFAULT_BASE_URL = "https://api.touchque.com";
declare class TouchQue {
    readonly auth: Auth;
    readonly login: Login;
    /** Webhook signature verification */
    readonly webhook: Webhook;
    /** WebAuthn/FIDO2 (passkey) registration and login approval */
    readonly webauthn: WebAuthn;
    /** Offline Sign — QR challenge / typed code approvals that work with the phone offline */
    readonly offline: Offline;
    /** Action types (LOGIN, SEND_MONEY…) */
    readonly actions: Actions;
    /**
     * @param config - Optional. Falls back to the environment:
     *   TQ_API_KEY, TQ_API_SECRET, TQ_API_URL (default https://api.touchque.com).
     *
     * @example
     * const tq = new TouchQue();                       // from the environment
     * const tq = new TouchQue({ apiKey, apiSecret });  // explicit
     */
    constructor(config?: Partial<TouchQueConfig>);
    /**
     * Starts an approval and returns immediately — show the step in your UI.
     * `waiting` + `number`: show the number, the user picks it on the phone.
     * `enroll`: show `enroll.qrCodeDataUrl` so the user links the TouchQue app first.
     *
     * @example
     * const step = await tq.start('SEND_MONEY', { user: 'jane@acme.com', details: { Amount: '250 EUR' } });
     */
    start(action: string, options: StartOptions): Promise<Step>;
    /** Where a started approval is now: waiting, approved, rejected, expired… */
    check(requestId: string): Promise<Step>;
    /**
     * Uses an approved request exactly once, after checking it is for this user,
     * action and transaction. Call it right before doing the protected thing.
     */
    complete(requestId: string, expect: CompleteExpectations): Promise<Approval>;
    /**
     * Wrap and protect any async function with TouchQue 2FA.
     *
     * @param fn The function to protect
     * @param options Configuration for extracting the user identity and 2FA type
     * @returns A new function that requires 2FA approval before executing the original function
     *
     * @example
     * const secureWithdraw = tq.protect(processWithdraw, {
     *   type: 'WITHDRAW',
     *   getUserIdentifier: (username, amount) => username
     * });
     *
     * await secureWithdraw("user@company.com", 500); // Prompts 2FA automatically
     */
    protect<TArgs extends any[], TReturn>(fn: (...args: TArgs) => Promise<TReturn> | TReturn, options: ProtectOptions<TArgs>): (...args: TArgs) => Promise<TReturn>;
}

/** The client built from TQ_API_KEY / TQ_API_SECRET, created on first use. */
declare function getDefaultClient(): TouchQue;

export { type ActionType, Actions, type Approval, type ApprovalAssurance, type ApprovalProof, Auth, type CompleteExpectations, DEFAULT_BASE_URL, type DefineActionOptions, type FraudReason, GUARD_HEADERS, type GenerateSecretOptions, type GenerateSecretResponse, type GetUserResponse, type GuardBody, type GuardInput, type GuardResult, Login, type LoginRequestDetails, type LoginRequestOptions, type LoginRequestResponse, type LoginStatus, type LoginStatusResponse, type LoginType, MemoryWebhookReplayCache, Offline, type OfflineChallengeOptions, type OfflineChallengeResponse, type OfflineTotpVerifyOptions, type OfflineVerifyOptions, type OfflineVerifyResult, type ProtectOptions, type RateLimitOptions, type ReportFraudOptions, type ReportFraudResponse, type ResetSecretOptions, type ResetSecretResponse, type StartOptions, type Step, type StepState, TouchQue, TouchQueAPIError, type TouchQueConfig, TouchQueConfigError, TouchQueError, type TouchQueErrorData, type TouchQueMiddlewareOptions, TouchQueNetworkError, TouchQuePasskeyRequiredError, TouchQueRejectedError, type TouchQueRouterOptions, TouchQueTimeoutError, TouchQueWebhookReplayError, TouchQueWebhookSignatureError, type UnlinkSecretOptions, type UnlinkSecretResponse, type ValidateSecretOptions, type ValidateSecretResponse, type VerifyApprovalProofOptions, type VerifyWebhookOptions, type WaitForApprovalOptions, type WaitForApprovalResult, WebAuthn, type WebAuthnAuthenticateOptionsRequest, type WebAuthnAuthenticateVerifyRequest, type WebAuthnAuthenticateVerifyResponse, type WebAuthnAuthenticationOptions, type WebAuthnCredentialSummary, type WebAuthnPrimaryOptionsRequest, type WebAuthnPrimaryOptionsResponse, type WebAuthnPrimaryVerifyRequest, type WebAuthnPrimaryVerifyResponse, type WebAuthnRegisterOptionsRequest, type WebAuthnRegisterVerifyRequest, type WebAuthnRegisterVerifyResponse, type WebAuthnRegistrationOptions, Webhook, type WebhookPayload, type WebhookReplayCache, type WithTouchQueOptions, detailsDigest, getDefaultClient, normalizeDetails, requireTouchQue, runGuard, signGuardToken, touchqueRouter, verifyApprovalProof, verifyGuardToken, withTouchQue };
