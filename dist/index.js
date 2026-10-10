"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var index_exports = {};
__export(index_exports, {
  Actions: () => Actions,
  Auth: () => Auth,
  DEFAULT_BASE_URL: () => DEFAULT_BASE_URL,
  GUARD_HEADERS: () => GUARD_HEADERS,
  Login: () => Login,
  MemoryWebhookReplayCache: () => MemoryWebhookReplayCache,
  Offline: () => Offline,
  TouchQue: () => TouchQue3,
  TouchQueAPIError: () => TouchQueAPIError,
  TouchQueConfigError: () => TouchQueConfigError,
  TouchQueError: () => TouchQueError,
  TouchQueNetworkError: () => TouchQueNetworkError,
  TouchQuePasskeyRequiredError: () => TouchQuePasskeyRequiredError,
  TouchQueRejectedError: () => TouchQueRejectedError,
  TouchQueTimeoutError: () => TouchQueTimeoutError,
  TouchQueWebhookReplayError: () => TouchQueWebhookReplayError,
  TouchQueWebhookSignatureError: () => TouchQueWebhookSignatureError,
  WebAuthn: () => WebAuthn,
  Webhook: () => Webhook,
  detailsDigest: () => detailsDigest,
  getDefaultClient: () => getDefaultClient,
  normalizeDetails: () => normalizeDetails,
  requireTouchQue: () => requireTouchQue,
  runGuard: () => runGuard,
  signGuardToken: () => signGuardToken,
  touchqueRouter: () => touchqueRouter,
  verifyApprovalProof: () => verifyApprovalProof,
  verifyGuardToken: () => verifyGuardToken,
  withTouchQue: () => withTouchQue
});
module.exports = __toCommonJS(index_exports);

// src/core/HttpClient.ts
var import_axios = __toESM(require("axios"));
var crypto = __toESM(require("crypto"));

// src/errors.ts
var TouchQueError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "TouchQueError";
  }
};
var TouchQueAPIError = class extends TouchQueError {
  status;
  code;
  data;
  constructor(status, data) {
    const message = data.message || data.error || `TouchQue API Error: HTTP ${status}`;
    super(message);
    this.name = "TouchQueAPIError";
    this.status = status;
    this.code = data.code;
    this.data = data;
  }
};
var TouchQueNetworkError = class extends TouchQueError {
  code;
  constructor(message, code) {
    super(`TouchQue: network request failed${code ? ` (${code})` : ""} \u2014 ${message}`);
    this.name = "TouchQueNetworkError";
    this.code = code;
  }
};
var TouchQueTimeoutError = class extends TouchQueError {
  requestId;
  constructor(requestId, timeoutMs) {
    super(
      `TouchQue: Request '${requestId}' was not approved within ${timeoutMs / 1e3}s. The user did not respond in time.`
    );
    this.name = "TouchQueTimeoutError";
    this.requestId = requestId;
  }
};
var TouchQueRejectedError = class extends TouchQueError {
  requestId;
  constructor(requestId) {
    super(
      `TouchQue: Request '${requestId}' was rejected by the user.`
    );
    this.name = "TouchQueRejectedError";
    this.requestId = requestId;
  }
};
var TouchQueWebhookSignatureError = class extends TouchQueError {
  constructor() {
    super(
      "TouchQue: Webhook signature verification failed. This request did not come from TouchQue or the payload was tampered."
    );
    this.name = "TouchQueWebhookSignatureError";
  }
};
var TouchQueWebhookReplayError = class extends TouchQueWebhookSignatureError {
  jti;
  constructor(jti) {
    super();
    this.message = "TouchQue: This webhook (jti) was already accepted.";
    this.name = "TouchQueWebhookReplayError";
    this.jti = jti;
  }
};
var TouchQueConfigError = class extends TouchQueError {
  constructor(message) {
    super(`TouchQue Config Error: ${message}`);
    this.name = "TouchQueConfigError";
  }
};
var TouchQuePasskeyRequiredError = class extends TouchQueError {
  requestId;
  constructor(requestId) {
    super(`TouchQue: Request '${requestId}' must be approved with a passkey (phishing-resistant policy); no push was sent.`);
    this.name = "TouchQuePasskeyRequiredError";
    this.requestId = requestId;
  }
};

// src/core/HttpClient.ts
var TEN_MB = 10 * 1024 * 1024;
function assertSafeBaseUrl(baseUrl) {
  let url;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new TouchQueConfigError(`baseUrl is not a valid URL: ${baseUrl}`);
  }
  if (url.protocol === "https:") return;
  if (url.protocol === "http:") {
    const host = url.hostname.toLowerCase();
    if (host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]") return;
    throw new TouchQueConfigError(
      `Refusing to use a plaintext http:// baseUrl for "${url.hostname}". The API key and request signature would be sent in the clear \u2014 use https://.`
    );
  }
  throw new TouchQueConfigError(`baseUrl must be http(s): ${baseUrl}`);
}
function buildQuery(params) {
  if (!params) return "";
  const keys = Object.keys(params).filter((k) => params[k] !== void 0 && params[k] !== null);
  if (keys.length === 0) return "";
  keys.sort();
  const parts = keys.map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(String(params[k]))}`);
  return `?${parts.join("&")}`;
}
var HttpClient = class {
  client;
  apiKey;
  apiSecret;
  constructor(config) {
    if (!config.apiKey || typeof config.apiKey !== "string") {
      throw new TouchQueConfigError("apiKey is required and must be a string");
    }
    if (!config.apiSecret || typeof config.apiSecret !== "string") {
      throw new TouchQueConfigError("apiSecret is required and must be a string");
    }
    if (!config.apiKey.startsWith("tq_")) {
      throw new TouchQueConfigError(
        'apiKey must start with "tq_". Did you accidentally swap apiKey and apiSecret?'
      );
    }
    this.apiKey = config.apiKey;
    this.apiSecret = config.apiSecret;
    const baseURL = config.baseUrl || "https://api.touchque.com";
    assertSafeBaseUrl(baseURL);
    this.client = import_axios.default.create({
      baseURL,
      timeout: config.timeout || 1e4,
      headers: { "Content-Type": "application/json" },
      // An API endpoint should never redirect; a redirect to another host
      // could leak the signed auth headers.
      maxRedirects: 0,
      // Cap the response/request size so a misbehaving or spoofed endpoint
      // can't exhaust memory.
      maxContentLength: TEN_MB,
      maxBodyLength: TEN_MB
    });
  }
  /**
   * Canonical signature.
   * Format: HMAC(apiSecret, "METHOD:pathWithQuery:timestamp:nonce:bodyHash")
   *
   * `pathWithQuery` includes the sorted query string so GET/DELETE query
   * params are covered by the signature (older SDKs signed the path only;
   * the backend accepts either form).
   */
  sign(method, pathWithQuery, body, timestamp, nonce) {
    const bodyHash = crypto.createHash("sha256").update(body || "").digest("hex");
    const message = `${method.toUpperCase()}:${pathWithQuery}:${timestamp}:${nonce}:${bodyHash}`;
    return crypto.createHmac("sha256", this.apiSecret).update(message).digest("hex");
  }
  generateNonce() {
    return crypto.randomBytes(16).toString("hex");
  }
  authHeaders(method, pathWithQuery, body) {
    const timestamp = Date.now().toString();
    const nonce = this.generateNonce();
    return {
      "x-api-key": this.apiKey,
      "x-signature": this.sign(method, pathWithQuery, body, timestamp, nonce),
      "x-timestamp": timestamp,
      "x-nonce": nonce
    };
  }
  async post(path, body = {}) {
    const bodyStr = JSON.stringify(body);
    try {
      const response = await this.client.post(path, bodyStr, {
        headers: this.authHeaders("POST", path, bodyStr)
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }
  async get(path, params) {
    const query = buildQuery(params);
    try {
      const response = await this.client.get(path + query, {
        headers: this.authHeaders("GET", path + query, "")
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }
  async delete(path) {
    try {
      const response = await this.client.delete(path, {
        headers: this.authHeaders("DELETE", path, "")
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }
  handleError(error) {
    if (import_axios.default.isAxiosError(error)) {
      const axiosErr = error;
      if (!axiosErr.response) {
        return new TouchQueNetworkError(axiosErr.message, axiosErr.code);
      }
      const status = axiosErr.response.status;
      const data = axiosErr.response.data || {};
      return new TouchQueAPIError(status, {
        error: data.error,
        message: data.message,
        code: data.code,
        reason: typeof data.reason === "string" ? data.reason : void 0,
        attemptsLeft: typeof data.attemptsLeft === "number" ? data.attemptsLeft : void 0,
        retryAfter: typeof data.retryAfter === "number" ? data.retryAfter : Number(axiosErr.response.headers?.["retry-after"]) || void 0
      });
    }
    return new TouchQueAPIError(500, {
      message: error instanceof Error ? error.message : "Unknown error"
    });
  }
};

// src/resources/Auth.ts
var Auth = class {
  constructor(http) {
    this.http = http;
  }
  http;
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
  async generateSecret(options) {
    return this.http.post("/auth/generate-secret", {
      externalUsername: options.externalUsername
    });
  }
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
  async resetSecret(options) {
    return this.http.post("/auth/secret/reset", {
      externalUsername: options.externalUsername
    });
  }
  /**
   * Validate a secret code.
   * Useful if you want to verify the user entered the correct setup secret.
   * Note: The backend allows this without an API key, but the SDK sends it for consistency.
   */
  async validateSecret(options) {
    return this.http.post("/auth/secret/validate", {
      secret: options.secret
    });
  }
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
  async getUser(options) {
    return this.http.get(`/users/${encodeURIComponent(options.externalUsername)}`);
  }
};

// src/resources/Login.ts
var Login = class {
  constructor(http) {
    this.http = http;
  }
  http;
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
  async request(options) {
    return this.http.post("/login/request", {
      externalUsername: options.externalUsername,
      type: options.type,
      ...options.referenceId && { referenceId: options.referenceId },
      ...options.clientIp && { clientIp: options.clientIp },
      ...options.userAgent && { userAgent: options.userAgent },
      ...options.details && { details: options.details },
      ...options.requireBiometric && { requireBiometric: options.requireBiometric },
      ...options.requireNumberMatch && { requireNumberMatch: options.requireNumberMatch }
    });
  }
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
  async status(requestId) {
    return this.http.get(`/login/status/${encodeURIComponent(requestId)}`);
  }
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
  async waitForApproval(options) {
    const timeout = options.timeout || 3e4;
    const pollInterval = options.pollInterval || 400;
    const startTime = Date.now();
    while (Date.now() - startTime < timeout) {
      const { status } = await this.status(options.requestId);
      if (status === "CONFIRMED") {
        return { approved: true, status };
      }
      if (status === "REJECTED") {
        throw new TouchQueRejectedError(options.requestId);
      }
      if (status === "EXPIRED") {
        throw new TouchQueTimeoutError(options.requestId, timeout);
      }
      await new Promise((resolve) => setTimeout(resolve, pollInterval));
    }
    throw new TouchQueTimeoutError(options.requestId, timeout);
  }
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
  async verify(options) {
    const { timeout, pollInterval, ...requestOptions } = options;
    const loginReq = await this.request(requestOptions);
    if (loginReq.requiresPasskey) throw new TouchQuePasskeyRequiredError(loginReq.requestId);
    const result = await this.waitForApproval({
      requestId: loginReq.requestId,
      timeout,
      pollInterval
    });
    return {
      ...result,
      requestId: loginReq.requestId,
      challengeCode: loginReq.challengeCode
    };
  }
  /**
   * Approve a pending 2FA request using a Recovery Code.
   * Useful when a user loses their phone and needs to bypass 2FA
   * using one of the backup codes generated during setup.
   */
  async approveWithRecoveryCode(options) {
    return this.http.post("/login/recovery", {
      requestId: options.requestId,
      code: options.code
    });
  }
  /**
   * Report a request you later learned was fraud — a chargeback, a confirmed
   * account takeover, a scam the user was talked into. TouchQue's risk engine
   * learns from it (it is the strongest signal it gets) and the report is
   * kept in your audit log. The request's status does not change. Safe to
   * call more than once: a repeat answers `alreadyReported: true`.
   */
  async reportFraud(requestId, options = {}) {
    if (!requestId) throw new Error("reportFraud() needs the request id");
    return this.http.post(`/login/${encodeURIComponent(requestId)}/report-fraud`, {
      ...options.reason && { reason: options.reason },
      ...options.note && { note: options.note }
    });
  }
};

// src/resources/Webhook.ts
var crypto2 = __toESM(require("crypto"));
var MemoryWebhookReplayCache = class {
  constructor(maxEntries = 1e5) {
    this.maxEntries = maxEntries;
  }
  maxEntries;
  seen = /* @__PURE__ */ new Map();
  checkAndSet(jti, ttlSeconds) {
    const now = Date.now();
    const expiresAt = this.seen.get(jti);
    if (expiresAt !== void 0 && expiresAt > now) return false;
    if (this.seen.size >= this.maxEntries) {
      for (const [key, exp] of this.seen) {
        if (exp <= now || this.seen.size >= this.maxEntries) this.seen.delete(key);
        if (this.seen.size < this.maxEntries * 0.9) break;
      }
    }
    this.seen.set(jti, now + ttlSeconds * 1e3);
    return true;
  }
};
function canonicalize(payload) {
  const { signature: _drop, ...rest } = payload;
  const sorted = {};
  for (const key of Object.keys(rest).sort()) {
    sorted[key] = rest[key];
  }
  return JSON.stringify(sorted);
}
var Webhook = class {
  apiSecret;
  constructor(apiSecret) {
    this.apiSecret = apiSecret;
  }
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
  verify(options) {
    const { rawBody } = options;
    if (!rawBody || typeof rawBody !== "string") {
      throw new TouchQueWebhookSignatureError();
    }
    let payload;
    try {
      const parsed = JSON.parse(rawBody);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("not an object");
      }
      payload = parsed;
    } catch {
      throw new TouchQueWebhookSignatureError();
    }
    const provided = typeof options.signature === "string" && options.signature ? options.signature : typeof payload.signature === "string" ? payload.signature : "";
    if (!provided) {
      throw new TouchQueWebhookSignatureError();
    }
    const expected = crypto2.createHmac("sha256", this.apiSecret).update(canonicalize(payload)).digest("hex");
    const providedBuf = Buffer.from(provided, "utf8");
    const expectedBuf = Buffer.from(expected, "utf8");
    if (providedBuf.length !== expectedBuf.length || !crypto2.timingSafeEqual(providedBuf, expectedBuf)) {
      throw new TouchQueWebhookSignatureError();
    }
    const tolerance = options.toleranceSeconds ?? 300;
    if (tolerance > 0) {
      const ts = typeof payload.timestamp === "string" ? Date.parse(payload.timestamp) : NaN;
      if (Number.isNaN(ts) || Math.abs(Date.now() - ts) > tolerance * 1e3) {
        throw new TouchQueWebhookSignatureError();
      }
    }
    if (options.replayCache) {
      const jti = payload.jti;
      if (typeof jti !== "string" || !jti) throw new TouchQueWebhookSignatureError();
      const ttl = Math.max(tolerance * 2, 600);
      if (!options.replayCache.checkAndSet(jti, ttl)) throw new TouchQueWebhookReplayError(jti);
    }
    return payload;
  }
  /**
   * Check a webhook signature without throwing. Returns `true` / `false`.
   *
   * @example
   * if (tq.webhook.isValid({ rawBody, signature })) {
   *   // process
   * }
   */
  isValid(options) {
    try {
      this.verify(options);
      return true;
    } catch {
      return false;
    }
  }
};

// src/resources/WebAuthn.ts
var WebAuthn = class {
  constructor(http) {
    this.http = http;
  }
  http;
  /**
   * Step 1 of registering a passkey: get options for `navigator.credentials.create()`.
   *
   * @example
   * const options = await tq.webauthn.registerOptions({ externalUsername: 'user@company.com' });
   * // send `options` to the browser, call navigator.credentials.create({ publicKey: options })
   */
  async registerOptions(options) {
    return this.http.post("/webauthn/register/options", {
      externalUsername: options.externalUsername,
      ...options.discoverable ? { discoverable: true } : {}
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
  async registerVerify(options) {
    return this.http.post("/webauthn/register/verify", {
      externalUsername: options.externalUsername,
      response: options.response,
      ...options.label && { label: options.label }
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
  async authenticateOptions(options) {
    return this.http.post("/webauthn/login/options", {
      requestId: options.requestId
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
  async authenticateVerify(options) {
    return this.http.post("/webauthn/login/verify", {
      requestId: options.requestId,
      response: options.response
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
  async primaryOptions(options) {
    return this.http.post("/webauthn/authenticate/primary/options", {
      externalUsername: options.externalUsername
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
  async primaryVerify(options) {
    return this.http.post("/webauthn/authenticate/primary/verify", {
      attemptId: options.attemptId,
      response: options.response
    });
  }
  /**
   * List a user's registered WebAuthn credentials (labels/metadata only, no key material).
   */
  async listCredentials(options) {
    return this.http.get("/webauthn/credentials", {
      externalUsername: options.externalUsername
    });
  }
  /**
   * Remove a registered credential (e.g. the user lost that device).
   * Pass `externalUsername` so only that user's credential can be removed.
   */
  async deleteCredential(credentialRecordId, options = {}) {
    const query = options.externalUsername ? `?externalUsername=${encodeURIComponent(options.externalUsername)}` : "";
    return this.http.delete(`/webauthn/credentials/${encodeURIComponent(credentialRecordId)}${query}`);
  }
};

// src/resources/Offline.ts
var NOT_APPROVED_STATUSES = [401, 403, 404, 409, 410, 423, 429];
var Offline = class {
  constructor(http) {
    this.http = http;
  }
  http;
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
  async challenge(options) {
    return this.http.post("/offline/challenge", {
      externalUsername: options.externalUsername,
      type: options.type,
      ...options.details && { details: options.details },
      ...options.clientIp && { clientIp: options.clientIp },
      ...options.userAgent && { userAgent: options.userAgent },
      ...options.ttlSeconds !== void 0 && { ttlSeconds: options.ttlSeconds },
      ...options.includeQrImage === false && { includeQrImage: false },
      ...options.requestId && { requestId: options.requestId },
      ...options.requireNumberMatch === true && { requireNumberMatch: true }
    });
  }
  /**
   * Check the code the user typed. Resolves `{ approved: true }` on success and
   * `{ approved: false, reason }` for a wrong / expired / used / locked
   * challenge (never throws for those); other failures (network, 5xx) throw.
   * A challenge locks after 5 wrong codes and a code works once.
   */
  async verify(options) {
    return this.notApprovedAsResult(
      () => this.http.post("/offline/verify", { challengeId: options.challengeId, code: options.code })
    );
  }
  /**
   * Check a time-based code typed from the app (no QR). Requires the workspace
   * policy `offlineTotpEnabled`. Pass `type` when the code is for a specific
   * action so critical actions are refused.
   */
  async verifyTotp(options) {
    return this.notApprovedAsResult(
      () => this.http.post("/offline/totp/verify", {
        externalUsername: options.externalUsername,
        code: options.code,
        ...options.type && { type: options.type },
        ...options.clientIp && { clientIp: options.clientIp },
        ...options.requestId && { requestId: options.requestId }
      })
    );
  }
  async notApprovedAsResult(call) {
    try {
      return await call();
    } catch (error) {
      if (error instanceof TouchQueAPIError && NOT_APPROVED_STATUSES.includes(error.status)) {
        const data = error.data;
        return { approved: false, reason: data.reason ?? data.error ?? "not_approved", attemptsLeft: data.attemptsLeft };
      }
      throw error;
    }
  }
};

// src/resources/Actions.ts
var Actions = class {
  constructor(http) {
    this.http = http;
  }
  http;
  /**
   * Creates the action type, or updates its name/description/critical flag.
   * Safe to call on every start-up: it never re-enables a type an admin disabled.
   *
   * @example
   * await tq.actions.define('SEND_MONEY', { name: 'Send money', critical: true });
   */
  async define(type, options = {}) {
    return this.http.post("/action-types", {
      type,
      name: options.name || type,
      ...options.description !== void 0 && { description: options.description },
      ...options.critical !== void 0 && { critical: options.critical }
    });
  }
  async list() {
    return this.http.get("/action-types");
  }
};

// src/internal.ts
var store = /* @__PURE__ */ new WeakMap();
function registerInternals(client, internals) {
  store.set(client, internals);
}
function get(client) {
  const i = store.get(client);
  if (!i) throw new TypeError("Not a TouchQue client instance");
  return i;
}
var guardSecret = (client) => get(client).apiSecret;
var resources = (client) => get(client).resources;

// src/steps.ts
var crypto4 = __toESM(require("crypto"));

// src/approvalProof.ts
var crypto3 = __toESM(require("crypto"));
function toPairs(details) {
  if (!details) return [];
  const pairs = Array.isArray(details) ? details.map((d) => ({ label: d.label, value: d.value })) : Object.entries(details).map(([label, value]) => ({ label, value }));
  return pairs.map((p) => ({ label: String(p.label).trim(), value: String(p.value).trim() }));
}
function detailsDigest(details) {
  const pairs = toPairs(details);
  if (pairs.length === 0) return "";
  const canonical = pairs.map((p) => `${p.label}${p.value}`).join("");
  return crypto3.createHash("sha256").update(canonical, "utf8").digest("hex");
}
function verifyApprovalProof(proof, options) {
  try {
    if (!proof || proof.version !== "v2" || proof.algorithm !== "ECDSA-P256-SHA256") return false;
    if (options.expectedPublicKey) {
      if (proof.publicKey !== options.expectedPublicKey) return false;
    } else if (options.allowUnpinnedKey !== true) {
      return false;
    }
    const expectedMessage = [
      "touchque-approve:v2",
      options.requestId,
      options.type,
      options.challengeCode ?? "",
      detailsDigest(options.details)
    ].join("\n");
    if (proof.message !== expectedMessage) return false;
    const raw = Buffer.from(proof.publicKey, "base64");
    if (raw.length !== 65 || raw[0] !== 4) return false;
    const b64url = (b) => b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const key = crypto3.createPublicKey({
      key: { kty: "EC", crv: "P-256", x: b64url(raw.subarray(1, 33)), y: b64url(raw.subarray(33, 65)) },
      format: "jwk"
    });
    return crypto3.verify(
      "sha256",
      Buffer.from(proof.message, "utf8"),
      { key, dsaEncoding: "der" },
      Buffer.from(proof.signature, "base64")
    );
  } catch {
    return false;
  }
}

// src/steps.ts
function normalizeDetails(details) {
  if (!details) return [];
  const pairs = Array.isArray(details) ? details.map((d) => [d.label, d.value]) : Object.entries(details);
  return pairs.map(([label, value]) => ({ label: String(label).trim(), value: String(value).trim() }));
}
var codeOf = (err) => err instanceof TouchQueAPIError ? err.code || err.data?.error : void 0;
async function start(r, action, opts) {
  if (!opts?.user) throw new TouchQueConfigError("start() needs the user id (options.user)");
  const details = normalizeDetails(opts.details);
  try {
    const res = await r.login.request({
      externalUsername: opts.user,
      type: action,
      referenceId: opts.referenceId,
      clientIp: opts.ip,
      userAgent: opts.userAgent,
      details: details.length ? details : void 0
    });
    if (res.requiresPasskey) {
      return { state: "passkey_required", requestId: res.requestId, expiresAt: res.expiresAt, details: details.length ? details : void 0 };
    }
    return {
      state: "waiting",
      requestId: res.requestId,
      number: res.challengeCode || void 0,
      expiresAt: res.expiresAt,
      details: details.length ? details : void 0
    };
  } catch (err) {
    if (!(err instanceof TouchQueAPIError)) throw err;
    const code = codeOf(err);
    const data = err.data;
    if (err.status === 404 && (code === "device_not_linked" || /linked device/i.test(err.message))) {
      if (opts.enroll === false) return { state: "enroll" };
      return enrollStep(r, opts.user);
    }
    if (err.status === 423) return { state: "frozen", retryAfter: data.retryAfter };
    if (err.status === 429) return { state: "rate_limited", retryAfter: data.retryAfter };
    if (err.status === 400 && (code === "unknown_action" || /Invalid action type/i.test(err.message))) {
      throw new TouchQueConfigError(
        `Unknown action "${action}". Create it once with tq.actions.define('${action}') or in the Dashboard (Action Types).`
      );
    }
    if (err.status === 403) {
      const reason = code === "blocked" ? data.reason || "policy" : code === "passkey_not_registered" || data.error === "phishing_resistant_required" ? "passkey_not_registered" : code === "action_disabled" ? "action_disabled" : code || "blocked";
      return { state: "blocked", reason };
    }
    throw err;
  }
}
async function enrollStep(r, user) {
  try {
    const gen = await r.auth.generateSecret({ externalUsername: user });
    return { state: "enroll", enroll: { qrCodeDataUrl: gen.qrCodeDataUrl, recoveryCodes: gen.recoveryCodes, expiresAt: gen.expiresAt } };
  } catch (err) {
    if (!(err instanceof TouchQueAPIError) || err.status !== 409) throw err;
    const current = await r.auth.getUser({ externalUsername: user }).catch(() => null);
    if (current && (current.used || current.deviceId)) {
      return { state: "enroll", reason: "already_linked" };
    }
    const reset = await r.auth.resetSecret({ externalUsername: user });
    return { state: "enroll", enroll: { qrCodeDataUrl: reset.qrCodeDataUrl, recoveryCodes: reset.recoveryCodes, expiresAt: reset.expiresAt } };
  }
}
async function check(r, requestId) {
  const s = await r.login.status(requestId);
  const map = { PENDING: "waiting", CONFIRMED: "approved", REJECTED: "rejected", EXPIRED: "expired" };
  const state = s.status === "PENDING" && s.requiresPasskey ? "passkey_required" : map[s.status] || "waiting";
  return { state, requestId, ...state === "approved" && s.assurance ? { assurance: s.assurance } : {} };
}
async function complete(r, requestId, expect) {
  const res = await r.http.post(`/login/${encodeURIComponent(requestId)}/consume`, {});
  const sameUser = String(res.externalUsername).toLowerCase() === String(expect.user).toLowerCase();
  const sameDetails = detailsDigest(normalizeDetails(expect.details)) === detailsDigest(res.details || []);
  const sameRef = (res.referenceId || null) === (expect.referenceId || null);
  if (!sameUser || res.type !== expect.action || !sameDetails || !sameRef) {
    throw new TouchQueError("TouchQue: this approval is for a different user, action or transaction.");
  }
  return {
    requestId,
    user: res.externalUsername,
    action: res.type,
    assurance: res.assurance,
    confirmedVia: res.confirmedVia,
    approvalProof: res.approvalProof
  };
}
var b64u = (b) => b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
var fromB64u = (s) => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
var tokenKey = (apiSecret) => crypto4.createHmac("sha256", apiSecret).update("touchque-guard-token-v1").digest();
function signGuardToken(apiSecret, claims) {
  const body = b64u(Buffer.from(JSON.stringify(claims), "utf8"));
  const mac = b64u(crypto4.createHmac("sha256", tokenKey(apiSecret)).update(body).digest());
  return `v1.${body}.${mac}`;
}
function verifyGuardToken(apiSecret, token) {
  if (typeof token !== "string" || token.length > 4096) return null;
  const [v, body, mac] = token.split(".");
  if (v !== "v1" || !body || !mac) return null;
  const expected = crypto4.createHmac("sha256", tokenKey(apiSecret)).update(body).digest();
  const given = fromB64u(mac);
  if (given.length !== expected.length || !crypto4.timingSafeEqual(given, expected)) return null;
  try {
    const claims = JSON.parse(fromB64u(body).toString("utf8"));
    if (typeof claims.exp !== "number" || claims.exp < Date.now()) return null;
    return claims;
  } catch {
    return null;
  }
}

// src/guard.ts
var GUARD_HEADERS = {
  token: "x-touchque-token",
  offline: "x-touchque-offline",
  code: "x-touchque-code",
  codeType: "x-touchque-code-type"
};
var TOKEN_TTL_MS = 10 * 60 * 1e3;
var STATUS = {
  waiting: 202,
  enroll: 202,
  passkey_required: 202,
  offline: 202,
  approved: 200,
  rejected: 403,
  blocked: 403,
  expired: 408,
  frozen: 423,
  rate_limited: 429
};
async function runGuard(tq, input) {
  const r = resources(tq);
  const secret = guardSecret(tq);
  const { action } = input;
  if (!input.user) {
    return { status: 401, body: { touchque: { state: "blocked", reason: "unauthenticated" }, error: { code: "unauthenticated", message: "Sign in first." } } };
  }
  const user = String(input.user);
  const details = normalizeDetails(input.details);
  const base = { u: user, a: action, d: detailsDigest(details), r: input.referenceId ?? null };
  const expectations = { user, action, details, referenceId: input.referenceId };
  const issue = (step, extra = {}) => {
    if (details.length && !step.details && step.state !== "blocked") step.details = details;
    const claims = {
      ...base,
      st: step.state,
      rid: step.requestId,
      n: step.number,
      oc: step.offline?.challengeId,
      exp: Date.now() + TOKEN_TTL_MS,
      ...extra
    };
    return { status: STATUS[step.state], body: { touchque: step, token: signGuardToken(secret, claims) } };
  };
  try {
    const claims = verifyGuardToken(secret, input.token);
    const bound = claims && claims.u === base.u && claims.a === base.a && claims.d === base.d && claims.r === base.r ? claims : null;
    if (bound && input.code && (bound.st === "offline" || input.codeType === "totp")) {
      const totp = input.codeType === "totp";
      const res = totp ? await r.offline.verifyTotp({ externalUsername: user, code: input.code, type: action, clientIp: input.ip, requestId: bound.rid }) : await r.offline.verify({ challengeId: String(bound.oc), code: input.code });
      const forThis = (!res.externalUsername || res.externalUsername.toLowerCase() === user.toLowerCase()) && (!res.type || res.type === action);
      if (res.approved && forThis) {
        const method = totp ? "offline_totp" : "offline_code";
        return {
          status: 200,
          approved: {
            requestId: bound.oc || "offline-totp",
            user,
            action,
            assurance: { phishingResistant: false, method },
            confirmedVia: totp ? "OFFLINE_TOTP" : "OFFLINE_CODE",
            approvalProof: null
          }
        };
      }
      if (res.reason === "invalid_code" && !totp) {
        return issue({ state: "offline", offline: { challengeId: String(bound.oc), attemptsLeft: res.attemptsLeft } }, { oc: bound.oc, rid: bound.rid, n: bound.n });
      }
      if (res.reason === "invalid_code") return issue({ state: "offline", reason: "invalid_code" }, { oc: bound.oc, rid: bound.rid, n: bound.n });
      if (res.reason === "request_rejected") return issue({ state: "rejected", requestId: bound.rid, reason: "request_rejected" });
      return issue({ state: res.reason === "expired" ? "expired" : "blocked", reason: res.reason || "offline_failed" });
    }
    if (input.offline) {
      try {
        const ch = await r.offline.challenge({
          externalUsername: user,
          type: action,
          details: details.length ? details : void 0,
          clientIp: input.ip,
          userAgent: input.userAgent,
          requestId: bound?.rid
        });
        return issue({
          state: "offline",
          offline: {
            challengeId: ch.challengeId,
            qrDataUrl: ch.qrDataUrl || void 0,
            expiresAt: ch.expiresAt,
            totpAvailable: ch.totpAvailable,
            ...ch.challengeCode && { challengeCode: ch.challengeCode }
          }
        }, { rid: bound?.rid, n: ch.challengeCode || bound?.n });
      } catch (err) {
        if (err instanceof TouchQueAPIError && err.status === 409 && (err.code || err.data?.error) === "request_rejected") {
          return issue({ state: "rejected", requestId: bound?.rid, reason: "request_rejected" });
        }
        if (err instanceof TouchQueAPIError && err.status < 500) {
          return issue({ state: "blocked", reason: err.code || err.data?.error || "offline_unavailable" });
        }
        throw err;
      }
    }
    if (bound && bound.rid && (bound.st === "waiting" || bound.st === "passkey_required" || bound.st === "offline")) {
      const now = await check(r, bound.rid);
      if (now.state === "approved") {
        try {
          return { status: 200, approved: await complete(r, bound.rid, expectations) };
        } catch (err) {
          if (err instanceof TouchQueAPIError && err.status === 409) return issue({ state: "expired", reason: err.code || "already_used" });
          throw err;
        }
      }
      if (bound.st === "offline" && (now.state === "waiting" || now.state === "expired" || now.state === "passkey_required")) {
        return issue({ state: "offline", offline: { challengeId: String(bound.oc) } }, { oc: bound.oc, rid: bound.rid, n: bound.n });
      }
      if (now.state === "waiting" || now.state === "passkey_required") {
        return issue({ state: now.state, requestId: bound.rid, number: bound.n }, { n: bound.n });
      }
      return issue({ state: now.state, requestId: bound.rid });
    }
    return issue(await start(r, action, {
      user,
      details: details.length ? details : void 0,
      referenceId: input.referenceId,
      ip: input.ip,
      userAgent: input.userAgent
    }));
  } catch (err) {
    if (err instanceof TouchQueConfigError) {
      console.error(`[TouchQue] ${err.message}`);
      return { status: 500, body: { touchque: { state: "blocked", reason: "misconfigured" }, error: { code: "misconfigured", message: "Two-factor approval is not configured correctly." } } };
    }
    if (!(err instanceof TouchQueNetworkError) && !(err instanceof TouchQueAPIError && err.status >= 500)) {
      console.error("[TouchQue] approval failed:", err instanceof Error ? err.message : err);
    }
    return { status: 503, body: { touchque: { state: "blocked", reason: "unavailable" }, error: { code: "unavailable", message: "Two-factor approval is temporarily unavailable." } } };
  }
}
function guardInputFromHeaders(get2) {
  const offline = get2(GUARD_HEADERS.offline);
  return {
    token: get2(GUARD_HEADERS.token) || void 0,
    offline: offline === "1" || offline === "true",
    code: get2(GUARD_HEADERS.code) || void 0,
    codeType: get2(GUARD_HEADERS.codeType) || void 0
  };
}

// src/middleware/express.ts
var defaultUser = (req) => {
  const u = req.user;
  const id = u?.email ?? u?.id ?? u?.username;
  return id === void 0 || id === null ? void 0 : String(id);
};
function requireTouchQue(a, b, c) {
  const legacy = typeof a !== "string";
  const action = legacy ? b : a;
  const options = (legacy ? c : b) || {};
  const explicitClient = legacy ? a : options.client;
  const userOf = options.user || options.getUserId || defaultUser;
  const detailsOf = options.details || options.getDetails;
  const refOf = options.referenceId || options.getReferenceId;
  return async (req, res, next) => {
    try {
      const client = explicitClient || getDefaultClient();
      const [user, details, referenceId] = await Promise.all([
        userOf(req),
        detailsOf ? detailsOf(req) : void 0,
        refOf ? refOf(req) : void 0
      ]);
      const result = await runGuard(client, {
        user: user ?? void 0,
        action,
        details,
        referenceId: referenceId ?? void 0,
        ip: req.ip,
        userAgent: req.get?.("user-agent") ?? void 0,
        ...guardInputFromHeaders((name) => req.get?.(name) ?? req.headers?.[name])
      });
      if (result.approved) {
        req.touchque = result.approved;
        next();
        return;
      }
      if (result.status === 429 || result.status === 423) {
        const retry = result.body.touchque.retryAfter;
        if (retry) res.set("Retry-After", String(retry));
      }
      res.set("Cache-Control", "no-store");
      res.status(result.status).json(result.body);
    } catch (err) {
      next(err);
    }
  };
}

// src/next.ts
function withTouchQue(action, handler, options) {
  return async (req, ctx) => {
    const client = options.client || getDefaultClient();
    const [user, details, referenceId] = await Promise.all([
      options.user(req),
      options.details ? options.details(req) : void 0,
      options.referenceId ? options.referenceId(req) : void 0
    ]);
    const ip = options.ip ? options.ip(req) : req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || void 0;
    const result = await runGuard(client, {
      user: user ?? void 0,
      action,
      details,
      referenceId: referenceId ?? void 0,
      ip,
      userAgent: req.headers.get("user-agent") ?? void 0,
      ...guardInputFromHeaders((name) => req.headers.get(name))
    });
    if (result.approved) {
      return handler(req, { ...ctx, touchque: result.approved });
    }
    const headers = { "Content-Type": "application/json", "Cache-Control": "no-store" };
    if (result.body.touchque.retryAfter) headers["Retry-After"] = String(result.body.touchque.retryAfter);
    return new Response(JSON.stringify(result.body), { status: result.status, headers });
  };
}

// src/router.ts
var import_express = require("express");

// src/rateLimiter.ts
var MAX_KEYS = 5e4;
var FixedWindowLimiter = class {
  entries = /* @__PURE__ */ new Map();
  windowMs;
  perIp;
  perUser;
  constructor(options = {}) {
    this.windowMs = options.windowMs ?? 6e4;
    this.perIp = options.perIp ?? 20;
    this.perUser = options.perUser ?? 5;
  }
  /** Counts one hit. Returns seconds to wait when over `limit`, otherwise 0. */
  hit(key, limit, now = Date.now()) {
    let e = this.entries.get(key);
    if (!e || e.resetAt <= now) {
      if (!e && this.entries.size >= MAX_KEYS) this.prune(now);
      e = { count: 0, resetAt: now + this.windowMs };
      this.entries.set(key, e);
    }
    e.count += 1;
    return e.count > limit ? Math.max(1, Math.ceil((e.resetAt - now) / 1e3)) : 0;
  }
  prune(now) {
    for (const [k, v] of this.entries) if (v.resetAt <= now) this.entries.delete(k);
    if (this.entries.size >= MAX_KEYS) {
      let i = 0;
      for (const k of this.entries.keys()) {
        if (i++ > MAX_KEYS / 2) break;
        this.entries.delete(k);
      }
    }
  }
};

// src/router.ts
function sendAuthResultError(res, error) {
  if (error instanceof TouchQueRejectedError) {
    res.status(403).json({ error: "2FA_REJECTED", message: "User rejected the 2FA request on their device." });
    return;
  }
  if (error instanceof TouchQuePasskeyRequiredError) {
    res.status(409).json({ error: "PASSKEY_REQUIRED", requestId: error.requestId, message: "Approve this sign-in with your passkey." });
    return;
  }
  if (error instanceof TouchQueTimeoutError) {
    res.status(408).json({ error: "2FA_TIMEOUT", message: "User did not respond to the 2FA request in time." });
    return;
  }
  const apiErr = error;
  if (typeof apiErr.status === "number" && apiErr.status < 500) {
    res.status(apiErr.status).json({ error: apiErr.data?.error || apiErr.data?.message || apiErr.message || "request_failed" });
    return;
  }
  console.error("[TouchQue Router Error]", error);
  res.status(503).json({ error: "2FA_UNAVAILABLE", message: "The 2FA verification service is temporarily unavailable." });
}
function sendRelayError(res, error) {
  if (error instanceof TouchQueAPIError && error.status < 500) {
    res.status(error.status).json({ error: error.code || error.data?.error || "request_failed" });
    return;
  }
  res.status(502).json({ error: "relay_error" });
}
function requireUserId(req, res, getUserId) {
  const userId = getUserId(req);
  if (!userId) {
    res.status(401).json({
      error: "UNAUTHORIZED_FOR_2FA",
      message: "Could not find user ID in request. Put your own auth middleware in front of this router."
    });
    return void 0;
  }
  return userId;
}
var warnedPreAuth = false;
function touchqueRouter(tq, options) {
  const { getUserId, getLoginUser, actionType = "LOGIN", onAuthenticated, getDetails } = options;
  const router = (0, import_express.Router)();
  const limiter = options.rateLimit === false ? null : new FixedWindowLimiter(options.rateLimit || {});
  const offlineEnabled = Boolean(getLoginUser) || options.allowOfflineWithoutFirstFactor === true;
  if (!getLoginUser && !warnedPreAuth) {
    warnedPreAuth = true;
    console.warn("[TouchQue] touchqueRouter: POST /login takes the username from the request body" + (offlineEnabled ? ", and so do the offline routes" : "; the offline routes are disabled until you set it") + ". Set `getLoginUser` to bind them to your first factor (password step) so they cannot be used against arbitrary users.");
  }
  const offlineAllowed = (res) => {
    if (offlineEnabled) return true;
    res.status(403).json({
      error: "OFFLINE_REQUIRES_FIRST_FACTOR",
      message: "Offline sign-in is disabled: configure getLoginUser (or allowOfflineWithoutFirstFactor) on the TouchQue router."
    });
    return false;
  };
  const allow = (req, res, route, user) => {
    if (!limiter) return true;
    const ipWait = limiter.hit(`ip|${route}|${req.ip || "unknown"}`, limiter.perIp);
    const userWait = user ? limiter.hit(`user|${route}|${user}`, limiter.perUser) : 0;
    const wait = Math.max(ipWait, userWait);
    if (!wait) return true;
    res.set("Retry-After", String(wait));
    res.status(429).json({ error: "RATE_LIMITED", message: "Too many attempts. Try again later.", retryAfter: wait });
    return false;
  };
  const loginUser = async (req, res, bodyField) => {
    if (getLoginUser) {
      const u = await getLoginUser(req);
      if (!u) {
        res.status(401).json({ error: "FIRST_FACTOR_REQUIRED", message: "Sign in with your password first." });
        return void 0;
      }
      return String(u).toLowerCase();
    }
    const typed = String(req.body?.[bodyField] || "").toLowerCase();
    if (!typed) {
      res.status(400).json({ error: "externalUsername_required" });
      return void 0;
    }
    return typed;
  };
  router.post("/enroll/start", async (req, res) => {
    const userId = requireUserId(req, res, getUserId);
    if (!userId) return;
    try {
      res.json(await tq.auth.generateSecret({ externalUsername: userId }));
    } catch (error) {
      const err = error;
      if (err.status === 409) {
        try {
          const current = await tq.auth.getUser({ externalUsername: userId });
          if (current.used || current.deviceId) {
            res.status(409).json({ error: "already_linked", message: "A phone is already linked to this account." });
            return;
          }
          res.json(await tq.auth.resetSecret({ externalUsername: userId }));
          return;
        } catch (retryError) {
          sendRelayError(res, retryError);
          return;
        }
      }
      sendRelayError(res, error);
    }
  });
  router.get("/enroll/status", async (req, res) => {
    const userId = requireUserId(req, res, getUserId);
    if (!userId) return;
    try {
      const u = await tq.auth.getUser({ externalUsername: userId });
      res.json({ linked: Boolean(u.used && u.deviceId), used: u.used, deviceId: u.deviceId });
    } catch (error) {
      const err = error;
      if (err.status === 404) {
        res.json({ linked: false, used: false, deviceId: null });
        return;
      }
      sendRelayError(res, error);
    }
  });
  router.post("/login", async (req, res) => {
    const externalUsername = await loginUser(req, res, "externalUsername");
    if (!externalUsername || !allow(req, res, "login", externalUsername)) return;
    const result = await runGuard(tq, {
      user: externalUsername,
      action: actionType,
      details: getDetails ? await getDetails(req) : void 0,
      ip: req.ip,
      userAgent: req.get("user-agent"),
      ...guardInputFromHeaders((name) => req.get(name))
    });
    if (!result.approved) {
      if (result.body.touchque.retryAfter) res.set("Retry-After", String(result.body.touchque.retryAfter));
      res.set("Cache-Control", "no-store");
      res.status(result.status).json(result.body);
      return;
    }
    try {
      if (onAuthenticated) {
        const via = result.approved.confirmedVia === "OFFLINE_TOTP" ? "offline-totp" : result.approved.confirmedVia === "OFFLINE_CODE" ? "offline" : "login";
        await onAuthenticated(req, res, { externalUsername, requestId: result.approved.requestId, via });
      }
      res.json({ status: "success", requestId: result.approved.requestId, assurance: result.approved.assurance });
    } catch (error) {
      sendAuthResultError(res, error);
    }
  });
  router.post("/offline/challenge", async (req, res) => {
    if (!offlineAllowed(res)) return;
    const externalUsername = await loginUser(req, res, "externalUsername");
    if (!externalUsername || !allow(req, res, "offline-challenge", externalUsername)) return;
    try {
      const requestId = typeof req.body?.requestId === "string" && req.body.requestId ? req.body.requestId : void 0;
      const c = await tq.offline.challenge({
        externalUsername,
        type: actionType,
        clientIp: req.ip,
        userAgent: req.get("user-agent"),
        details: getDetails ? await getDetails(req) : void 0,
        requestId
      });
      res.json({
        challengeId: c.challengeId,
        qr: c.qr,
        qrDataUrl: c.qrDataUrl,
        expiresAt: c.expiresAt,
        expiresInSeconds: c.expiresInSeconds,
        totpAvailable: c.totpAvailable,
        ...c.challengeCode && { challengeCode: c.challengeCode }
      });
    } catch (error) {
      sendRelayError(res, error);
    }
  });
  router.post("/offline/verify", async (req, res) => {
    if (!offlineAllowed(res) || !allow(req, res, "offline-verify")) return;
    try {
      const r = await tq.offline.verify({ challengeId: String(req.body?.challengeId || ""), code: String(req.body?.code || "") });
      if (!r.approved || !r.externalUsername) {
        res.status(r.reason === "invalid_code" ? 401 : 400).json({ approved: false, reason: r.reason, attemptsLeft: r.attemptsLeft });
        return;
      }
      if (getLoginUser) {
        const expected = await getLoginUser(req);
        if (!expected || String(expected).toLowerCase() !== r.externalUsername.toLowerCase()) {
          res.status(401).json({ approved: false, reason: "invalid_code" });
          return;
        }
      }
      if (onAuthenticated) {
        await onAuthenticated(req, res, { externalUsername: r.externalUsername, requestId: r.challengeId, via: "offline" });
      }
      res.json({ status: "success", approved: true, requestId: r.challengeId });
    } catch (error) {
      sendRelayError(res, error);
    }
  });
  router.post("/offline/totp", async (req, res) => {
    if (!offlineAllowed(res)) return;
    const externalUsername = await loginUser(req, res, "externalUsername");
    if (!externalUsername || !allow(req, res, "offline-totp", externalUsername)) return;
    try {
      const r = await tq.offline.verifyTotp({
        externalUsername,
        code: String(req.body?.code || ""),
        type: actionType,
        clientIp: req.ip,
        requestId: typeof req.body?.requestId === "string" && req.body.requestId ? req.body.requestId : void 0
      });
      if (!r.approved || !r.externalUsername) {
        res.status(r.reason === "invalid_code" ? 401 : 400).json({ approved: false, reason: r.reason });
        return;
      }
      if (onAuthenticated) {
        await onAuthenticated(req, res, { externalUsername: r.externalUsername, via: "offline-totp" });
      }
      res.json({ status: "success", approved: true });
    } catch (error) {
      sendRelayError(res, error);
    }
  });
  router.post("/passkey/authenticate/options", async (req, res) => {
    const email = String(req.body?.email || "").toLowerCase();
    if (!allow(req, res, "passkey-options", email || void 0)) return;
    try {
      res.json(await tq.webauthn.primaryOptions({ externalUsername: email }));
    } catch (error) {
      sendRelayError(res, error);
    }
  });
  router.post("/passkey/authenticate/verify", async (req, res) => {
    if (!allow(req, res, "passkey-verify")) return;
    try {
      const r = await tq.webauthn.primaryVerify({ attemptId: req.body?.attemptId, response: req.body?.response });
      if (r.success) {
        if (onAuthenticated) {
          await onAuthenticated(req, res, { externalUsername: r.externalUsername, requestId: r.requestId, via: "passkey" });
        }
        res.json({ status: "success", requestId: r.requestId });
      } else if (r.requiresStepUp) {
        res.json({ requiresStepUp: true });
      } else {
        res.status(401).json({ error: "verification_failed" });
      }
    } catch (error) {
      sendRelayError(res, error);
    }
  });
  router.post("/passkey/login/options", async (req, res) => {
    if (!allow(req, res, "passkey-approve")) return;
    try {
      res.json(await tq.webauthn.authenticateOptions({ requestId: req.body?.requestId }));
    } catch (error) {
      sendRelayError(res, error);
    }
  });
  router.post("/passkey/login/verify", async (req, res) => {
    if (!allow(req, res, "passkey-approve")) return;
    try {
      const r = await tq.webauthn.authenticateVerify({ requestId: req.body?.requestId, response: req.body?.response });
      if (r.success && getLoginUser && typeof r.externalUsername === "string") {
        const expected = await getLoginUser(req);
        if (!expected || String(expected).toLowerCase() !== r.externalUsername.toLowerCase()) {
          res.status(401).json({ error: "verification_failed" });
          return;
        }
      }
      if (r.success && onAuthenticated && typeof r.externalUsername === "string" && r.externalUsername) {
        await onAuthenticated(req, res, { externalUsername: r.externalUsername, requestId: r.requestId || req.body?.requestId, via: "passkey" });
      }
      res.json(r);
    } catch (error) {
      sendRelayError(res, error);
    }
  });
  router.post("/passkey/register/options", async (req, res) => {
    const userId = requireUserId(req, res, getUserId);
    if (!userId) return;
    try {
      res.json(await tq.webauthn.registerOptions({ externalUsername: userId, discoverable: true }));
    } catch (error) {
      sendRelayError(res, error);
    }
  });
  router.post("/passkey/register/verify", async (req, res) => {
    const userId = requireUserId(req, res, getUserId);
    if (!userId) return;
    try {
      res.json(await tq.webauthn.registerVerify({ externalUsername: userId, response: req.body?.response, label: req.body?.label }));
    } catch (error) {
      sendRelayError(res, error);
    }
  });
  router.get("/passkey/credentials", async (req, res) => {
    const userId = requireUserId(req, res, getUserId);
    if (!userId) return;
    try {
      res.json(await tq.webauthn.listCredentials({ externalUsername: userId }));
    } catch (error) {
      sendRelayError(res, error);
    }
  });
  router.delete("/passkey/credentials/:id", async (req, res) => {
    const userId = requireUserId(req, res, getUserId);
    if (!userId) return;
    try {
      res.json(await tq.webauthn.deleteCredential(req.params.id, { externalUsername: userId }));
    } catch (error) {
      sendRelayError(res, error);
    }
  });
  return router;
}

// src/index.ts
var DEFAULT_BASE_URL = "https://api.touchque.com";
var TouchQue3 = class {
  auth;
  login;
  /** Webhook signature verification */
  webhook;
  /** WebAuthn/FIDO2 (passkey) registration and login approval */
  webauthn;
  /** Offline Sign — QR challenge / typed code approvals that work with the phone offline */
  offline;
  /** Action types (LOGIN, SEND_MONEY…) */
  actions;
  /**
   * @param config - Optional. Falls back to the environment:
   *   TQ_API_KEY, TQ_API_SECRET, TQ_API_URL (default https://api.touchque.com).
   *
   * @example
   * const tq = new TouchQue();                       // from the environment
   * const tq = new TouchQue({ apiKey, apiSecret });  // explicit
   */
  constructor(config = {}) {
    const env = typeof process !== "undefined" ? process.env : {};
    const resolved = {
      apiKey: config.apiKey ?? env.TQ_API_KEY ?? "",
      apiSecret: config.apiSecret ?? env.TQ_API_SECRET ?? "",
      baseUrl: config.baseUrl ?? env.TQ_API_URL ?? DEFAULT_BASE_URL,
      timeout: config.timeout
    };
    if (!resolved.apiKey || !resolved.apiSecret) {
      throw new TouchQueConfigError("Set TQ_API_KEY and TQ_API_SECRET (or pass { apiKey, apiSecret }).");
    }
    const http = new HttpClient(resolved);
    this.auth = new Auth(http);
    this.login = new Login(http);
    this.webhook = new Webhook(resolved.apiSecret);
    this.webauthn = new WebAuthn(http);
    this.offline = new Offline(http);
    this.actions = new Actions(http);
    registerInternals(this, { apiSecret: resolved.apiSecret, resources: { http, auth: this.auth, login: this.login, offline: this.offline } });
  }
  /**
   * Starts an approval and returns immediately — show the step in your UI.
   * `waiting` + `number`: show the number, the user picks it on the phone.
   * `enroll`: show `enroll.qrCodeDataUrl` so the user links the TouchQue app first.
   *
   * @example
   * const step = await tq.start('SEND_MONEY', { user: 'jane@acme.com', details: { Amount: '250 EUR' } });
   */
  start(action, options) {
    return start({ http: httpOf(this), auth: this.auth, login: this.login, offline: this.offline }, action, options);
  }
  /** Where a started approval is now: waiting, approved, rejected, expired… */
  check(requestId) {
    return check({ http: httpOf(this), auth: this.auth, login: this.login, offline: this.offline }, requestId);
  }
  /**
   * Uses an approved request exactly once, after checking it is for this user,
   * action and transaction. Call it right before doing the protected thing.
   */
  complete(requestId, expect) {
    return complete({ http: httpOf(this), auth: this.auth, login: this.login, offline: this.offline }, requestId, expect);
  }
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
  protect(fn, options) {
    return async (...args) => {
      const externalUsername = options.getUserIdentifier(...args);
      const referenceId = options.getReferenceId ? options.getReferenceId(...args) : void 0;
      const context = options.getContext ? options.getContext(...args) : void 0;
      await this.login.verify({
        externalUsername,
        type: options.type,
        referenceId,
        ...context,
        timeout: options.timeout,
        pollInterval: options.pollInterval
      });
      return fn(...args);
    };
  }
};
function httpOf(client) {
  return resources(client).http;
}
var defaultClient;
function getDefaultClient() {
  if (!defaultClient) defaultClient = new TouchQue3();
  return defaultClient;
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  Actions,
  Auth,
  DEFAULT_BASE_URL,
  GUARD_HEADERS,
  Login,
  MemoryWebhookReplayCache,
  Offline,
  TouchQue,
  TouchQueAPIError,
  TouchQueConfigError,
  TouchQueError,
  TouchQueNetworkError,
  TouchQuePasskeyRequiredError,
  TouchQueRejectedError,
  TouchQueTimeoutError,
  TouchQueWebhookReplayError,
  TouchQueWebhookSignatureError,
  WebAuthn,
  Webhook,
  detailsDigest,
  getDefaultClient,
  normalizeDetails,
  requireTouchQue,
  runGuard,
  signGuardToken,
  touchqueRouter,
  verifyApprovalProof,
  verifyGuardToken,
  withTouchQue
});
