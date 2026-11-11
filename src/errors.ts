// src/errors.ts
// Custom error classes for the Touchque SDK

import { TouchqueErrorData } from './types';

/**
 * Base error class for all Touchque SDK errors.
 */
export class TouchqueError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TouchqueError';
  }
}

/**
 * Thrown when the Touchque API returns a non-2xx HTTP response.
 * Contains the HTTP status code and the raw API error data.
 */
export class TouchqueAPIError extends TouchqueError {
  public readonly status: number;
  public readonly code: string | undefined;
  public readonly data: TouchqueErrorData;
  /** "Why?" case code of a refusal (`K7P-2QX`), to show the user; undefined for other errors. */
  public readonly caseCode: string | undefined;

  constructor(status: number, data: TouchqueErrorData) {
    const message = data.message || data.error || `Touchque API Error: HTTP ${status}`;
    super(message);
    this.name = 'TouchqueAPIError';
    this.status = status;
    this.code = data.code;
    this.data = data;
    this.caseCode = typeof data.caseCode === 'string' ? data.caseCode : undefined;
  }
}

/**
 * The organization behind your workspace cannot use this feature here (HTTP
 * 403). `reason`:
 * - `not_in_plan` — the feature is not in its plan (`feature_not_in_plan`): an
 *   owner or admin adds it in the Touchque dashboard;
 * - `read_only` — it is being turned off (`feature_read_only`): reads still
 *   work for 14 days, changes are refused;
 * - `off` — it is switched off on this Touchque deployment (`feature_off`).
 * `feature` is the catalog id (`device_risk`, `ai_agents`, `mobile_sdk`, `ciam`…).
 * Extends TouchqueAPIError, so existing `catch` blocks still see it; catch one
 * of the three subclasses to tell them apart.
 */
export class TouchqueFeatureError extends TouchqueAPIError {
  public readonly feature: string | undefined;
  public readonly reason: 'not_in_plan' | 'read_only' | 'off';

  constructor(status: number, data: TouchqueErrorData, reason: 'not_in_plan' | 'read_only' | 'off') {
    super(status, data);
    this.name = 'TouchqueFeatureError';
    this.feature = typeof data.feature === 'string' ? data.feature : undefined;
    this.reason = reason;
  }
}

/** `feature_not_in_plan`: the feature is not in the organization's plan. */
export class TouchqueFeatureNotInPlanError extends TouchqueFeatureError {
  constructor(status: number, data: TouchqueErrorData) {
    super(status, data, 'not_in_plan');
    this.name = 'TouchqueFeatureNotInPlanError';
  }
}

/** `feature_read_only`: the feature is being turned off; reads work, changes are refused. */
export class TouchqueFeatureReadOnlyError extends TouchqueFeatureError {
  constructor(status: number, data: TouchqueErrorData) {
    super(status, data, 'read_only');
    this.name = 'TouchqueFeatureReadOnlyError';
  }
}

/** `feature_off`: the feature is switched off on this Touchque deployment. */
export class TouchqueFeatureOffError extends TouchqueFeatureError {
  constructor(status: number, data: TouchqueErrorData) {
    super(status, data, 'off');
    this.name = 'TouchqueFeatureOffError';
  }
}

/** The API error for an answer: a TouchqueFeatureError subclass for the three feature codes, else TouchqueAPIError. */
export function apiError(status: number, data: TouchqueErrorData): TouchqueAPIError {
  switch (data.error) {
    case 'feature_not_in_plan': return new TouchqueFeatureNotInPlanError(status, data);
    case 'feature_read_only': return new TouchqueFeatureReadOnlyError(status, data);
    case 'feature_off': return new TouchqueFeatureOffError(status, data);
    default: return new TouchqueAPIError(status, data);
  }
}

/**
 * Thrown when a request never reached Touchque at all — no HTTP response
 * was received (connection refused, DNS failure, client-side timeout).
 * Distinct from TouchqueAPIError, which means Touchque DID respond, just
 * with a non-2xx status. A TouchqueNetworkError is generally safe to
 * retry; a TouchqueAPIError often is not (e.g. a validation error will
 * fail again identically).
 */
export class TouchqueNetworkError extends TouchqueError {
  public readonly code: string | undefined;

  constructor(message: string, code?: string) {
    super(`Touchque: network request failed${code ? ` (${code})` : ''} — ${message}`);
    this.name = 'TouchqueNetworkError';
    this.code = code;
  }
}

/**
 * Thrown when the waitForApproval() polling method times out
 * before the user approves or rejects the request.
 */
export class TouchqueTimeoutError extends TouchqueError {
  public readonly requestId: string;

  constructor(requestId: string, timeoutMs: number) {
    super(
      `Touchque: Request '${requestId}' was not approved within ${timeoutMs / 1000}s. ` +
      `The user did not respond in time.`
    );
    this.name = 'TouchqueTimeoutError';
    this.requestId = requestId;
  }
}

/**
 * Thrown when a login request is explicitly rejected by the user.
 */
export class TouchqueRejectedError extends TouchqueError {
  public readonly requestId: string;

  constructor(requestId: string) {
    super(
      `Touchque: Request '${requestId}' was rejected by the user.`
    );
    this.name = 'TouchqueRejectedError';
    this.requestId = requestId;
  }
}

/**
 * Thrown when webhook signature verification fails.
 * This means the incoming webhook is not from Touchque (potential forgery).
 */
export class TouchqueWebhookSignatureError extends TouchqueError {
  constructor() {
    super(
      'Touchque: Webhook signature verification failed. ' +
      'This request did not come from Touchque or the payload was tampered.'
    );
    this.name = 'TouchqueWebhookSignatureError';
  }
}

/**
 * Thrown when a correctly signed webhook has already been accepted once (same
 * `jti`). Usually a Touchque retry of a delivery you already processed —
 * answer 200 so it stops, but do not run your side effects again. Extends
 * `TouchqueWebhookSignatureError`, so existing `catch` blocks still reject it.
 */
export class TouchqueWebhookReplayError extends TouchqueWebhookSignatureError {
  readonly jti: string;
  constructor(jti: string) {
    super();
    this.message = 'Touchque: This webhook (jti) was already accepted.';
    this.name = 'TouchqueWebhookReplayError';
    this.jti = jti;
  }
}

/**
 * Thrown when SDK is used before being properly configured.
 */
export class TouchqueConfigError extends TouchqueError {
  constructor(message: string) {
    super(`Touchque Config Error: ${message}`);
    this.name = 'TouchqueConfigError';
  }
}

/**
 * Thrown by `login.verify()` when the workspace requires a phishing-resistant
 * factor for this action: no push was sent. Approve `requestId` with a passkey
 * in the browser (`@touchque/web` `passkeys.approveLogin({ requestId })`, relayed
 * by `touchqueRouter`'s `/passkey/login/*` routes), then check `login.status()`.
 */
export class TouchquePasskeyRequiredError extends TouchqueError {
  public readonly requestId: string;
  /**
   * `policy`: a phishing-resistant policy, no push was sent.
   * `step_up`: the push was tapped while the user was on a call (Vishing
   * Shield); the request is still open and waits for a passkey in the browser.
   */
  public readonly reason: 'policy' | 'step_up';

  constructor(requestId: string, reason: 'policy' | 'step_up' = 'policy') {
    super(reason === 'step_up'
      ? `Touchque: Request '${requestId}' must now be approved with a passkey: the user approved on the phone during a call.`
      : `Touchque: Request '${requestId}' must be approved with a passkey (phishing-resistant policy); no push was sent.`);
    this.name = 'TouchquePasskeyRequiredError';
    this.requestId = requestId;
    this.reason = reason;
  }
}

/**
 * An AI agent's approval ended without a usable approval: the person
 * rejected it (`rejected`), the risk engine refused it (`blocked`), it was
 * taken back after a call (`revoked`), it expired (`expired`), it was
 * approved too long ago to use (`stale`) or it was already used (`redeemed`).
 */
export class TouchqueApprovalError extends TouchqueError {
  public readonly approvalId: string;
  public readonly status: string;
  public readonly reason: string | undefined;

  constructor(approvalId: string, status: string, reason?: string) {
    super(`Touchque: approval '${approvalId}' is ${status}${reason ? ` (${reason})` : ''}.`);
    this.name = 'TouchqueApprovalError';
    this.approvalId = approvalId;
    this.status = status;
    this.reason = reason;
  }
}

/**
 * An approval token does not say what you are about to execute (another
 * person, action type, amount, recipient…), or it is not a valid token from
 * Touchque. Do not execute.
 */
export class TouchqueApprovalMismatchError extends TouchqueError {
  constructor(message: string) {
    super(`Touchque: ${message}`);
    this.name = 'TouchqueApprovalMismatchError';
  }
}
