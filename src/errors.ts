// src/errors.ts
// Custom error classes for the TouchQue SDK

import { TouchQueErrorData } from './types';

/**
 * Base error class for all TouchQue SDK errors.
 */
export class TouchQueError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TouchQueError';
  }
}

/**
 * Thrown when the TouchQue API returns a non-2xx HTTP response.
 * Contains the HTTP status code and the raw API error data.
 */
export class TouchQueAPIError extends TouchQueError {
  public readonly status: number;
  public readonly code: string | undefined;
  public readonly data: TouchQueErrorData;
  /** "Why?" case code of a refusal (`K7P-2QX`), to show the user; undefined for other errors. */
  public readonly caseCode: string | undefined;

  constructor(status: number, data: TouchQueErrorData) {
    const message = data.message || data.error || `TouchQue API Error: HTTP ${status}`;
    super(message);
    this.name = 'TouchQueAPIError';
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
 *   owner or admin adds it in the TouchQue dashboard;
 * - `read_only` — it is being turned off (`feature_read_only`): reads still
 *   work for 14 days, changes are refused;
 * - `off` — it is switched off on this TouchQue deployment (`feature_off`).
 * `feature` is the catalog id (`device_risk`, `ai_agents`, `mobile_sdk`, `ciam`…).
 * Extends TouchQueAPIError, so existing `catch` blocks still see it; catch one
 * of the three subclasses to tell them apart.
 */
export class TouchQueFeatureError extends TouchQueAPIError {
  public readonly feature: string | undefined;
  public readonly reason: 'not_in_plan' | 'read_only' | 'off';

  constructor(status: number, data: TouchQueErrorData, reason: 'not_in_plan' | 'read_only' | 'off') {
    super(status, data);
    this.name = 'TouchQueFeatureError';
    this.feature = typeof data.feature === 'string' ? data.feature : undefined;
    this.reason = reason;
  }
}

/** `feature_not_in_plan`: the feature is not in the organization's plan. */
export class TouchQueFeatureNotInPlanError extends TouchQueFeatureError {
  constructor(status: number, data: TouchQueErrorData) {
    super(status, data, 'not_in_plan');
    this.name = 'TouchQueFeatureNotInPlanError';
  }
}

/** `feature_read_only`: the feature is being turned off; reads work, changes are refused. */
export class TouchQueFeatureReadOnlyError extends TouchQueFeatureError {
  constructor(status: number, data: TouchQueErrorData) {
    super(status, data, 'read_only');
    this.name = 'TouchQueFeatureReadOnlyError';
  }
}

/** `feature_off`: the feature is switched off on this TouchQue deployment. */
export class TouchQueFeatureOffError extends TouchQueFeatureError {
  constructor(status: number, data: TouchQueErrorData) {
    super(status, data, 'off');
    this.name = 'TouchQueFeatureOffError';
  }
}

/** The API error for an answer: a TouchQueFeatureError subclass for the three feature codes, else TouchQueAPIError. */
export function apiError(status: number, data: TouchQueErrorData): TouchQueAPIError {
  switch (data.error) {
    case 'feature_not_in_plan': return new TouchQueFeatureNotInPlanError(status, data);
    case 'feature_read_only': return new TouchQueFeatureReadOnlyError(status, data);
    case 'feature_off': return new TouchQueFeatureOffError(status, data);
    default: return new TouchQueAPIError(status, data);
  }
}

/**
 * Thrown when a request never reached TouchQue at all — no HTTP response
 * was received (connection refused, DNS failure, client-side timeout).
 * Distinct from TouchQueAPIError, which means TouchQue DID respond, just
 * with a non-2xx status. A TouchQueNetworkError is generally safe to
 * retry; a TouchQueAPIError often is not (e.g. a validation error will
 * fail again identically).
 */
export class TouchQueNetworkError extends TouchQueError {
  public readonly code: string | undefined;

  constructor(message: string, code?: string) {
    super(`TouchQue: network request failed${code ? ` (${code})` : ''} — ${message}`);
    this.name = 'TouchQueNetworkError';
    this.code = code;
  }
}

/**
 * Thrown when the waitForApproval() polling method times out
 * before the user approves or rejects the request.
 */
export class TouchQueTimeoutError extends TouchQueError {
  public readonly requestId: string;

  constructor(requestId: string, timeoutMs: number) {
    super(
      `TouchQue: Request '${requestId}' was not approved within ${timeoutMs / 1000}s. ` +
      `The user did not respond in time.`
    );
    this.name = 'TouchQueTimeoutError';
    this.requestId = requestId;
  }
}

/**
 * Thrown when a login request is explicitly rejected by the user.
 */
export class TouchQueRejectedError extends TouchQueError {
  public readonly requestId: string;

  constructor(requestId: string) {
    super(
      `TouchQue: Request '${requestId}' was rejected by the user.`
    );
    this.name = 'TouchQueRejectedError';
    this.requestId = requestId;
  }
}

/**
 * Thrown when webhook signature verification fails.
 * This means the incoming webhook is not from TouchQue (potential forgery).
 */
export class TouchQueWebhookSignatureError extends TouchQueError {
  constructor() {
    super(
      'TouchQue: Webhook signature verification failed. ' +
      'This request did not come from TouchQue or the payload was tampered.'
    );
    this.name = 'TouchQueWebhookSignatureError';
  }
}

/**
 * Thrown when a correctly signed webhook has already been accepted once (same
 * `jti`). Usually a TouchQue retry of a delivery you already processed —
 * answer 200 so it stops, but do not run your side effects again. Extends
 * `TouchQueWebhookSignatureError`, so existing `catch` blocks still reject it.
 */
export class TouchQueWebhookReplayError extends TouchQueWebhookSignatureError {
  readonly jti: string;
  constructor(jti: string) {
    super();
    this.message = 'TouchQue: This webhook (jti) was already accepted.';
    this.name = 'TouchQueWebhookReplayError';
    this.jti = jti;
  }
}

/**
 * Thrown when SDK is used before being properly configured.
 */
export class TouchQueConfigError extends TouchQueError {
  constructor(message: string) {
    super(`TouchQue Config Error: ${message}`);
    this.name = 'TouchQueConfigError';
  }
}

/**
 * Thrown by `login.verify()` when the workspace requires a phishing-resistant
 * factor for this action: no push was sent. Approve `requestId` with a passkey
 * in the browser (`@touchque/web` `passkeys.approveLogin({ requestId })`, relayed
 * by `touchqueRouter`'s `/passkey/login/*` routes), then check `login.status()`.
 */
export class TouchQuePasskeyRequiredError extends TouchQueError {
  public readonly requestId: string;
  /**
   * `policy`: a phishing-resistant policy, no push was sent.
   * `step_up`: the push was tapped while the user was on a call (Vishing
   * Shield); the request is still open and waits for a passkey in the browser.
   */
  public readonly reason: 'policy' | 'step_up';

  constructor(requestId: string, reason: 'policy' | 'step_up' = 'policy') {
    super(reason === 'step_up'
      ? `TouchQue: Request '${requestId}' must now be approved with a passkey: the user approved on the phone during a call.`
      : `TouchQue: Request '${requestId}' must be approved with a passkey (phishing-resistant policy); no push was sent.`);
    this.name = 'TouchQuePasskeyRequiredError';
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
export class TouchQueApprovalError extends TouchQueError {
  public readonly approvalId: string;
  public readonly status: string;
  public readonly reason: string | undefined;

  constructor(approvalId: string, status: string, reason?: string) {
    super(`TouchQue: approval '${approvalId}' is ${status}${reason ? ` (${reason})` : ''}.`);
    this.name = 'TouchQueApprovalError';
    this.approvalId = approvalId;
    this.status = status;
    this.reason = reason;
  }
}

/**
 * An approval token does not say what you are about to execute (another
 * person, action type, amount, recipient…), or it is not a valid token from
 * TouchQue. Do not execute.
 */
export class TouchQueApprovalMismatchError extends TouchQueError {
  constructor(message: string) {
    super(`TouchQue: ${message}`);
    this.name = 'TouchQueApprovalMismatchError';
  }
}
