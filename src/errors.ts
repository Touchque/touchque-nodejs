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

  constructor(status: number, data: TouchQueErrorData) {
    const message = data.message || data.error || `TouchQue API Error: HTTP ${status}`;
    super(message);
    this.name = 'TouchQueAPIError';
    this.status = status;
    this.code = data.code;
    this.data = data;
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

  constructor(requestId: string) {
    super(`TouchQue: Request '${requestId}' must be approved with a passkey (phishing-resistant policy); no push was sent.`);
    this.name = 'TouchQuePasskeyRequiredError';
    this.requestId = requestId;
  }
}
