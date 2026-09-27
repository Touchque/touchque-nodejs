// src/index.ts
// TouchQue Node.js SDK
//
//   // .env: TQ_API_KEY=tq_…  TQ_API_SECRET=…
//   const { requireTouchQue } = require('@touchque/node');
//   app.post('/transfer', requireTouchQue('SEND_MONEY'), (req, res) => { … });
//
// The guard answers 202 { touchque: step, token } until the user approves on
// their phone; your page shows the step (matching number, first-time QR) in
// its own design and sends the request again with the token. See README.

import { HttpClient } from './core/HttpClient';
import { Auth } from './resources/Auth';
import { Login } from './resources/Login';
import { Webhook } from './resources/Webhook';
import { WebAuthn } from './resources/WebAuthn';
import { Offline } from './resources/Offline';
import { Actions } from './resources/Actions';
import { TouchQueConfig } from './types';
import { TouchQueConfigError } from './errors';
import { registerInternals } from './internal';
import { start, check, complete, Step, StartOptions, Approval, CompleteExpectations } from './steps';

// Export everything developers might need
export * from './types';
export * from './errors';
export * from './resources/Auth';
export * from './resources/Login';
export * from './resources/Webhook';
export * from './resources/WebAuthn';
export * from './resources/Offline';
export * from './resources/Actions';
export type { Step, StepState, StartOptions, Approval, CompleteExpectations } from './steps';

export const DEFAULT_BASE_URL = 'https://api.touchque.com';

export class TouchQue {
  public readonly auth: Auth;
  public readonly login: Login;
  /** Webhook signature verification */
  public readonly webhook: Webhook;
  /** WebAuthn/FIDO2 (passkey) registration and login approval */
  public readonly webauthn: WebAuthn;
  /** Offline Sign — QR challenge / typed code approvals that work with the phone offline */
  public readonly offline: Offline;
  /** Action types (LOGIN, SEND_MONEY…) */
  public readonly actions: Actions;

  /**
   * @param config - Optional. Falls back to the environment:
   *   TQ_API_KEY, TQ_API_SECRET, TQ_API_URL (default https://api.touchque.com).
   *
   * @example
   * const tq = new TouchQue();                       // from the environment
   * const tq = new TouchQue({ apiKey, apiSecret });  // explicit
   */
  constructor(config: Partial<TouchQueConfig> = {}) {
    const env = typeof process !== 'undefined' ? process.env : {};
    const resolved: TouchQueConfig = {
      apiKey: config.apiKey ?? env.TQ_API_KEY ?? '',
      apiSecret: config.apiSecret ?? env.TQ_API_SECRET ?? '',
      baseUrl: config.baseUrl ?? env.TQ_API_URL ?? DEFAULT_BASE_URL,
      timeout: config.timeout,
    };
    if (!resolved.apiKey || !resolved.apiSecret) {
      throw new TouchQueConfigError('Set TQ_API_KEY and TQ_API_SECRET (or pass { apiKey, apiSecret }).');
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
  start(action: string, options: StartOptions): Promise<Step> {
    return start({ http: httpOf(this), auth: this.auth, login: this.login, offline: this.offline }, action, options);
  }

  /** Where a started approval is now: waiting, approved, rejected, expired… */
  check(requestId: string): Promise<Step> {
    return check({ http: httpOf(this), auth: this.auth, login: this.login, offline: this.offline }, requestId);
  }

  /**
   * Uses an approved request exactly once, after checking it is for this user,
   * action and transaction. Call it right before doing the protected thing.
   */
  complete(requestId: string, expect: CompleteExpectations): Promise<Approval> {
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
  public protect<TArgs extends any[], TReturn>(
    fn: (...args: TArgs) => Promise<TReturn> | TReturn,
    options: import('./types').ProtectOptions<TArgs>
  ): (...args: TArgs) => Promise<TReturn> {
    return async (...args: TArgs): Promise<TReturn> => {
      const externalUsername = options.getUserIdentifier(...args);
      const referenceId = options.getReferenceId ? options.getReferenceId(...args) : undefined;
      const context = options.getContext ? options.getContext(...args) : undefined;

      // Send 2FA request and wait for user approval
      await this.login.verify({
        externalUsername,
        type: options.type,
        referenceId,
        ...context,
        timeout: options.timeout,
        pollInterval: options.pollInterval
      });
      
      // If we reach here, it was approved. Call the original function.
      return fn(...args);
    };
  }
}

// ─── Re-export everything for convenience ───

export { Auth } from './resources/Auth';
export { Login } from './resources/Login';
export { Webhook } from './resources/Webhook';
export { verifyApprovalProof, detailsDigest } from './approvalProof';
export type { ApprovalProof, VerifyApprovalProofOptions } from './approvalProof';

export {
  TouchQueError,
  TouchQueAPIError,
  TouchQueNetworkError,
  TouchQueTimeoutError,
  TouchQueRejectedError,
  TouchQueWebhookSignatureError,
  TouchQueConfigError,
} from './errors';

export { requireTouchQue, TouchQueMiddlewareOptions } from './middleware/express';
export { withTouchQue, WithTouchQueOptions } from './next';
export { runGuard, GUARD_HEADERS, GuardInput, GuardResult, GuardBody } from './guard';
export { signGuardToken, verifyGuardToken, normalizeDetails } from './steps';
export { touchqueRouter, TouchQueRouterOptions } from './router';
export type { RateLimitOptions } from './rateLimiter';

export type {
  TouchQueConfig,
  GenerateSecretOptions,
  GenerateSecretResponse,
  ResetSecretOptions,
  ResetSecretResponse,
  LoginType,
  LoginRequestOptions,
  LoginRequestResponse,
  LoginStatus,
  LoginStatusResponse,
  WaitForApprovalOptions,
  WaitForApprovalResult,
  VerifyWebhookOptions,
  WebhookPayload,
  ProtectOptions,
} from './types';

import { resources as internalResources } from './internal';
function httpOf(client: TouchQue): HttpClient {
  return internalResources(client).http;
}

let defaultClient: TouchQue | undefined;
/** The client built from TQ_API_KEY / TQ_API_SECRET, created on first use. */
export function getDefaultClient(): TouchQue {
  if (!defaultClient) defaultClient = new TouchQue();
  return defaultClient;
}
