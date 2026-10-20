// src/resources/Login.ts
// Login request management — request 2FA, check status, wait for approval
//
// This is the core of TouchQue: any action that needs 2FA confirmation
// (login, withdraw, transfer, purchase, etc.) uses these methods.

import { HttpClient } from '../core/HttpClient';
import {
  LoginRequestOptions,
  LoginRequestResponse,
  LoginStatusResponse,
  WaitForApprovalOptions,
  WaitForApprovalResult,
  VerifyOptions,
  VerifyChallenge,
} from '../types';
import { TouchQueTimeoutError, TouchQueRejectedError, TouchQuePasskeyRequiredError } from '../errors';

export class Login {
  constructor(private readonly http: HttpClient) {}

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
   *
   * @example
   * // Silent sign-ins: once approved, this browser is known (see `risk.check`)
   * const response = await tq.login.request({
   *   externalUsername: 'user@company.com',
   *   type: 'LOGIN',
   *   browserProof: req.get('x-touchque-browser'),
   * });
   */
  async request(options: LoginRequestOptions): Promise<LoginRequestResponse> {
    return this.http.post<LoginRequestResponse>('/login/request', {
      externalUsername: options.externalUsername,
      type: options.type,
      ...(options.referenceId && { referenceId: options.referenceId }),
      ...(options.clientIp && { clientIp: options.clientIp }),
      ...(options.userAgent && { userAgent: options.userAgent }),
      ...(options.details && { details: options.details }),
      ...(options.requireBiometric && { requireBiometric: options.requireBiometric }),
      ...(options.requireNumberMatch && { requireNumberMatch: options.requireNumberMatch }),
      ...(options.browserProof && { browserProof: options.browserProof }),
      ...(options.context && { context: options.context }),
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
  async status(requestId: string): Promise<LoginStatusResponse> {
    return this.http.get<LoginStatusResponse>(`/login/status/${encodeURIComponent(requestId)}`);
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
   * @throws {TouchQuePasskeyRequiredError} If the request now needs a passkey
   *   (`reason: 'step_up'`: the user approved on the phone during a call);
   *   finish it in the browser with `@touchque/web` `passkeys.approveLogin({ requestId })`
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
  async waitForApproval(options: WaitForApprovalOptions): Promise<WaitForApprovalResult> {
    const timeout = options.timeout || 30000;
    const pollInterval = options.pollInterval || 400; // 0.4s default polling
    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
      const { status, requiresPasskey } = await this.status(options.requestId);

      if (status === 'CONFIRMED') {
        return { approved: true, status };
      }

      if (status === 'REJECTED') {
        throw new TouchQueRejectedError(options.requestId);
      }

      if (status === 'EXPIRED') {
        throw new TouchQueTimeoutError(options.requestId, timeout);
      }

      // Vishing Shield: the phone was on a call at the tap, so the request now
      // waits for a passkey in the browser; polling would only run into the timeout.
      if (status === 'PENDING' && requiresPasskey) {
        throw new TouchQuePasskeyRequiredError(options.requestId, 'step_up');
      }

      // Wait before next poll
      await new Promise((resolve) => setTimeout(resolve, pollInterval));
    }

    // Timeout reached
    throw new TouchQueTimeoutError(options.requestId, timeout);
  }

  /**
   * Convenience: Send a 2FA request AND wait for approval in one call.
   *
   * Perfect for protecting any action with a single function call.
   *
   * @throws {TouchQueRejectedError} User rejected
   * @throws {TouchQueTimeoutError} User didn't respond in time
   * @throws {TouchQuePasskeyRequiredError} A passkey must approve it (policy, or the
   *   user tapped Approve during a call)
   *
   * With number matching (your `requireNumberMatch`, a workspace policy or
   * the risk engine can turn it on), the user must pick a number on the
   * phone: show `challengeCode` to the user from `onChallenge`, which runs
   * before verify() waits. Otherwise the user has to guess.
   *
   * @example
   * const result = await tq.login.verify({
   *   externalUsername: 'user@company.com',
   *   type: 'SEND_MONEY',
   *   referenceId: 'order_789',
   *   onChallenge: ({ challengeCode }) => {
   *     if (challengeCode) showOnScreen(`Pick ${challengeCode} on your phone`);
   *   },
   * });
   * // If we reach here, the user approved
   * executeAction();
   */
  async verify(
    options: VerifyOptions
  ): Promise<WaitForApprovalResult & { requestId: string; challengeCode?: string }> {
    const { timeout, pollInterval, onChallenge, ...requestOptions } = options;

    // Step 1: Send the 2FA request
    const loginReq = await this.request(requestOptions);
    // Passkey-only (phishing-resistant policy): nothing was pushed, so don't poll for 30 s.
    if (loginReq.requiresPasskey) throw new TouchQuePasskeyRequiredError(loginReq.requestId);

    // Step 1b: the number to show, before waiting (the phone asks for it).
    if (onChallenge) {
      const challenge: VerifyChallenge = {
        requestId: loginReq.requestId,
        expiresAt: loginReq.expiresAt,
        ...(loginReq.challengeCode && { challengeCode: loginReq.challengeCode }),
        ...(loginReq.reasons && { reasons: loginReq.reasons }),
        ...(loginReq.caseCode && { caseCode: loginReq.caseCode }),
      };
      try {
        const out = onChallenge(challenge) as Promise<unknown> | undefined;
        if (out && typeof out.catch === 'function') {
          out.catch((err: unknown) => console.warn('[TouchQue] onChallenge failed:', err instanceof Error ? err.message : err));
        }
      } catch (err) {
        console.warn('[TouchQue] onChallenge failed:', err instanceof Error ? err.message : err);
      }
    }

    // Step 2: Wait for the user's response
    const result = await this.waitForApproval({
      requestId: loginReq.requestId,
      timeout,
      pollInterval,
    });

    return {
      ...result,
      requestId: loginReq.requestId,
      challengeCode: loginReq.challengeCode,
    };
  }

  /**
   * Approve a pending 2FA request using a Recovery Code.
   * Useful when a user loses their phone and needs to bypass 2FA
   * using one of the backup codes generated during setup.
   */
  async approveWithRecoveryCode(options: { requestId: string; code: string }): Promise<{ success: boolean; message: string }> {
    return this.http.post<{ success: boolean; message: string }>('/login/recovery', {
      requestId: options.requestId,
      code: options.code,
    });
  }

  /**
   * Report a request you later learned was fraud — a chargeback, a confirmed
   * account takeover, a scam the user was talked into. TouchQue's risk engine
   * learns from it (it is the strongest signal it gets) and the report is
   * kept in your audit log. The request's status does not change. Safe to
   * call more than once: a repeat answers `alreadyReported: true`.
   */
  async reportFraud(requestId: string, options: ReportFraudOptions = {}): Promise<ReportFraudResponse> {
    if (!requestId) throw new Error('reportFraud() needs the request id');
    return this.http.post<ReportFraudResponse>(`/login/${encodeURIComponent(requestId)}/report-fraud`, {
      ...(options.reason && { reason: options.reason }),
      ...(options.note && { note: options.note }),
    });
  }
}

export type FraudReason = 'chargeback' | 'account_takeover' | 'social_engineering' | 'other';

export interface ReportFraudOptions {
  /** Default 'other'. */
  reason?: FraudReason;
  /** Free text for your audit log, at most 500 characters. */
  note?: string;
}

export interface ReportFraudResponse {
  reported: true;
  /** true when this request had already been reported. */
  alreadyReported: boolean;
  requestId: string;
}
