// src/resources/SafeGuard.ts
// Safe Guard: a Safe transaction approved on the approver's phone for TouchQueSafeGuard (the
// guard on your Safe). You send the raw transaction; the phone gets the raw fields only, decodes
// them itself, shows its own rows and signs, with a key only its biometrics unlock, a 105-byte
// approval of the hash it computed. TouchQue never holds a key that can approve.
//
// 1. `request({ externalUsername, type, safeTx })` asks the phone (same pipeline as
//    `login.request`: risk engine, push limit, Vishing Shield, case code, always biometrics).
// 2. `waitForApproval({ requestId })` (or poll `status`) until the phone answered.
// 3. Check `safeTx.approval` yourself with `verifySafeApproval` (safeGuard.ts): it needs your own
//    transaction and the approver's key from the guard, not this response.
// 4. `purpose: 'approve'`: `withSafeApprovals(ownerSignatures, approvals)` as the signatures of
//    `execTransaction`. `purpose: 'schedule'`: send `safeScheduleCall(safe, governanceHash,
//    approvals)` to the guard; the change runs once its waiting time is over.

import { HttpClient } from '../core/HttpClient';
import { TouchQueConfigError, TouchQueRejectedError, TouchQueTimeoutError } from '../errors';
import { SafeGuardRequestOptions, SafeGuardRequestResponse, SafeGuardStatusResponse, SafeGuardTx, WaitForApprovalOptions } from '../types';

const big = (v: unknown) => (typeof v === 'bigint' ? v.toString() : v);

/** JSON has no bigint: large values go as decimal strings, as the API takes them. */
function wire(safeTx: SafeGuardTx): Record<string, unknown> {
  const tx = safeTx.tx;
  return {
    ...safeTx,
    chainId: big(safeTx.chainId),
    tx: {
      ...tx, value: big(tx.value), safeTxGas: big(tx.safeTxGas), baseGas: big(tx.baseGas), gasPrice: big(tx.gasPrice), nonce: big(tx.nonce),
    },
  };
}

export class SafeGuard {
  constructor(private readonly http: HttpClient) {}

  /**
   * Asks the approver's phone to approve a Safe transaction.
   *
   * @example
   * const { requestId, safeTx } = await tq.safeGuard.request({
   *   externalUsername: 'treasurer@acme.com',
   *   type: 'safe_payment',               // an action type from your dashboard
   *   safeTx: {
   *     chainId: 1, safe: SAFE, guard: GUARD,
   *     tx: { to, value: '0', data, operation: 0, nonce: 42 },
   *     config: { threshold: 2, govThreshold: 3, govDelay: 172800, exitDelay: 259200 },
   *     batchTargets: [MULTI_SEND_CALL_ONLY],
   *     approverIndex: 0,                 // this person's index in the guard
   *   },
   * });
   */
  async request(options: SafeGuardRequestOptions): Promise<SafeGuardRequestResponse> {
    if (!options?.externalUsername) throw new TouchQueConfigError('safeGuard.request() needs externalUsername.');
    if (!options.type) throw new TouchQueConfigError('safeGuard.request() needs type: an action type from your dashboard.');
    if (!options.safeTx || typeof options.safeTx !== 'object' || !options.safeTx.tx) {
      throw new TouchQueConfigError('safeGuard.request() needs safeTx: { chainId, safe, guard, tx, config, approverIndex }.');
    }
    return this.http.post<SafeGuardRequestResponse>('/safe-guard/approvals', {
      externalUsername: options.externalUsername,
      type: options.type,
      safeTx: wire(options.safeTx),
      ...(options.referenceId && { referenceId: options.referenceId }),
      ...(options.expiresIn !== undefined && { expiresIn: options.expiresIn }),
      ...(options.clientIp && { clientIp: options.clientIp }),
      ...(options.userAgent && { userAgent: options.userAgent }),
    });
  }

  /** The request's status and, once approved, the approval (`safeTx.approval`, 105 bytes hex). */
  async status(requestId: string): Promise<SafeGuardStatusResponse> {
    if (!requestId) throw new TouchQueConfigError('safeGuard.status() needs a requestId.');
    return this.http.get<SafeGuardStatusResponse>(`/safe-guard/approvals/${encodeURIComponent(requestId)}`);
  }

  /**
   * Polls until the phone approved and returns the status with the approval. Throws
   * `TouchQueRejectedError` when the person said no, `TouchQueTimeoutError` when it expired or
   * `timeout` (default 5 minutes, the request's own life) ran out.
   */
  async waitForApproval(options: WaitForApprovalOptions): Promise<SafeGuardStatusResponse> {
    const timeout = options.timeout || 300000;
    const pollInterval = options.pollInterval || 1500;
    const startTime = Date.now();
    while (Date.now() - startTime < timeout) {
      const status = await this.status(options.requestId);
      if (status.status === 'CONFIRMED') return status;
      if (status.status === 'REJECTED') throw new TouchQueRejectedError(options.requestId);
      if (status.status === 'EXPIRED') throw new TouchQueTimeoutError(options.requestId, timeout);
      await new Promise((resolve) => setTimeout(resolve, pollInterval));
    }
    throw new TouchQueTimeoutError(options.requestId, timeout);
  }
}
