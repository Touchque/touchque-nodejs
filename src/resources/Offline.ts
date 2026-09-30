// Offline Sign — approvals that work while the user's PHONE has no internet.
//
// The user's computer (online) shows a QR carrying a challenge encrypted for the user's phone
// challenge. The phone scans it offline, shows the brand, the action and the
// transaction details, asks for Face ID and displays a 7-character code; the
// user types it back and `verify()` checks it. Optionally (workspace policy
// `offlineTotpEnabled`) the user can type the rolling time-based code instead
// of scanning — lower assurance, never accepted for critical actions.

import { HttpClient } from '../core/HttpClient';
import { TouchQueAPIError } from '../errors';
import {
  OfflineChallengeOptions,
  OfflineChallengeResponse,
  OfflineTotpVerifyOptions,
  OfflineVerifyOptions,
  OfflineVerifyResult,
} from '../types';

/** HTTP statuses that mean "not approved" rather than "something broke". */
const NOT_APPROVED_STATUSES = [401, 403, 404, 409, 410, 423, 429];

export class Offline {
  constructor(private readonly http: HttpClient) {}

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
  async challenge(options: OfflineChallengeOptions): Promise<OfflineChallengeResponse> {
    return this.http.post<OfflineChallengeResponse>('/offline/challenge', {
      externalUsername: options.externalUsername,
      type: options.type,
      ...(options.details && { details: options.details }),
      ...(options.clientIp && { clientIp: options.clientIp }),
      ...(options.userAgent && { userAgent: options.userAgent }),
      ...(options.ttlSeconds !== undefined && { ttlSeconds: options.ttlSeconds }),
      ...(options.includeQrImage === false && { includeQrImage: false }),
      ...(options.requestId && { requestId: options.requestId }),
      ...(options.requireNumberMatch === true && { requireNumberMatch: true }),
    });
  }

  /**
   * Check the code the user typed. Resolves `{ approved: true }` on success and
   * `{ approved: false, reason }` for a wrong / expired / used / locked
   * challenge (never throws for those); other failures (network, 5xx) throw.
   * A challenge locks after 5 wrong codes and a code works once.
   */
  async verify(options: OfflineVerifyOptions): Promise<OfflineVerifyResult> {
    return this.notApprovedAsResult(() =>
      this.http.post<OfflineVerifyResult>('/offline/verify', { challengeId: options.challengeId, code: options.code })
    );
  }

  /**
   * Check a time-based code typed from the app (no QR). Requires the workspace
   * policy `offlineTotpEnabled`. Pass `type` when the code is for a specific
   * action so critical actions are refused.
   */
  async verifyTotp(options: OfflineTotpVerifyOptions): Promise<OfflineVerifyResult> {
    return this.notApprovedAsResult(() =>
      this.http.post<OfflineVerifyResult>('/offline/totp/verify', {
        externalUsername: options.externalUsername,
        code: options.code,
        ...(options.type && { type: options.type }),
        ...(options.clientIp && { clientIp: options.clientIp }),
        ...(options.requestId && { requestId: options.requestId }),
      })
    );
  }

  private async notApprovedAsResult(call: () => Promise<OfflineVerifyResult>): Promise<OfflineVerifyResult> {
    try {
      return await call();
    } catch (error) {
      if (error instanceof TouchQueAPIError && NOT_APPROVED_STATUSES.includes(error.status)) {
        const data = error.data as unknown as { reason?: string; error?: string; attemptsLeft?: number };
        return { approved: false, reason: data.reason ?? data.error ?? 'not_approved', attemptsLeft: data.attemptsLeft };
      }
      throw error;
    }
  }
}
