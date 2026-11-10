// Offline Sign — approvals that work while the user's PHONE has no internet.
//
// The user's computer (online) shows a QR carrying a challenge encrypted for the user's phone
// challenge. The phone scans it offline, shows the brand, the action and the
// transaction details, asks for Face ID and displays a 7-character code; the
// user types it back and `verify()` checks it. Optionally (workspace policy
// `offlineTotpEnabled`) the user can type the rolling time-based code instead
// of scanning — lower assurance, never accepted for critical actions.

import * as crypto from 'crypto';
import { HttpClient } from '../core/HttpClient';
import { TouchQueAPIError } from '../errors';
import {
  OfflineChallengeOptions,
  OfflineChallengeResponse,
  OfflineTotpVerifierUser,
  OfflineTotpVerifiersOptions,
  OfflineTotpVerifiersResult,
  OfflineTotpVerifyOptions,
  OfflineVerifyOptions,
  OfflineVerifyResult,
} from '../types';

const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

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

  /**
   * For checking typed time-based codes while your server cannot reach
   * TouchQue (an outage): salted, slow digests of each user's next codes,
   * never a key. Check a typed code with `matchTotpVerifier()`. Requires the workspace policies `offlineTotpEnabled` and
   * `outageVerifiersEnabled`. Fetch again every few minutes from the step you
   * have: removed and frozen users fall out.
   */
  async totpVerifiers(options: OfflineTotpVerifiersOptions): Promise<OfflineTotpVerifiersResult> {
    return this.http.post<OfflineTotpVerifiersResult>('/offline/totp/verifiers', {
      externalUsernames: options.externalUsernames,
      ...(options.fromStep !== undefined && { fromStep: options.fromStep }),
      ...(options.steps !== undefined && { steps: options.steps }),
    });
  }

  /**
   * Checks a typed code against one user's verifiers from `totpVerifiers()`,
   * without calling TouchQue. Returns the step the code belongs to (the
   * current one or one either side), or null. Accept each step once: remember
   * the step you accepted for the user and refuse codes for it or an older one.
   */
  matchTotpVerifier(
    verifiers: OfflineTotpVerifiersResult,
    user: OfflineTotpVerifierUser,
    code: string,
    at: Date = new Date(),
  ): number | null {
    const given = typeof code === 'string' ? code.toUpperCase().replace(/[\s-]/g, '') : '';
    if (given.length !== 7 || [...given].some((c) => !CODE_ALPHABET.includes(c))) return null;
    const now = Math.floor(at.getTime() / 1000 / verifiers.stepSeconds);
    const salt = Buffer.from(user.salt, 'base64');
    const digests = Buffer.from(user.digests, 'base64');
    const L = verifiers.kdf.length;
    for (const step of [now, now - 1, now + 1]) {
      if (step < user.fromStep || step > verifiers.notAfterStep) continue;
      const at = (step - user.fromStep) * 2 * L;
      if (at + 2 * L > digests.length) continue;
      const got = crypto.pbkdf2Sync(given, Buffer.concat([salt, Buffer.from(`:${step}`)]), verifiers.kdf.iterations, L, 'sha256');
      if (crypto.timingSafeEqual(digests.subarray(at, at + L), got) || crypto.timingSafeEqual(digests.subarray(at + L, at + 2 * L), got)) return step;
    }
    return null;
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
