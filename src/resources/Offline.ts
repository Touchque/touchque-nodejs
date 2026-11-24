// Offline Sign — approvals that work while the user's PHONE has no internet.
//
// The user's computer (online) shows a QR carrying a challenge encrypted for the user's phone
// challenge. The phone scans it offline, shows the brand, the action and the
// transaction details, asks for Face ID and displays a 7-character code; the
// user types it back and `verify()` checks it. Optionally (workspace policy
// `offlineTotpEnabled`) the user can type the rolling time-based code instead
// of scanning — lower assurance, never accepted for critical actions.
//
// Offline sign-in packs are for a DEVICE with no network (a laptop for days, a
// kiosk, a field tablet): `issueDevicePack()` gives it the person's next offline
// sign-ins, and `verifyDeviceCode()` checks a typed code on the device itself.

import * as crypto from 'crypto';
import { HttpClient } from '../core/HttpClient';
import { TouchqueAPIError } from '../errors';
import {
  OfflineChallengeOptions,
  OfflineChallengeResponse,
  OfflineDevicePack,
  OfflineDevicePackOptions,
  OfflineDeviceReportOptions,
  OfflineDeviceReportResult,
  OfflineDeviceRevokeOptions,
  OfflineDeviceRevokeResult,
  OfflineTotpVerifierUser,
  OfflineTotpVerifiersOptions,
  OfflineTotpVerifiersResult,
  OfflineTotpVerifyOptions,
  OfflineVerifyOptions,
  OfflineVerifyResult,
} from '../types';

const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const DEVICE_CODE_LENGTH = 10;

/** HTTP statuses that mean "not approved" rather than "something broke". */
const NOT_APPROVED_STATUSES = [401, 403, 404, 409, 410, 423, 429];

/**
 * A typed offline sign-in code in its canonical form: upper case, without spaces or dashes. Null
 * unless it is exactly 10 characters of the codes' alphabet (A-Z and 2-9 without I and O).
 */
export function normalizeDeviceCode(input: unknown): string | null {
  if (typeof input !== 'string') return null;
  const code = input.replace(/[ \t\n\r\f\v-]/g, '').replace(/[a-z]/g, (c) => c.toUpperCase());
  if (code.length !== DEVICE_CODE_LENGTH) return null;
  for (const c of code) if (!CODE_ALPHABET.includes(c)) return null;
  return code;
}

/** An offline sign-in code the way the phone shows it, `XXXXX-XXXXX`; null unless {@link normalizeDeviceCode} accepts it. */
export function formatDeviceCode(input: unknown): string | null {
  const code = normalizeDeviceCode(input);
  return code === null ? null : `${code.slice(0, 5)}-${code.slice(5)}`;
}

/**
 * Checks the code a person typed against one slot of an offline sign-in pack, on the device and
 * with no network: PBKDF2-SHA256(code, salt || ":" || index, kdf.iterations, kdf.length) compared
 * in constant time with the slot's digest. Case, spaces and dashes are ignored; anything that is
 * not 10 characters of the codes' alphabet is false without computing the digest, and so is a KDF
 * other than pbkdf2-sha256. Check the lowest unused slot only (see `Offline.issueDevicePack()`).
 * The digest takes a moment by design (600,000 iterations), so it runs off the event loop.
 */
export async function verifyDeviceCode(
  kdf: { name?: string; iterations: number; length: number },
  slot: { index: number; salt: string; digest: string },
  code: string,
): Promise<boolean> {
  const given = normalizeDeviceCode(code);
  if (given === null || !kdf || !slot) return false;
  if (kdf.name && kdf.name !== 'pbkdf2-sha256') return false;
  const { iterations, length } = kdf;
  if (!Number.isSafeInteger(iterations) || iterations < 1 || iterations > 0x7fffffff) return false;
  if (!Number.isSafeInteger(length) || length < 1 || !Number.isSafeInteger(slot.index) || slot.index < 1) return false;
  if (typeof slot.salt !== 'string' || typeof slot.digest !== 'string') return false;
  const digest = Buffer.from(slot.digest, 'base64');
  if (digest.length !== length) return false;
  const salt = Buffer.concat([Buffer.from(slot.salt, 'base64'), Buffer.from(`:${slot.index}`)]);
  const got = await new Promise<Buffer>((resolve, reject) => {
    crypto.pbkdf2(given, salt, iterations, length, 'sha256', (err, key) => (err ? reject(err) : resolve(key)));
  });
  return crypto.timingSafeEqual(got, digest);
}

export class Offline {
  constructor(private readonly http: HttpClient) {}

  /**
   * Issue a challenge (encrypted for the user's phone) and get the QR to show.
   *
   * `qrDataUrl` is a ready-to-render PNG (`<img src={qrDataUrl}>`); `qr` is the
   * raw text if you draw the QR yourself. The challenge expires after
   * `expiresInSeconds` (default 120) — enforced by Touchque, not by the phone.
   * For a terminal or a small screen pass `qrFormat: 'compact'` (a smaller
   * `TQ3:` QR, same code) and `includeQrTerminal: true` to get `qrTerminal`,
   * the QR drawn with Unicode half blocks, ready to print.
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
      ...(options.qrFormat && { qrFormat: options.qrFormat }),
      ...(options.includeQrTerminal === true && { includeQrTerminal: true }),
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
   * For checking typed codes while your server cannot reach Touchque (an
   * outage): salted, slow digests of each user's next OUTAGE codes for one
   * scope, never a key. Outage codes are not the normal time-based code: each
   * scope (an organization, or your own outage server) has its own, the
   * user's phone shows them under the normal code ("<name>: code for when
   * Touchque can't be reached") once a call has named the scope for the user,
   * and `verifyTotp()` never accepts them. Check a typed code with
   * `matchTotpVerifier()`. Requires the workspace policies `offlineTotpEnabled`
   * and `outageVerifiersEnabled`. Fetch again every few minutes from the step
   * you have: removed and frozen users fall out. Quotas are per scope
   * (429 `scope_quota_exceeded`) and per workspace.
   */
  async totpVerifiers(options: OfflineTotpVerifiersOptions): Promise<OfflineTotpVerifiersResult> {
    return this.http.post<OfflineTotpVerifiersResult>('/offline/totp/verifiers', {
      externalUsernames: options.externalUsernames,
      scope: options.scope,
      ...(options.fromStep !== undefined && { fromStep: options.fromStep }),
      ...(options.steps !== undefined && { steps: options.steps }),
    });
  }

  /**
   * Checks a typed code against one user's verifiers from `totpVerifiers()`,
   * without calling Touchque. Returns the step the code belongs to (the
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
    const per = verifiers.digestsPerStep ?? 2;
    for (const step of [now, now - 1, now + 1]) {
      if (step < user.fromStep || step > verifiers.notAfterStep) continue;
      const at = (step - user.fromStep) * per * L;
      if (at + per * L > digests.length) continue;
      const got = crypto.pbkdf2Sync(given, Buffer.concat([salt, Buffer.from(`:${step}`)]), verifiers.kdf.iterations, L, 'sha256');
      for (let k = 0; k < per; k++) {
        if (crypto.timingSafeEqual(digests.subarray(at + k * L, at + (k + 1) * L), got)) return step;
      }
    }
    return null;
  }

  /**
   * The next offline sign-ins of a person on one device (a laptop, a kiosk, a field tablet) that
   * must sign them in with no network. Ask only right after a sign-in the person approved on the
   * phone at that device itself, never for a remote session. Each slot is the slow digest of a
   * 10-character code and a QR (`TQ4:`) only the person's phone opens: nothing in the pack can
   * produce a code. Offline, the device shows the lowest unused slot's QR (`qr`, or `qrTerminal`
   * in a terminal); the person scans it with the Touchque app, approves and types the code
   * (XXXXX-XXXXX); check it with {@link verifyDeviceCode}. Indexes continue from the device's last
   * pack and are never issued twice. Requires the workspace policies `offlineSignEnabled` and
   * `offlineDevicePacksEnabled` (403 `offline_device_packs_disabled`); refused under a passkey-only
   * policy (403 `phishing_resistant_required`), for a phone not enrolled for offline sign (409
   * `device_not_enrolled_for_offline`), for a revoked device (409 `scope_revoked`) and after 12
   * packs an hour per person and device (429 `too_many_packs`).
   *
   * @example
   * const pack = await tq.offline.issueDevicePack({
   *   externalUsername: 'jane@acme.com',
   *   scope: { id: 'pc-0f1e2d3c4b5a6978', name: 'LAPTOP-JANE' },
   *   account: 'ACME\\jane',
   * });
   */
  async issueDevicePack(options: OfflineDevicePackOptions): Promise<OfflineDevicePack> {
    return this.http.post<OfflineDevicePack>('/offline/device-packs', {
      externalUsername: options.externalUsername,
      scope: { id: options.scope.id, name: options.scope.name },
      account: options.account,
      ...(options.count !== undefined && { count: options.count }),
      ...(options.validDays !== undefined && { validDays: options.validDays }),
    });
  }

  /**
   * A device's offline sign-ins stop (lost, stolen, reinstalled): it gets no more packs, and the
   * person's phone refuses its codes once it has the list. Without `externalUsername`, every
   * person's packs on that device. A reinstalled device needs a new scope id.
   */
  async revokeDeviceScope(options: OfflineDeviceRevokeOptions): Promise<OfflineDeviceRevokeResult> {
    return this.http.post<OfflineDeviceRevokeResult>('/offline/device-packs/revoke', {
      scopeId: options.scopeId,
      ...(options.externalUsername && { externalUsername: options.externalUsername }),
      ...(options.reason && { reason: options.reason }),
    });
  }

  /**
   * The slots a device accepted while it had no network, sent once it is back online: Touchque
   * writes one log row per slot with the time it happened. 404 `unknown_scope` when the device has
   * no pack for that person.
   */
  async reportDevicePackUse(options: OfflineDeviceReportOptions): Promise<OfflineDeviceReportResult> {
    return this.http.post<OfflineDeviceReportResult>('/offline/device-packs/report', {
      scopeId: options.scopeId,
      externalUsername: options.externalUsername,
      used: options.used.map((u) => ({ index: u.index, at: u.at instanceof Date ? u.at.toISOString() : u.at })),
    });
  }

  /** {@link verifyDeviceCode}, from the client: checks a typed code against one slot, with no network. */
  verifyDeviceCode(
    kdf: { name?: string; iterations: number; length: number },
    slot: { index: number; salt: string; digest: string },
    code: string,
  ): Promise<boolean> {
    return verifyDeviceCode(kdf, slot, code);
  }

  private async notApprovedAsResult(call: () => Promise<OfflineVerifyResult>): Promise<OfflineVerifyResult> {
    try {
      return await call();
    } catch (error) {
      if (error instanceof TouchqueAPIError && NOT_APPROVED_STATUSES.includes(error.status)) {
        const data = error.data as unknown as { reason?: string; error?: string; attemptsLeft?: number };
        return { approved: false, reason: data.reason ?? data.error ?? 'not_approved', attemptsLeft: data.attemptsLeft };
      }
      throw error;
    }
  }
}
