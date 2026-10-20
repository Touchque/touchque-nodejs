// src/resources/Recovery.ts
// Never Locked Out: move a user whose phone is lost, dead or replaced to a
// new phone without a help desk.
//
// 1. Let users name colleagues who can vouch for them (`setVouchers`), behind
//    an approval on their phone.
// 2. When the phone is gone, after the password (or your IdP): `start`. Show
//    `bindUri` as a QR for the TouchQue app on the new phone, then poll
//    `status` and show each voucher's `code`: the user reads it to the
//    colleague on a call, who types it on their own phone.
// 3. After the cooling-off nobody vetoed, the account is on the new phone
//    (`status: 'COMPLETED'`); critical actions wait 24 h (probation).
// Admins can stop a running recovery with `veto`.

import { HttpClient } from '../core/HttpClient';
import { TouchQueConfigError } from '../errors';
import {
  ListRecoveriesOptions,
  RecoveryCase,
  RecoveryStarted,
  RecoveryVouchersResponse,
  SetRecoveryVouchersOptions,
  StartRecoveryOptions,
  VetoRecoveryOptions,
} from '../types';

/** A recovery still waiting for the new phone, the vouchers or the cooling-off. */
export const isRecoveryOpen = (r: Pick<RecoveryCase, 'status'>): boolean => ['AWAITING_DEVICE', 'VOUCHING', 'COOLING'].includes(r.status);

export class Recovery {
  constructor(private readonly http: HttpClient) {}

  /** The colleagues a user named, and whether each can vouch today. */
  async vouchers(options: { externalUsername: string }): Promise<RecoveryVouchersResponse> {
    if (!options?.externalUsername) throw new TouchQueConfigError('recovery.vouchers() needs the user (externalUsername)');
    return this.http.get<RecoveryVouchersResponse>('/recovery/vouchers', { externalUsername: options.externalUsername });
  }

  /** Replaces the user's vouchers. Ask for the user's phone first: whoever sets them chooses who may move the account. */
  async setVouchers(options: SetRecoveryVouchersOptions): Promise<RecoveryVouchersResponse> {
    if (!options?.externalUsername) throw new TouchQueConfigError('recovery.setVouchers() needs the user (externalUsername)');
    if (!Array.isArray(options.vouchers)) throw new TouchQueConfigError('recovery.setVouchers() needs a list of vouchers');
    return this.http.post<RecoveryVouchersResponse>('/recovery/vouchers', { externalUsername: options.externalUsername, vouchers: options.vouchers });
  }

  /**
   * Starts moving the user to a new phone. Call it only after the first
   * factor. Throws TouchQueAPIError with `code` `not_enough_vouchers`,
   * `recovery_in_progress`, `blocked`, `frozen` or `rate_limited`.
   *
   * @example
   * const r = await tq.recovery.start({ externalUsername: user, clientIp: req.ip, displayName: 'Ada' });
   * showQr(r.bindUri); // the new phone scans it
   */
  async start(options: StartRecoveryOptions): Promise<RecoveryStarted> {
    if (!options?.externalUsername) throw new TouchQueConfigError('recovery.start() needs the user (externalUsername)');
    return this.http.post<RecoveryStarted>('/recovery/start', {
      externalUsername: options.externalUsername,
      ...(options.clientIp && { clientIp: options.clientIp }),
      ...(options.userAgent && { userAgent: options.userAgent }),
      ...(options.displayName && { displayName: options.displayName }),
      ...(options.fallbackVouchers?.length && { fallbackVouchers: options.fallbackVouchers }),
      ...(options.required !== undefined && { required: options.required }),
      ...(options.coolOffMinutes !== undefined && { coolOffMinutes: options.coolOffMinutes }),
      ...(options.details?.length && { details: options.details }),
      ...(options.noticeDetails?.length && { noticeDetails: options.noticeDetails }),
    });
  }

  /** The recovery now, with its receipt chain. Poll it while the user waits. */
  async status(recoveryId: string): Promise<RecoveryCase> {
    if (!recoveryId) throw new TouchQueConfigError('recovery.status() needs the recovery id');
    return this.http.get<RecoveryCase>(`/recovery/${encodeURIComponent(recoveryId)}`);
  }

  /** A user's recoveries, or (`open: true`) every running one of your workspace. */
  async list(options: ListRecoveriesOptions): Promise<RecoveryCase[]> {
    if (!options?.externalUsername && !options?.open) throw new TouchQueConfigError('recovery.list() needs externalUsername or open: true');
    const res = await this.http.get<{ recoveries: RecoveryCase[] }>('/recovery', {
      ...(options.externalUsername && { externalUsername: options.externalUsername }),
      ...(options.open && { open: 'true' }),
    });
    return Array.isArray(res?.recoveries) ? res.recoveries : [];
  }

  /** Stops a running recovery (e.g. an admin who does not believe it). Does not freeze the user. */
  async veto(recoveryId: string, options: VetoRecoveryOptions = {}): Promise<RecoveryCase> {
    if (!recoveryId) throw new TouchQueConfigError('recovery.veto() needs the recovery id');
    return this.http.post<RecoveryCase>(`/recovery/${encodeURIComponent(recoveryId)}/veto`, {
      ...(options.by && { by: options.by }),
      ...(options.reason && { reason: options.reason }),
    });
  }
}
