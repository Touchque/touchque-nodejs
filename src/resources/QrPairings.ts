// src/resources/QrPairings.ts
// Pairing a browser by QR code: your page shows a QR code, the person scans it
// with the TouchQue app, and the phone that scanned is the one asked to approve.
//
// 1. Your page gets the thumbprint of its browser key (`@touchque/web`
//    `browserKey.thumbprint()`) and sends it to your server.
// 2. `create({ keyThumbprint, clientIp, userAgent })` registers a pairing and
//    returns `uri` (touchque://pair-browser?…): show it as a QR code. It can be
//    scanned once, for `ttlSeconds` (default 120). The nonce in it never leaves
//    your server and the QR: TouchQue keeps only its hash.
// 3. Poll `get(pairingId)`: `scanned` once a phone holding one of your users'
//    accounts read it (`externalUsername`, `proximity`: same network, same
//    country), `confirmed` once the person went on, `reported` when they said
//    someone told them to scan it (their 2FA freezes).
// 4. `login.request({ externalUsername, qrPairing: pairingId })` asks that phone,
//    once, with number matching; the browser key's fingerprint is one of the
//    rows the phone signs. When your own checks say no, `refuse(pairingId,
//    { reason, message })` and the phone shows why.

import { createHash, randomBytes } from 'node:crypto';
import { HttpClient } from '../core/HttpClient';
import { TouchQueConfigError } from '../errors';
import { CreatedQrPairing, CreateQrPairingOptions, QrPairing, RefuseQrPairingOptions } from '../types';

/** What `refuse` may tell the phone. */
export const QR_PAIRING_REFUSAL_REASONS = ['policy', 'device_not_approved', 'too_many_browsers', 'rate_limited', 'no_account', 'other'] as const;

const B64URL_43 = /^[A-Za-z0-9_-]{43}$/;

/** What the QR code says: `touchque://pair-browser?v=1&p=<pairing>&n=<nonce>&k=<key thumbprint>`. */
export function qrPairingUri(pairingId: string, nonce: string, keyThumbprint: string): string {
  return `touchque://pair-browser?v=1&p=${encodeURIComponent(pairingId)}&n=${encodeURIComponent(nonce)}&k=${encodeURIComponent(keyThumbprint)}`;
}

export class QrPairings {
  constructor(private readonly http: HttpClient) {}

  /**
   * Registers a pairing for one browser and returns the QR code's text.
   *
   * @example
   * const pairing = await tq.qrPairings.create({ keyThumbprint, clientIp: req.ip, userAgent: req.get('user-agent') });
   * res.json({ pairingId: pairing.pairingId, qr: pairing.uri });   // render pairing.uri as a QR code
   */
  async create(options: CreateQrPairingOptions): Promise<CreatedQrPairing> {
    if (!B64URL_43.test(String(options?.keyThumbprint ?? ''))) {
      throw new TouchQueConfigError('qrPairings.create() needs keyThumbprint: the RFC 7638 thumbprint of the browser key, base64url (43 characters).');
    }
    const ttl = options.ttlSeconds;
    if (ttl !== undefined && (!Number.isInteger(ttl) || ttl < 30 || ttl > 300)) {
      throw new TouchQueConfigError('qrPairings.create(): ttlSeconds must be 30 to 300.');
    }
    const nonce = randomBytes(32).toString('base64url');
    const created = await this.http.post<{ pairingId: string; expiresAt: string }>('/qr-pairings', {
      nonceHash: createHash('sha256').update(nonce, 'utf8').digest('base64url'),
      keyThumbprint: options.keyThumbprint,
      ...(options.clientIp && { clientIp: options.clientIp }),
      ...(options.userAgent && { userAgent: options.userAgent }),
      ...(options.browser && { browser: options.browser }),
      ...(options.os && { os: options.os }),
      ...(ttl !== undefined && { ttlSeconds: ttl }),
    });
    return { ...created, nonce, uri: qrPairingUri(created.pairingId, nonce, options.keyThumbprint) };
  }

  /** Where a pairing stands; once scanned, who scanned it and how near the phone was. */
  get(pairingId: string): Promise<QrPairing> {
    return this.http.get<QrPairing>(`/qr-pairings/${encodeURIComponent(requireId(pairingId, 'get'))}`);
  }

  /**
   * Your own checks refused a scanned pairing (an unapproved computer, too many
   * browsers…): the phone shows `message`. Only a `scanned` or `confirmed`
   * pairing can be refused (409 `not_open` otherwise).
   */
  refuse(pairingId: string, options: RefuseQrPairingOptions): Promise<QrPairing> {
    if (!QR_PAIRING_REFUSAL_REASONS.includes(options?.reason as (typeof QR_PAIRING_REFUSAL_REASONS)[number])) {
      throw new TouchQueConfigError(`qrPairings.refuse(): reason must be one of ${QR_PAIRING_REFUSAL_REASONS.join(', ')}.`);
    }
    if (typeof options.message !== 'string' || !options.message.trim()) {
      throw new TouchQueConfigError('qrPairings.refuse() needs message: what the phone shows (up to 300 characters).');
    }
    return this.http.post<QrPairing>(`/qr-pairings/${encodeURIComponent(requireId(pairingId, 'refuse'))}/outcome`, {
      reason: options.reason,
      message: options.message,
      ...(options.caseCode && { caseCode: options.caseCode }),
      ...(options.deviceCode && { deviceCode: options.deviceCode }),
    });
  }
}

function requireId(pairingId: string, method: string): string {
  if (typeof pairingId !== 'string' || !pairingId) throw new TouchQueConfigError(`qrPairings.${method}() needs the pairingId.`);
  return pairingId;
}
