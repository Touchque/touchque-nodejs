// src/approvalProof.ts
// Verifies the device-signed proof of an approval ("what you see is what you
// sign"). When the user's phone holds a Secure Enclave key, every approval is
// signed by it over the request id, the action type, the number-match code
// and a digest of the transaction details the user was shown. The proof
// arrives in the SUCCESS webhook (`approvalProof`) and in
// `login.status(id).approvalProof`; verifying it here does not require
// trusting TouchQue: it proves the enrolled phone signed exactly these
// details.

import * as crypto from 'crypto';
import type { LoginRequestDetails } from './types';

export interface ApprovalProof {
  version: 'v2';
  algorithm: 'ECDSA-P256-SHA256';
  /** The exact text the device signed */
  message: string;
  /** base64 DER signature */
  signature: string;
  /** base64 X9.63 Secure Enclave public key of the approving device */
  publicKey: string;
}

export interface VerifyApprovalProofOptions {
  /** The request id returned by login.request() */
  requestId: string;
  /** The action type you sent (e.g. 'WITHDRAW') */
  type: string;
  /**
   * The details you sent with login.request(), exactly as you sent them.
   * Pass undefined when you sent none.
   */
  details?: LoginRequestDetails;
  /**
   * The challenge code login.request() returned, when number matching was
   * used for this request.
   */
  challengeCode?: string;
  /**
   * Pin the device: the base64 public key you stored when the user enrolled.
   * When given, a proof from any other key is rejected. Strongly recommended.
   */
  expectedPublicKey?: string;
}

function toPairs(details?: LoginRequestDetails): Array<{ label: string; value: string }> {
  if (!details) return [];
  const pairs = Array.isArray(details)
    ? details.map((d) => ({ label: d.label, value: d.value }))
    : Object.entries(details).map(([label, value]) => ({ label, value }));
  return pairs.map((p) => ({ label: String(p.label).trim(), value: String(p.value).trim() }));
}

/** SHA-256 hex of the details as displayed on the phone ('' when none). */
export function detailsDigest(details?: LoginRequestDetails): string {
  const pairs = toPairs(details);
  if (pairs.length === 0) return '';
  const canonical = pairs.map((p) => `${p.label}\u001F${p.value}`).join('\u001E');
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

/**
 * Returns true only if the proof was signed by the device's key over exactly
 * the request, type, challenge code and details you expect. Never throws for
 * malformed input; returns false.
 */
export function verifyApprovalProof(
  proof: ApprovalProof | null | undefined,
  options: VerifyApprovalProofOptions
): boolean {
  try {
    if (!proof || proof.version !== 'v2' || proof.algorithm !== 'ECDSA-P256-SHA256') return false;
    if (options.expectedPublicKey && proof.publicKey !== options.expectedPublicKey) return false;

    const expectedMessage = [
      'touchque-approve:v2',
      options.requestId,
      options.type,
      options.challengeCode ?? '',
      detailsDigest(options.details),
    ].join('\n');
    if (proof.message !== expectedMessage) return false;

    const raw = Buffer.from(proof.publicKey, 'base64');
    if (raw.length !== 65 || raw[0] !== 0x04) return false;
    const b64url = (b: Buffer) => b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const key = crypto.createPublicKey({
      key: { kty: 'EC', crv: 'P-256', x: b64url(raw.subarray(1, 33)), y: b64url(raw.subarray(33, 65)) },
      format: 'jwk',
    });
    return crypto.verify(
      'sha256',
      Buffer.from(proof.message, 'utf8'),
      { key, dsaEncoding: 'der' },
      Buffer.from(proof.signature, 'base64')
    );
  } catch {
    return false;
  }
}
