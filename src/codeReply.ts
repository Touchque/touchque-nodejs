// src/codeReply.ts
// A code the person types back on the phone (login.request `reply`): a sign-in code another
// service sent them (a text message, WhatsApp, e-mail). Each request gets a one-time P-256 key
// pair; its public key goes with the request, the phone encrypts what was typed to it, and only
// you can open it: TouchQue stores and hands back nothing but the ciphertext (login.status
// `reply.ct`).
//   ECDH P-256, HKDF-SHA256 (salt: the request id, info "touchque-code-reply-v1"),
//   AES-256-GCM (additional data "touchque-code-reply:<request id>"),
//   as "v1.<the phone's one-time key, x9.63>.<nonce|ciphertext|tag>", base64url.

import crypto from 'crypto';

const INFO = 'touchque-code-reply-v1';
const CODE_RE = /^[A-Za-z0-9 -]{4,20}$/;

/** A one-time key pair for one request: send `publicKey`, keep `privateKey` until the answer. */
export interface CodeReplyKey {
  /** The uncompressed P-256 point (65 bytes), base64url: `reply.key`. */
  publicKey: string;
  /** PKCS#8 DER, base64url. Keep it server-side, for this one request. */
  privateKey: string;
}

/** A new one-time key pair for `login.request({ reply: { kind: 'code', key: publicKey } })`. */
export function newCodeReplyKey(): CodeReplyKey {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const raw = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x as string, 'base64url'), Buffer.from(jwk.y as string, 'base64url')]);
  return { publicKey: raw.toString('base64url'), privateKey: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64url') };
}

/**
 * The code the person typed on the phone, from `login.status(requestId).reply.ct`, or `null` when
 * it does not open with this key for this request (or is not a code).
 */
export function openCodeReply(privateKey: string, requestId: string, ct: string): string | null {
  try {
    const m = /^v1\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/.exec(String(ct || ''));
    if (!m) return null;
    const epk = Buffer.from(m[1], 'base64url');
    const box = Buffer.from(m[2], 'base64url');
    if (epk.length !== 65 || epk[0] !== 4 || box.length < 12 + 16 + 1) return null;
    const priv = crypto.createPrivateKey({ key: Buffer.from(privateKey, 'base64url'), format: 'der', type: 'pkcs8' });
    const peer = crypto.createPublicKey({
      key: { kty: 'EC', crv: 'P-256', x: epk.subarray(1, 33).toString('base64url'), y: epk.subarray(33, 65).toString('base64url') },
      format: 'jwk',
    });
    const shared = crypto.diffieHellman({ privateKey: priv, publicKey: peer });
    const key = Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.from(String(requestId), 'utf8'), Buffer.from(INFO, 'utf8'), 32));
    const d = crypto.createDecipheriv('aes-256-gcm', key, box.subarray(0, 12));
    d.setAAD(Buffer.from(`touchque-code-reply:${requestId}`, 'utf8'));
    d.setAuthTag(box.subarray(box.length - 16));
    const code = Buffer.concat([d.update(box.subarray(12, box.length - 16)), d.final()]).toString('utf8').trim();
    return CODE_RE.test(code) ? code : null;
  } catch {
    return null;
  }
}
