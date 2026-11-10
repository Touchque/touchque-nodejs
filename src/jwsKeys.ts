// src/jwsKeys.ts
// JWS and JWKS helpers shared by crossAppAccess and agentCard (not exported
// from the package).

import * as crypto from 'crypto';

export type Jwk = crypto.JsonWebKey & { kid?: string; alg?: string };

export const ALGS = ['RS256', 'ES256', 'EdDSA'];

export const b64urlJson = (part: string): Record<string, unknown> => JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));

export function keyOf(jwk: Jwk): crypto.KeyObject {
  const { kid, alg, use, key_ops: ops, ...material } = jwk as Jwk & { use?: string; key_ops?: string[] };
  return crypto.createPublicKey({ key: material, format: 'jwk' });
}

/** A JWS signature (RS256, ES256 as raw r||s, EdDSA). */
export function verifyJws(input: string, sig: Buffer, alg: string, key: crypto.KeyObject): boolean {
  try {
    if (alg === 'RS256') return key.asymmetricKeyType === 'rsa' && crypto.verify('sha256', Buffer.from(input), key, sig);
    if (alg === 'ES256') return key.asymmetricKeyType === 'ec' && sig.length === 64 && crypto.verify('sha256', Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' }, sig);
    if (alg === 'EdDSA') return key.asymmetricKeyType === 'ed25519' && crypto.verify(null, Buffer.from(input), key, sig);
  } catch {
    return false;
  }
  return false;
}

/** GET a JSON document (5 s, no redirects). */
export async function getJson(url: string): Promise<Record<string, unknown>> {
  const res = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(5000), headers: { Accept: 'application/json' } });
  if (!res.ok) throw new Error(`${url} answered ${res.status}`);
  return res.json() as Promise<Record<string, unknown>>;
}

/** https, or http on this machine (tests). */
export function safeUrl(value: string): URL | null {
  try {
    const u = new URL(value);
    const local = ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
    return u.protocol === 'https:' || (u.protocol === 'http:' && local) ? u : null;
  } catch {
    return null;
  }
}
