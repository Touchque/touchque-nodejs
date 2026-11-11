// src/hostedLoginSession.ts
// Encrypted cookies for apps that use Touchque Login without a session store:
// the sign-in in progress (state, nonce, PKCE verifier, where to go back) and
// the signed-in session (user claims, tokens). AES-256-GCM with a key derived
// from your secret; values too big for one cookie are split across several.
// Framework-agnostic: express and Next.js helpers build on it.

import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'crypto';
import { TouchqueError } from './errors';

const CHUNK = 3800;
const MAX_CHUNKS = 5;

export interface CookieOptions {
  secure: boolean;
  maxAgeSec: number;
  path?: string;
  sameSite?: 'Lax' | 'Strict' | 'None';
}

function keyOf(secret: string, purpose: string): Buffer {
  if (typeof secret !== 'string' || secret.length < 32) throw new TouchqueError('The cookie secret must be at least 32 characters');
  return createHash('sha256').update(`touchque-login:${purpose}:${secret}`).digest();
}

export function seal(value: unknown, secret: string, purpose: string, maxAgeSec: number): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', keyOf(secret, purpose), iv);
  const body = JSON.stringify({ v: value, exp: Math.floor(Date.now() / 1000) + maxAgeSec });
  const enc = Buffer.concat([cipher.update(body, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), enc]).toString('base64url');
}

export function unseal<T>(sealed: string | undefined, secret: string, purpose: string): T | null {
  if (!sealed) return null;
  try {
    const raw = Buffer.from(sealed, 'base64url');
    const decipher = createDecipheriv('aes-256-gcm', keyOf(secret, purpose), raw.subarray(0, 12));
    decipher.setAuthTag(raw.subarray(12, 28));
    const body = JSON.parse(Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString('utf8'));
    if (typeof body.exp !== 'number' || body.exp < Date.now() / 1000) return null;
    return body.v as T;
  } catch {
    return null;
  }
}

function serialize(name: string, value: string, o: CookieOptions): string {
  const parts = [`${name}=${value}`, `Path=${o.path || '/'}`, 'HttpOnly', `SameSite=${o.sameSite || 'Lax'}`];
  if (o.secure) parts.push('Secure');
  parts.push(o.maxAgeSec > 0 ? `Max-Age=${o.maxAgeSec}` : 'Max-Age=0');
  return parts.join('; ');
}

/** Parses a Cookie header. */
export function parseCookies(header: string | undefined | null): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

/** Set-Cookie values that store `sealed` under `name` (split into name.0, name.1… when long). */
export function cookieHeaders(name: string, sealed: string | null, cookies: Record<string, string>, o: CookieOptions): string[] {
  const out: string[] = [];
  const old = Object.keys(cookies).filter((k) => k === name || k.startsWith(`${name}.`));
  if (sealed === null) {
    for (const k of old) out.push(serialize(k, '', { ...o, maxAgeSec: 0 }));
    return out;
  }
  if (sealed.length <= CHUNK) {
    out.push(serialize(name, sealed, o));
    for (const k of old) if (k !== name) out.push(serialize(k, '', { ...o, maxAgeSec: 0 }));
    return out;
  }
  const chunks = Math.ceil(sealed.length / CHUNK);
  if (chunks > MAX_CHUNKS) throw new TouchqueError('The session is too large for cookies');
  const kept = new Set<string>();
  for (let i = 0; i < chunks; i += 1) {
    kept.add(`${name}.${i}`);
    out.push(serialize(`${name}.${i}`, sealed.slice(i * CHUNK, (i + 1) * CHUNK), o));
  }
  for (const k of old) if (!kept.has(k)) out.push(serialize(k, '', { ...o, maxAgeSec: 0 }));
  return out;
}

/** The sealed value stored under `name`, joined back from its chunks. */
export function readCookie(name: string, cookies: Record<string, string>): string | undefined {
  if (cookies[name]) return cookies[name];
  let joined = '';
  for (let i = 0; i < MAX_CHUNKS; i += 1) {
    const part = cookies[`${name}.${i}`];
    if (!part) break;
    joined += part;
  }
  return joined || undefined;
}

/** A path inside this app to return to after sign-in (never another site). */
export function safeReturnTo(value: unknown, fallback = '/'): string {
  if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//') || value.startsWith('/\\') || value.length > 2000) return fallback;
  return value;
}
