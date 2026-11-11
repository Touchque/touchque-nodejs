// src/nextMiddleware.ts — `@touchque/node/next/middleware`: protects Next.js
// pages with the Touchque Login session cookie. Runs on the Edge: WebCrypto
// only, no Node.js modules.
//
//   // middleware.ts
//   import { touchqueMiddleware } from '@touchque/node/next/middleware';
//   export default touchqueMiddleware({ secret: process.env.TOUCHQUE_SESSION_SECRET!, protect: ['/dashboard', '/settings'] });
//   export const config = { matcher: ['/dashboard/:path*', '/settings/:path*'] };
//
// It only checks that the cookie decrypts and has not expired; the pages
// read the session with touchque.getSession() (`@touchque/node/next`).

export interface TouchqueMiddlewareOptions {
  /** The same secret as createTouchqueLogin. */
  secret: string;
  /** Path prefixes that need a signed-in user, or a test. Default: every path the matcher sends here. */
  protect?: string[] | ((pathname: string) => boolean);
  /** Where the handlers are mounted. Default /auth. */
  basePath?: string;
  /** Cookie name. Default tq_session. */
  cookieName?: string;
}

const MAX_CHUNKS = 5;

function readCookie(name: string, header: string | null): string | undefined {
  const all: Record<string, string> = {};
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) all[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  if (all[name]) return all[name];
  let joined = '';
  for (let i = 0; i < MAX_CHUNKS; i += 1) {
    if (!all[`${name}.${i}`]) break;
    joined += all[`${name}.${i}`];
  }
  return joined || undefined;
}

function fromB64u(text: string): Uint8Array<ArrayBuffer> {
  const s = atob(text.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((text.length + 3) % 4));
  const out = new Uint8Array(new ArrayBuffer(s.length));
  for (let i = 0; i < s.length; i += 1) out[i] = s.charCodeAt(i);
  return out;
}

// The same key as hostedLoginSession.seal(..., 'session'): SHA-256 of the purpose and secret.
const importKey = (secret: string) => crypto.subtle.digest('SHA-256', new TextEncoder().encode(`touchque-login:session:${secret}`))
  .then((raw) => crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']));
const keys = new Map<string, ReturnType<typeof importKey>>();
function keyOf(secret: string): ReturnType<typeof importKey> {
  let k = keys.get(secret);
  if (!k) {
    k = importKey(secret);
    keys.set(secret, k);
  }
  return k;
}

/** True when the sealed session decrypts with the secret and has not expired. */
export async function hasSession(sealed: string | undefined, secret: string): Promise<boolean> {
  if (!sealed) return false;
  try {
    const raw = fromB64u(sealed);
    if (raw.length < 29) return false;
    // seal() writes iv (12) | tag (16) | ciphertext; WebCrypto wants ciphertext | tag.
    const data = new Uint8Array(new ArrayBuffer(raw.length - 12));
    data.set(raw.subarray(28), 0);
    data.set(raw.subarray(12, 28), raw.length - 28);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, 12) }, await keyOf(secret), data);
    const body = JSON.parse(new TextDecoder().decode(plain));
    return typeof body.exp === 'number' && body.exp > Date.now() / 1000;
  } catch {
    return false;
  }
}

/** Next.js middleware: a protected path without a session goes to {basePath}/login?returnTo=… */
export function touchqueMiddleware(options: TouchqueMiddlewareOptions) {
  if (!options?.secret || options.secret.length < 32) throw new Error('secret must be at least 32 characters');
  const basePath = (options.basePath || '/auth').replace(/\/+$/, '');
  const cookieName = options.cookieName || 'tq_session';
  const list = Array.isArray(options.protect) ? options.protect : null;
  const isProtected = typeof options.protect === 'function'
    ? options.protect
    : (path: string) => !list || list.some((p) => path === p || path.startsWith(`${p.replace(/\/+$/, '')}/`));
  return async (request: Request): Promise<Response | undefined> => {
    const url = new URL(request.url);
    if (url.pathname.startsWith(`${basePath}/`) || !isProtected(url.pathname)) return undefined;
    if (await hasSession(readCookie(cookieName, request.headers.get('cookie')), options.secret)) return undefined;
    const target = new URL(`${basePath}/login`, url);
    target.searchParams.set('returnTo', url.pathname + url.search);
    return new Response(null, { status: 307, headers: { Location: target.toString() } });
  };
}
