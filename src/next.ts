// src/next.ts
// Next.js (App Router) and any Fetch-API framework (Hono, Remix, SvelteKit,
// Bun, Deno, Cloudflare Workers with nodejs_compat):
//
//   export const POST = withTouchQue('SEND_MONEY', async (req, { touchque }) => {
//     return Response.json({ ok: true });
//   }, { user: async () => (await auth())?.user?.email });
//
// Same contract as requireTouchQue: 202 { touchque: step, token } until the
// user approves, then your handler runs once.

import { TouchQue, getDefaultClient } from './index';
import type { LoginRequestDetails } from './types';
import type { Approval } from './steps';
import { runGuard, guardInputFromHeaders, silentInputFromHeaders, SilentSignInOptions } from './guard';

type MaybePromise<T> = T | Promise<T>;

export interface WithTouchQueOptions {
  client?: TouchQue;
  /** Who is approving — read it from YOUR session (required). */
  user: (req: Request) => MaybePromise<string | undefined | null>;
  /** What the phone shows and the approval is bound to. Build it from server-side state. */
  details?: (req: Request) => MaybePromise<LoginRequestDetails | undefined>;
  referenceId?: (req: Request) => MaybePromise<string | undefined>;
  /** For your TouchQue Actions only (`event.context`): roles, plan, amount… Never shown on the phone. */
  context?: (req: Request) => MaybePromise<Record<string, unknown> | undefined>;
  /**
   * End user's IP. Default: none, unless `trustedProxyHops` is set. Use a
   * preset such as `ipFromVercel` / `ipFromCloudflare`, or your own function
   * reading a header your platform overwrites. Never the leftmost
   * X-Forwarded-For hop: a proxy that appends (nginx
   * `$proxy_add_x_forwarded_for`) leaves it under the client's control.
   */
  ip?: (req: Request) => string | undefined;
  /**
   * How many reverse proxies you run in front of this app. The client is the
   * X-Forwarded-For entry this many hops from the right (1 = the address
   * your one proxy saw). Ignored when `ip` is set.
   */
  trustedProxyHops?: number;
  /**
   * Silent sign-ins (default off). When on, a new attempt whose browser sent
   * its device-bound key proof (`X-TouchQue-Browser`, added by `@touchque/web`
   * with `browserKey: true`) first asks TouchQue whether anything about it is
   * new. If nothing is, your handler runs at once with no push
   * (`ctx.touchque.assurance.method === 'silent'`, `ctx.touchque.reasons`). Otherwise,
   * and on any error, the usual push starts and its approval makes the
   * browser known. `{ maxAgeSeconds }` sets your own limit on how long ago the
   * last phone approval in that browser may be.
   */
  silentSignIn?: boolean | SilentSignInOptions;
}

/** The X-Forwarded-For entry `hops` from the right, or undefined. */
export function forwardedFor(req: Request, hops: number): string | undefined {
  if (!Number.isInteger(hops) || hops < 1) return undefined;
  const parts = (req.headers.get('x-forwarded-for') || '').split(',').map((p) => p.trim()).filter(Boolean);
  return parts.length >= hops ? parts[parts.length - hops] : undefined;
}

/** Vercel overwrites `x-real-ip` with the address it accepted the connection from. */
export const ipFromVercel = (req: Request): string | undefined => req.headers.get('x-real-ip')?.trim() || undefined;

/** Cloudflare sets `cf-connecting-ip`; only use this when the origin accepts Cloudflare traffic only. */
export const ipFromCloudflare = (req: Request): string | undefined => req.headers.get('cf-connecting-ip')?.trim() || undefined;

export function withTouchQue<Ctx = unknown>(
  action: string,
  handler: (req: Request, ctx: Ctx & { touchque: Approval }) => MaybePromise<Response>,
  options: WithTouchQueOptions,
): (req: Request, ctx?: Ctx) => Promise<Response> {
  return async (req: Request, ctx?: Ctx): Promise<Response> => {
    const client = options.client || getDefaultClient();
    const [user, details, referenceId, context] = await Promise.all([
      options.user(req),
      options.details ? options.details(req) : undefined,
      options.referenceId ? options.referenceId(req) : undefined,
      options.context ? options.context(req) : undefined,
    ]);
    const ip = options.ip ? options.ip(req) : forwardedFor(req, options.trustedProxyHops ?? 0);
    const result = await runGuard(client, {
      user: user ?? undefined,
      action,
      details,
      referenceId: referenceId ?? undefined,
      context: context ?? undefined,
      ip,
      userAgent: req.headers.get('user-agent') ?? undefined,
      ...guardInputFromHeaders((name) => req.headers.get(name)),
      ...silentInputFromHeaders(options.silentSignIn, (name) => req.headers.get(name)),
    });
    if (result.approved) {
      return handler(req, { ...(ctx as Ctx), touchque: result.approved });
    }
    const headers: Record<string, string> = { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' };
    if (result.body.touchque.retryAfter) headers['Retry-After'] = String(result.body.touchque.retryAfter);
    return new Response(JSON.stringify(result.body), { status: result.status, headers });
  };
}
