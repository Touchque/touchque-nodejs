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
import { runGuard, guardInputFromHeaders } from './guard';

type MaybePromise<T> = T | Promise<T>;

export interface WithTouchQueOptions {
  client?: TouchQue;
  /** Who is approving — read it from YOUR session (required). */
  user: (req: Request) => MaybePromise<string | undefined | null>;
  /** What the phone shows and the approval is bound to. Build it from server-side state. */
  details?: (req: Request) => MaybePromise<LoginRequestDetails | undefined>;
  referenceId?: (req: Request) => MaybePromise<string | undefined>;
  /** End user's IP (default: first X-Forwarded-For hop, which your platform must set). */
  ip?: (req: Request) => string | undefined;
}

export function withTouchQue<Ctx = unknown>(
  action: string,
  handler: (req: Request, ctx: Ctx & { touchque: Approval }) => MaybePromise<Response>,
  options: WithTouchQueOptions,
): (req: Request, ctx?: Ctx) => Promise<Response> {
  return async (req: Request, ctx?: Ctx): Promise<Response> => {
    const client = options.client || getDefaultClient();
    const [user, details, referenceId] = await Promise.all([
      options.user(req),
      options.details ? options.details(req) : undefined,
      options.referenceId ? options.referenceId(req) : undefined,
    ]);
    const ip = options.ip ? options.ip(req) : req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || undefined;
    const result = await runGuard(client, {
      user: user ?? undefined,
      action,
      details,
      referenceId: referenceId ?? undefined,
      ip,
      userAgent: req.headers.get('user-agent') ?? undefined,
      ...guardInputFromHeaders((name) => req.headers.get(name)),
    });
    if (result.approved) {
      return handler(req, { ...(ctx as Ctx), touchque: result.approved });
    }
    const headers: Record<string, string> = { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' };
    if (result.body.touchque.retryAfter) headers['Retry-After'] = String(result.body.touchque.retryAfter);
    return new Response(JSON.stringify(result.body), { status: result.status, headers });
  };
}
