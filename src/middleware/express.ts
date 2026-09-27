// src/middleware/express.ts
// One line per protected route:
//
//   app.post('/transfer', requireTouchQue('SEND_MONEY'), handler)
//
// Until the user approves on their phone the middleware answers
// 202 { touchque: step, token }. Your page shows the step in its own design
// (the matching number, or the QR code for first-time linking) and sends the
// same request again with header `X-TouchQue-Token: <token>` every ~1.5 s
// (@touchque/web's touchqueFetch does exactly this). Once approved the handler
// runs ONCE, with `req.touchque` = { requestId, assurance, approvalProof, … }.

import type { Request, Response, NextFunction } from 'express';
import { TouchQue, getDefaultClient } from '../index';
import type { LoginRequestDetails } from '../types';
import { runGuard, guardInputFromHeaders } from '../guard';

type MaybePromise<T> = T | Promise<T>;

export interface TouchQueMiddlewareOptions {
  /** Client to use (default: one built from TQ_API_KEY / TQ_API_SECRET). */
  client?: TouchQue;
  /**
   * Who is approving. Default: `req.user.email || req.user.id || req.user.username`
   * (set by your auth). For the login step, return the user who just passed
   * your password check, e.g. `(req) => req.session.passwordOk`.
   */
  user?: (req: Request) => MaybePromise<string | undefined | null>;
  /** What the phone shows and the approval is bound to (amount, recipient…). Build it from server-side state. */
  details?: (req: Request) => MaybePromise<LoginRequestDetails | undefined>;
  /** Your own transaction id, bound to the approval. */
  referenceId?: (req: Request) => MaybePromise<string | undefined>;
  /** @deprecated use `user` */
  getUserId?: (req: Request) => string | undefined;
  /** @deprecated use `details` */
  getDetails?: (req: Request) => MaybePromise<LoginRequestDetails | undefined>;
  /** @deprecated use `referenceId` */
  getReferenceId?: (req: Request) => string | undefined;
  /** @deprecated no effect — the page polls instead of the server holding the request open */
  timeout?: number;
}

const defaultUser = (req: Request): string | undefined => {
  const u = (req as unknown as { user?: { email?: string; id?: string | number; username?: string } }).user;
  const id = u?.email ?? u?.id ?? u?.username;
  return id === undefined || id === null ? undefined : String(id);
};

/**
 * Protects a route with TouchQue approval.
 *
 * @example
 * app.post('/transfer',
 *   requireTouchQue('SEND_MONEY', { details: (req) => ({ Amount: `${req.body.amount} EUR`, To: req.body.iban }) }),
 *   (req, res) => res.json({ ok: true }));
 */
export function requireTouchQue(action: string, options?: TouchQueMiddlewareOptions): (req: Request, res: Response, next: NextFunction) => Promise<void>;
/** @deprecated pass the client as `options.client` (or rely on the environment) */
export function requireTouchQue(client: TouchQue, action: string, options?: TouchQueMiddlewareOptions): (req: Request, res: Response, next: NextFunction) => Promise<void>;
export function requireTouchQue(
  a: string | TouchQue,
  b?: string | TouchQueMiddlewareOptions,
  c?: TouchQueMiddlewareOptions,
) {
  const legacy = typeof a !== 'string';
  const action = (legacy ? b : a) as string;
  const options: TouchQueMiddlewareOptions = (legacy ? c : (b as TouchQueMiddlewareOptions)) || {};
  const explicitClient = legacy ? (a as TouchQue) : options.client;
  const userOf = options.user || options.getUserId || defaultUser;
  const detailsOf = options.details || options.getDetails;
  const refOf = options.referenceId || options.getReferenceId;

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const client = explicitClient || getDefaultClient();
      const [user, details, referenceId] = await Promise.all([
        userOf(req), detailsOf ? detailsOf(req) : undefined, refOf ? refOf(req) : undefined,
      ]);
      const result = await runGuard(client, {
        user: user ?? undefined,
        action,
        details,
        referenceId: referenceId ?? undefined,
        ip: req.ip,
        userAgent: req.get?.('user-agent') ?? undefined,
        ...guardInputFromHeaders((name) => req.get?.(name) ?? (req.headers?.[name] as string | undefined)),
      });
      if (result.approved) {
        (req as unknown as { touchque: unknown }).touchque = result.approved;
        next();
        return;
      }
      if (result.status === 429 || result.status === 423) {
        const retry = result.body.touchque.retryAfter;
        if (retry) res.set('Retry-After', String(retry));
      }
      res.set('Cache-Control', 'no-store');
      res.status(result.status).json(result.body);
    } catch (err) {
      next(err);
    }
  };
}
