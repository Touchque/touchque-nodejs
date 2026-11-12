// src/middleware/express.ts
// One line per protected route:
//
//   app.post('/transfer', requireTouchque('SEND_MONEY'), handler)
//
// Until the user approves on their phone the middleware answers
// 202 { touchque: step, token }. Your page shows the step in its own design
// (the matching number, or the QR code for first-time linking) and sends the
// same request again with header `X-Touchque-Token: <token>` every ~1.5 s
// (@touchque/web's touchqueFetch does exactly this). Once approved the handler
// runs ONCE, with `req.touchque` = { requestId, assurance, approvalProof, … }.

import type { Request, Response, NextFunction } from 'express';
import { Touchque, getDefaultClient } from '../index';
import type { LoginRequestDetails } from '../types';
import {
  runGuard, guardInputFromHeaders, silentInputFromHeaders, SilentSignInOptions, GuardRefusal, GuardResult,
  adapterClient, withoutClient, respond,
} from '../guard';
import { logOf } from '../internal';

type MaybePromise<T> = T | Promise<T>;

export interface TouchqueMiddlewareOptions {
  /**
   * Client to use (default: one built from TQ_API_KEY / TQ_API_SECRET on the
   * first request). Without those, guarded routes answer 500 `misconfigured`
   * (401 when no one is signed in) and the handler never runs; nothing throws.
   */
  client?: Touchque;
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
  /** For your Touchque Actions only (`event.context`): roles, plan, amount… Never shown on the phone. */
  context?: (req: Request) => MaybePromise<Record<string, unknown> | undefined>;
  /** @deprecated use `user` */
  getUserId?: (req: Request) => string | undefined;
  /** @deprecated use `details` */
  getDetails?: (req: Request) => MaybePromise<LoginRequestDetails | undefined>;
  /** @deprecated use `referenceId` */
  getReferenceId?: (req: Request) => string | undefined;
  /** @deprecated no effect — the page polls instead of the server holding the request open */
  timeout?: number;
  /**
   * Silent sign-ins (default off). When on, a new attempt whose browser sent
   * its device-bound key proof (`X-Touchque-Browser`, added by `@touchque/web`
   * with `browserKey: true`) first asks Touchque whether anything about it is
   * new. If nothing is, your handler runs at once with no push
   * (`touchque.assurance.method === 'silent'`, `touchque.reasons`). Otherwise,
   * and on any error, the usual push starts and its approval makes the
   * browser known. `{ maxAgeSeconds }` sets your own limit on how long ago the
   * last phone approval in that browser may be.
   */
  silentSignIn?: boolean | SilentSignInOptions;
  /**
   * Your app's own error shape for every answer of status 400 or more (401,
   * 403, 408, 423, 429, 500, 503); never for a 202 step or an approval. Gets
   * `{ status, code, message, touchque }`. What encodes to a JSON object (a
   * class instance, `toJSON()`, a Map as its entries) is sent with `touchque`
   * set to the step, so `@touchque/web` still sees the state; anything else
   * (string, number, array, null) is sent as it is, and `undefined` keeps the
   * default body. Status and headers stay the same. If it throws, or JSON
   * cannot encode the result, the default body is sent and the client's logger
   * gets the error.
   *
   * @example
   * errorBody: (r) => ({ message: r.message, code: r.code })
   * // 403 {"message":"The approval was rejected.","code":"rejected","touchque":{"state":"rejected",…}}
   */
  errorBody?: (refusal: GuardRefusal) => unknown;
}

const defaultUser = (req: Request): string | undefined => {
  const u = (req as unknown as { user?: { email?: string; id?: string | number; username?: string } }).user;
  const id = u?.email ?? u?.id ?? u?.username;
  return id === undefined || id === null ? undefined : String(id);
};

/**
 * Protects a route with Touchque approval.
 *
 * @example
 * app.post('/transfer',
 *   requireTouchque('SEND_MONEY', { details: (req) => ({ Amount: `${req.body.amount} EUR`, To: req.body.iban }) }),
 *   (req, res) => res.json({ ok: true }));
 */
export function requireTouchque(action: string, options?: TouchqueMiddlewareOptions): (req: Request, res: Response, next: NextFunction) => Promise<void>;
/** @deprecated pass the client as `options.client` (or rely on the environment) */
export function requireTouchque(client: Touchque, action: string, options?: TouchqueMiddlewareOptions): (req: Request, res: Response, next: NextFunction) => Promise<void>;
export function requireTouchque(
  a: string | Touchque,
  b?: string | TouchqueMiddlewareOptions,
  c?: TouchqueMiddlewareOptions,
) {
  const legacy = typeof a !== 'string';
  const action = (legacy ? b : a) as string;
  const options: TouchqueMiddlewareOptions = (legacy ? c : (b as TouchqueMiddlewareOptions)) || {};
  const explicitClient = legacy ? (a as Touchque) : options.client;
  const userOf = options.user || options.getUserId || defaultUser;
  const detailsOf = options.details || options.getDetails;
  const refOf = options.referenceId || options.getReferenceId;

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const client = adapterClient(explicitClient, getDefaultClient);
      let result: GuardResult;
      if (!client) {
        // No TQ_API_KEY / TQ_API_SECRET: a JSON answer, never a throw.
        result = withoutClient(await userOf(req));
      } else {
        const [user, details, referenceId, context] = await Promise.all([
          userOf(req), detailsOf ? detailsOf(req) : undefined, refOf ? refOf(req) : undefined,
          options.context ? options.context(req) : undefined,
        ]);
        const header = (name: string) => req.get?.(name) ?? (req.headers?.[name] as string | undefined);
        result = await runGuard(client, {
          user: user ?? undefined,
          action,
          details,
          referenceId: referenceId ?? undefined,
          context: context ?? undefined,
          ip: req.ip,
          userAgent: req.get?.('user-agent') ?? undefined,
          ...guardInputFromHeaders(header),
          ...silentInputFromHeaders(options.silentSignIn, header),
        });
      }
      if (result.approved) {
        (req as unknown as { touchque: unknown }).touchque = result.approved;
        next();
        return;
      }
      // What guardResponse() gives, judged with the app's own JSON replacer.
      const answer = await respond(result, options.errorBody, logOf(client), req.app?.get('json replacer'));
      res.set(answer.headers);
      if (answer.body === result.body) {
        res.status(answer.status).json(answer.body);
        return;
      }
      // errorBody's shape went through the app's JSON replacer already: sent without a second pass.
      res.status(answer.status).type('application/json')
        .send(jsonText(answer.body, req.app?.get('json spaces'), req.app?.get('json escape')));
    } catch (err) {
      next(err);
    }
  };
}

/** JSON text as Express's res.json writes it with the app's 'json spaces' and 'json escape', but no replacer. */
function jsonText(value: unknown, spaces: string | number | undefined, escape: boolean | undefined): string {
  const text = JSON.stringify(value, null, spaces);
  return escape ? text.replace(/[<>&]/g, (c) => `\\u00${c.charCodeAt(0).toString(16)}`) : text;
}
