// src/resources/Assist.ts
// Help desk: IT working on a person's account in the open.
//
// 1. Before your help desk acts on someone's account: `open` with the person
//    and the signed-in agent. The person's phone gets a calm notice ("<agent>
//    from IT is working on your account now"); while the session is open,
//    their "someone says they're from IT" button shows this agent, and with
//    none open it tells them to hang up (webhook ASSIST_CLAIM_UNVERIFIED).
// 2. Before a sensitive action (a factor or password reset, an activation or
//    recovery link, an unlock, a new phone, removing a passkey): `verify`.
//    Show `challengeCode` to the agent only; they read it to the person, who
//    types it on their phone and approves with Face ID. Default deny.
// 3. Right before the action: `spend` (a passed check, for that action, at
//    most ten minutes old, once). `unfreeze` lifts a freeze the same way.
// No phone (`no_phone`, `route: 'never_locked_out'`): the person moves to a
// new phone with Never Locked Out (`tq.recovery`); the help desk cannot.

import { HttpClient } from '../core/HttpClient';
import { TouchqueConfigError } from '../errors';
import { AssistCheckStarted, AssistSession, OpenAssistOptions, VerifyAssistOptions } from '../types';

const path = (id: string, rest = '') => `/assist/${encodeURIComponent(id)}${rest}`;

/** The check of `requestId` passed on the person's phone and was not used yet. */
export function isAssistCheckPassed(session: AssistSession, requestId: string): boolean {
  const c = session.checks.find((x) => x.requestId === requestId);
  return !!c && c.outcome === 'verified' && !c.spentAt;
}

export class Assist {
  constructor(private readonly http: HttpClient) {}

  /**
   * Starts helping a person. A session of the same agent for the same person
   * is replaced.
   *
   * @example
   * const s = await tq.assist.open({
   *   externalUsername: 'ayse@acme.com',
   *   agent: { name: 'Deniz Kaya', title: 'IT help desk', ref: agent.id },
   *   reason: 'Ticket 4411',
   * });
   */
  async open(options: OpenAssistOptions): Promise<AssistSession> {
    if (!options?.externalUsername || !options?.agent?.name) throw new TouchqueConfigError('assist.open() needs externalUsername and agent.name');
    return this.http.post<AssistSession>('/assist', {
      externalUsername: options.externalUsername,
      agent: { name: options.agent.name, ...(options.agent.title && { title: options.agent.title }), ...(options.agent.ref && { ref: options.agent.ref }) },
      ...(options.reason && { reason: options.reason }),
      ...(options.ttlMinutes !== undefined && { ttlMinutes: options.ttlMinutes }),
      ...(options.notify !== undefined && { notify: options.notify }),
    });
  }

  /** The session and its checks. Poll it while a check is `pending`. */
  async get(id: string): Promise<AssistSession> {
    if (!id) throw new TouchqueConfigError('assist.get() needs the session id');
    return this.http.get<AssistSession>(path(id));
  }

  /** A person's sessions, or every open one (`{ open: true }`), newest first. */
  async list(options: { externalUsername?: string; open?: boolean }): Promise<AssistSession[]> {
    if (!options?.externalUsername && !options?.open) throw new TouchqueConfigError('assist.list() needs externalUsername or open: true');
    const res = await this.http.get<{ sessions: AssistSession[] }>('/assist', {
      ...(options.externalUsername && { externalUsername: options.externalUsername }),
      ...(options.open && { open: 'true' }),
    });
    return Array.isArray(res?.sessions) ? res.sessions : [];
  }

  /**
   * Asks the person's phone to confirm `action`. Throws TouchqueAPIError
   * `no_phone` (send them to Never Locked Out), `assist_not_open` or
   * `rate_limited`.
   */
  async verify(id: string, options: VerifyAssistOptions): Promise<AssistCheckStarted> {
    if (!id || !options?.action) throw new TouchqueConfigError('assist.verify() needs the session id and an action');
    return this.http.post<AssistCheckStarted>(path(id, '/verify'), {
      action: options.action,
      ...(options.actionText && { actionText: options.actionText }),
      ...(options.details && { details: options.details as unknown as Record<string, unknown> }),
    });
  }

  /** Uses a passed check for its action, right before you take it. Throws `check_required` (428) otherwise. */
  async spend(id: string, options: { requestId: string; action: string }): Promise<AssistSession> {
    if (!id || !options?.requestId || !options?.action) throw new TouchqueConfigError('assist.spend() needs the session id, requestId and action');
    return this.http.post<AssistSession>(path(id, '/spend'), { requestId: options.requestId, action: options.action });
  }

  /** Lifts the person's approval freeze with a passed check for `unlock`. */
  async unfreeze(id: string, options: { requestId: string }): Promise<{ unfrozen: boolean; session: AssistSession }> {
    if (!id || !options?.requestId) throw new TouchqueConfigError('assist.unfreeze() needs the session id and requestId');
    return this.http.post<{ unfrozen: boolean; session: AssistSession }>(path(id, '/unfreeze'), { requestId: options.requestId });
  }

  /** Stops helping; checks still waiting on the phone expire. */
  async end(id: string, options: { by?: string; reason?: string } = {}): Promise<AssistSession> {
    if (!id) throw new TouchqueConfigError('assist.end() needs the session id');
    return this.http.post<AssistSession>(path(id, '/end'), {
      ...(options.by && { by: options.by }),
      ...(options.reason && { reason: options.reason }),
    });
  }
}
