// src/testing.ts — `@touchque/node/testing`
// A fake Touchque client for your app's tests: no network, no API keys.
// FakeTouchque is a real Touchque whose API calls are answered in memory, so the
// real guard runs: your routes answer exactly what they answer in production
// (202 + token, then your handler once approved).
//
//   import { FakeTouchque } from '@touchque/node/testing';
//
//   const tq = new FakeTouchque().install();   // routes given no `client` use it
//   const first = await request(app).post('/transfer').send({ amount: 5 });   // 202 { touchque, token }
//   tq.approve();                                                             // the person approves on the phone
//   const done = await request(app).post('/transfer').set('X-Touchque-Token', first.body.token).send({ amount: 5 });
//   tq.uninstall();
//
// It answers the calls the step-up guard makes (approval requests, first-time
// linking, offline codes, silent sign-in checks) and defining action types.
// Any other call throws TouchqueAPIError 404.
//
// Its own entry, which loads the main entry ('./index') at run time and bundles
// nothing else of it (see tsup.config.ts): so both share one Touchque class, its
// errors and the default client. Import values from './index' only.

import { Touchque, setDefaultClient, type TouchqueLogger } from './index';
import type { TestingHooks } from './internal';
import type { TransportCall, TransportAnswer } from './core/HttpClient';

/** An approval request made to a FakeTouchque. */
export interface FakeApprovalRequest {
  id: string;
  user: string;
  /** The action type, e.g. `SEND_MONEY`. */
  type: string;
  referenceId: string | null;
  details: Array<{ label: string; value: string }> | null;
  status: 'PENDING' | 'CONFIRMED' | 'REJECTED' | 'EXPIRED';
  /** The number the push asks for (`'47'` with `numberMatch`), or null. */
  challengeCode: string | null;
  /** True once the guard used the approval. */
  consumed: boolean;
  /** `'DEVICE'`, `'WEBAUTHN'` (a passkey), or null while not approved. */
  confirmedVia: string | null;
  /**
   * 30 s after it was made (ISO 8601): its status answer and every poll carry it; set a later time to
   * extend it. The fake never expires a request by time: call `expire()`.
   */
  expiresAt: string;
}

/** One API call your app made through a FakeTouchque. */
export interface FakeCall {
  method: string;
  /** The path as sent, without its query string (`/users/jane%40acme.com`). */
  path: string;
  /** The JSON body, `{}` for none. */
  body: Record<string, any>;
}

export interface FakeTouchqueOptions {
  /** Every user has a phone linked (default true). False: only the users you `link()`. */
  linked?: boolean;
  /** Approve every request as it is made (default false). */
  autoApprove?: boolean;
  /** Every push asks for the number `'47'` (default false). */
  numberMatch?: boolean;
  /** Where the SDK reports its own problems, as on a real client (`console`). Default: nothing is logged. */
  logger?: TouchqueLogger;
}

type Body = Record<string, any>;
type Route = [method: string, path: RegExp, answer: (body: Body, ...parts: string[]) => TransportAnswer];

const HOOKS = Symbol.for('@touchque/node/testing');

/** The main entry's hooks (TestingHooks in internal.ts). */
function hooks(): TestingHooks {
  const found = (Touchque as unknown as Record<symbol, TestingHooks | undefined>)[HOOKS];
  if (!found) throw new Error('@touchque/node/testing needs @touchque/node of the same version.');
  return found;
}

const iso = (ms: number) => new Date(ms).toISOString();
const ok = (body: unknown): TransportAnswer => ({ status: 200, body });

/**
 * A Touchque client that answers in memory, for your app's tests.
 *
 * Every user has a phone linked by default, so a guarded route sends a push;
 * `unlink(user)` gives that user the first-time QR instead, and with
 * `{ linked: false }` only the users you `link()` have one.
 *
 * The phone is yours to drive: `approve()`, `reject()` or `expire()` the latest
 * request (or one by its id), or set `autoApprove` to approve every request as
 * it is made. `requests` lists the approval requests, `calls` every API call,
 * in order. The offline code is `'ABCD123'` and the time-based code `'123456'`.
 */
export class FakeTouchque extends Touchque {
  /** The code the phone shows for an offline QR (`X-Touchque-Code`). */
  offlineCode = 'ABCD123';
  /** The time-based code (`X-Touchque-Code-Type: totp`). */
  totpCode = '123456';
  /** Every user has a phone linked unless `unlink()`ed. */
  linkedByDefault: boolean;
  /** Approve every new request at once, as if the person tapped Approve straight away. */
  autoApprove: boolean;
  /** Ask for the number `'47'` on every push. */
  numberMatch: boolean;
  /** How long a first-time QR works, in ms (5 minutes, like the API). */
  secretTtlMs = 300_000;
  /** The approval requests made so far, oldest first. */
  readonly requests: FakeApprovalRequest[] = [];
  /** Every API call so far, oldest first. */
  readonly calls: FakeCall[] = [];

  readonly #linked = new Set<string>();
  readonly #unlinked = new Set<string>();
  /** First-time QRs issued and not scanned: user → expiry (ms). */
  readonly #pending = new Map<string, number>();
  readonly #challenges = new Map<string, { user: string; type: string; used: boolean; requestId?: string }>();
  readonly #actionTypes = new Map<string, Record<string, unknown>>();
  #seq = 0;
  /** What install() replaced, while installed. */
  #replaced: { client: Touchque | undefined } | null = null;

  readonly #routes: Route[] = [
    ['POST', /^\/login\/request$/, (b) => this.#loginRequest(b)],
    ['GET', /^\/login\/status\/([^/]+)$/, (_b, id) => this.#loginStatus(id)],
    ['POST', /^\/login\/([^/]+)\/consume$/, (_b, id) => this.#loginConsume(id)],
    ['POST', /^\/auth\/generate-secret$/, (b) => this.#generateSecret(b)],
    ['POST', /^\/auth\/secret\/reset$/, (b) => this.#resetSecret(b)],
    ['GET', /^\/users\/([^/]+)$/, (_b, user) => this.#getUser(user)],
    ['POST', /^\/offline\/challenge$/, (b) => this.#offlineChallenge(b)],
    ['POST', /^\/offline\/verify$/, (b) => this.#offlineVerify(b)],
    ['POST', /^\/offline\/totp\/verify$/, (b) => this.#offlineTotpVerify(b)],
    ['POST', /^\/risk\/check$/, (b) => this.#riskCheck(b)],
    ['POST', /^\/action-types$/, (b) => this.#defineActionType(b)],
    ['GET', /^\/action-types$/, () => ok([...this.#actionTypes.values()])],
  ];

  constructor(options: FakeTouchqueOptions = {}) {
    // The key and secret only sign the guard tokens and the calls: nothing leaves the process.
    super({ apiKey: 'tq_fake_key', apiSecret: 'fake_secret', baseUrl: 'http://localhost', logger: options.logger });
    this.linkedByDefault = options.linked ?? true;
    this.autoApprove = options.autoApprove ?? false;
    this.numberMatch = options.numberMatch ?? false;
    hooks().useTransport(this, (call) => this.#answer(call));
  }

  // ── the phone ────────────────────────────────────────────────────────

  /** `user` has a phone linked (as if they scanned the first-time QR). */
  link(user: string): void {
    this.#linked.add(user);
    this.#unlinked.delete(user);
    this.#pending.delete(user);
  }

  /** `user` has no phone linked: a guarded route shows them the first-time QR. */
  unlink(user: string): void {
    this.#unlinked.add(user);
    this.#linked.delete(user);
    this.#pending.delete(user);
  }

  isLinked(user: string): boolean {
    return this.#linked.has(user) || (this.linkedByDefault && !this.#unlinked.has(user));
  }

  /**
   * The person approves on the phone: the latest request, or `requestId`.
   * `via: 'WEBAUTHN'` approves it with a passkey. Returns the request's id.
   */
  approve(requestId?: string, via = 'DEVICE'): string {
    const r = this.#pick(requestId);
    r.status = 'CONFIRMED';
    r.confirmedVia = via;
    return r.id;
  }

  /** The person taps Reject: the latest request, or `requestId`. Returns its id. */
  reject(requestId?: string): string {
    const r = this.#pick(requestId);
    r.status = 'REJECTED';
    return r.id;
  }

  /** Nobody answered in time: the latest request, or `requestId`. Returns its id. */
  expire(requestId?: string): string {
    const r = this.#pick(requestId);
    r.status = 'EXPIRED';
    return r.id;
  }

  // ── the default client ───────────────────────────────────────────────

  /**
   * Makes this the default client (`setDefaultClient(this)`), which the
   * adapters and `runGuard(null, …)` use when given no client, until `uninstall()`.
   */
  install(): this {
    const replaced = setDefaultClient(this);
    if (!this.#replaced) this.#replaced = { client: replaced };
    return this;
  }

  /** Puts back the default client that `install()` replaced. */
  uninstall(): void {
    if (!this.#replaced) return;
    setDefaultClient(this.#replaced.client);
    this.#replaced = null;
  }

  // ── the API, in memory ───────────────────────────────────────────────

  #find(requestId: string): FakeApprovalRequest | undefined {
    return this.requests.find((r) => r.id === requestId);
  }

  #pick(requestId?: string): FakeApprovalRequest {
    const r = requestId ? this.#find(requestId) : this.requests[this.requests.length - 1];
    if (!r) throw new Error(requestId ? `FakeTouchque: no approval request ${requestId}` : 'FakeTouchque: no approval request yet');
    return r;
  }

  #answer(call: TransportCall): TransportAnswer {
    const path = call.path.split('?')[0];
    const body: Body = call.body && typeof call.body === 'object' && !Array.isArray(call.body) ? call.body as Body : {};
    this.calls.push({ method: call.method, path, body });
    for (const [method, pattern, answer] of this.#routes) {
      const m = method === call.method ? pattern.exec(path) : null;
      if (m) return answer(body, ...m.slice(1).map(decodeURIComponent));
    }
    return { status: 404, body: { error: `FakeTouchque does not answer ${call.method} ${path}` } };
  }

  #loginRequest(b: Body): TransportAnswer {
    const user = String(b.externalUsername ?? '');
    if (!this.isLinked(user)) return { status: 404, body: { code: 'device_not_linked', error: 'No linked device found for this user' } };
    const number = this.numberMatch || b.requireNumberMatch === true ? '47' : null;
    const r: FakeApprovalRequest = {
      id: `00000000-0000-4000-8000-${String(++this.#seq).padStart(12, '0')}`, user, type: String(b.type ?? ''),
      referenceId: b.referenceId ?? null, details: b.details ?? null, status: this.autoApprove ? 'CONFIRMED' : 'PENDING',
      challengeCode: number, consumed: false, confirmedVia: this.autoApprove ? 'DEVICE' : null, expiresAt: iso(Date.now() + 30_000),
    };
    this.requests.push(r);
    return ok({ message: 'Request sent', requestId: r.id, challengeCode: number, expiresAt: r.expiresAt, caseCode: 'K7P-2QX' });
  }

  /** What the status and the consume answers say about a request. */
  #approval(r: FakeApprovalRequest): Body {
    const passkey = r.confirmedVia === 'WEBAUTHN';
    return {
      externalUsername: r.user, type: r.type, referenceId: r.referenceId, details: r.details, confirmedVia: r.confirmedVia,
      assurance: r.status === 'CONFIRMED' ? { phishingResistant: passkey, method: passkey ? 'passkey' : 'push' } : null,
      provisional: false, reconfirmedAt: null, revoked: false, revokeReason: null,
    };
  }

  #loginStatus(requestId: string): TransportAnswer {
    const r = this.#find(requestId);
    if (!r) return { status: 404, body: { code: 'not_found' } };
    return ok({ status: r.status, consumed: r.consumed, expiresAt: r.expiresAt, ...this.#approval(r) });
  }

  #loginConsume(requestId: string): TransportAnswer {
    const r = this.#find(requestId);
    if (!r) return { status: 404, body: { code: 'not_found' } };
    if (r.status !== 'CONFIRMED') {
      return { status: 409, body: { code: r.status === 'REJECTED' ? 'rejected' : r.status === 'EXPIRED' ? 'expired' : 'not_approved' } };
    }
    if (r.consumed) return { status: 409, body: { code: 'already_used' } };
    r.consumed = true;
    return ok({ consumed: true, requestId: r.id, approvalProof: null, ...this.#approval(r) });
  }

  #newSecret(user: string): Body {
    const seq = ++this.#seq;
    const expires = Date.now() + this.secretTtlMs;
    this.#pending.set(user, expires);
    return {
      secret: `S${seq}`, qrCodeDataUrl: `data:image/png;base64,QR${seq}-${user}`, externalUsername: user,
      expiresAt: iso(expires), ttlMs: this.secretTtlMs, recoveryCodes: [`r${seq}`],
    };
  }

  #generateSecret(b: Body): TransportAnswer {
    const user = String(b.externalUsername ?? '');
    if (this.isLinked(user)) return { status: 409, body: { error: 'already linked' } };
    if (this.#pending.has(user)) return { status: 409, body: { error: 'Secret already generated' } };
    return ok(this.#newSecret(user));
  }

  #resetSecret(b: Body): TransportAnswer {
    // Like the API: a reset unlinks the phone (the guard only resets a user it found not linked).
    const user = String(b.externalUsername ?? '');
    this.#unlinked.add(user);
    this.#linked.delete(user);
    return ok({ success: true, ...this.#newSecret(user) });
  }

  #getUser(user: string): TransportAnswer {
    const linked = this.isLinked(user);
    if (!linked && !this.#pending.has(user)) return { status: 404, body: { error: 'not found' } };
    return ok({ externalUsername: user, deviceId: linked ? 'dev-1' : null, used: linked, frozen: false, device: null });
  }

  #offlineChallenge(b: Body): TransportAnswer {
    const requestId = typeof b.requestId === 'string' && b.requestId ? b.requestId : undefined;
    const follows = requestId ? this.#find(requestId) : undefined;
    if (requestId && !follows) return { status: 404, body: { error: 'request_not_found' } };
    if (follows?.status === 'REJECTED') return { status: 409, body: { error: 'request_rejected' } };
    const challengeId = `ch-${++this.#seq}`;
    this.#challenges.set(challengeId, { user: String(b.externalUsername ?? ''), type: String(b.type ?? ''), used: false, requestId });
    const number = follows?.challengeCode || (b.requireNumberMatch === true ? '47' : null);
    return ok({
      challengeId, qr: 'TQ2.fake', qrDataUrl: 'data:image/png;base64,OFFLINE', expiresAt: iso(Date.now() + 120_000), expiresInSeconds: 120,
      totpAvailable: true, ...(number && { challengeCode: number }),
    });
  }

  #rejected(requestId: unknown): boolean {
    return typeof requestId === 'string' && this.#find(requestId)?.status === 'REJECTED';
  }

  #offlineVerify(b: Body): TransportAnswer {
    const ch = this.#challenges.get(String(b.challengeId ?? ''));
    if (!ch) return { status: 404, body: { approved: false, reason: 'unknown_challenge' } };
    if (ch.used) return { status: 410, body: { approved: false, reason: 'used' } };
    if (this.#rejected(ch.requestId)) return { status: 410, body: { approved: false, reason: 'request_rejected' } };
    if (b.code !== this.offlineCode) return { status: 401, body: { approved: false, reason: 'invalid_code', attemptsLeft: 4 } };
    ch.used = true;
    return ok({ approved: true, challengeId: b.challengeId, externalUsername: ch.user, type: ch.type });
  }

  #offlineTotpVerify(b: Body): TransportAnswer {
    if (this.#rejected(b.requestId)) return { status: 410, body: { approved: false, reason: 'request_rejected' } };
    if (b.code !== this.totpCode) return { status: 401, body: { approved: false, reason: 'invalid_code' } };
    return ok({ approved: true, externalUsername: b.externalUsername });
  }

  #riskCheck(b: Body): TransportAnswer {
    // Silent sign-ins: the fake always asks the phone.
    const reason = b.browserProof
      ? { code: 'new_browser', text: 'This browser has not been approved on the phone for this account' }
      : { code: 'no_browser_key', text: 'No device-bound browser key was presented' };
    return ok({ prompt: true, reasons: [reason], assurance: 'normal', silentMode: 'enforce', caseCode: 'CHK-2QX' });
  }

  #defineActionType(b: Body): TransportAnswer {
    const defined = {
      id: `at-${++this.#seq}`, type: b.type, name: b.name, description: b.description || '', critical: Boolean(b.critical), active: true,
    };
    this.#actionTypes.set(String(b.type), defined);
    return ok(defined);
  }
}
