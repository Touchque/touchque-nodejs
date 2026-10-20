// src/resources/Actions.ts
// TouchQue Actions: your own code at points of the approval pipeline (before
// the push is sent, the silent sign-in decision, after an approval, fraud
// reports, device and recovery events). TouchQue runs it in a sandbox; this
// resource deploys, tests, replays and observes it.
//
//   await tq.actions.deploy('night-alert', {
//     trigger: 'approval.decided',
//     template: { id: 'alert', params: { channel: 'slack', when: { countries: ['TR'], hours: { from: 0, to: 6 } } } },
//   });
//
// The types below (LoginRequestEvent, LoginRequestApi, …) describe what your
// Action code receives, for editor autocompletion when you write Actions in
// your own repository.

import { HttpClient } from '../core/HttpClient';
import { TouchQueConfigError } from '../errors';

// ─── What an Action receives ─────────────────────────────────────────────

export type ActionTrigger =
  | 'login.request'
  | 'risk.check'
  | 'approval.decided'
  | 'shield.decision'
  | 'fraud.reported'
  | 'device.linked'
  | 'device.keys_lost'
  | 'user.unlinked'
  | 'passkey.added'
  | 'passkey.removed'
  | 'recovery.updated';

/** Loosening powers; each needs an admin's phone approval in the dashboard. */
export type ActionCapability = 'skip_number_match' | 'override_block' | 'allow_silent';

export interface ActionClient {
  ip: string | null;
  userAgent: string | null;
  /** ISO 3166-1 alpha-2, when the address resolved. */
  country: string | null;
  location: string | null;
  /** IANA time zone of the address, when known (use with `api.time.local`). */
  timeZone: string | null;
  /** risk.check only: `bound` (a known device-bound browser key), `new`, `none`. */
  browser: 'bound' | 'new' | 'none' | null;
}

export interface ActionRequestAction {
  type: string;
  name: string;
  critical: boolean;
}

interface ActionEventBase {
  id: string;
  trigger: ActionTrigger;
  /** ISO 8601. */
  time: string;
  workspace: { id: string };
  user: { id: string | null };
  /** The secrets this version declares. */
  secrets: Record<string, string | undefined>;
}

export interface LoginRequestEvent extends ActionEventBase {
  trigger: 'login.request';
  request: { id: string; action: ActionRequestAction; referenceId: string | null; details: Array<{ label: string; value: string }> | null };
  /** What your server passed as `context` in the login request. */
  context: Record<string, unknown> | null;
  client: ActionClient;
  risk: { score: number | null; engineAction: 'ALLOW' | 'CHALLENGE' | 'BLOCK' | null; factors: string[]; hardFlags: string[]; trustedNetwork: boolean };
  device: { integrity: string; trusted: boolean; platform: string | null };
  /** TouchQue's decision before any Action ran. */
  decision: { outcome: 'deny' | 'unavailable' | 'passkey' | 'number_match' | 'push'; reason: string | null; reasons: string[] };
}

export interface RiskCheckEvent extends ActionEventBase {
  trigger: 'risk.check';
  request: { action: ActionRequestAction | null };
  context: Record<string, unknown> | null;
  client: ActionClient;
  risk: { score: number | null; engineAction: string | null; factors: string[]; assurance: string | null; silentOk: boolean };
  decision: { prompt: boolean; reasons: string[] };
}

export interface ApprovalDecidedEvent extends ActionEventBase {
  trigger: 'approval.decided';
  request: { id: string; action: ActionRequestAction; referenceId: string | null; details: unknown; createdAt: string | null };
  client: ActionClient;
  approval: {
    status: 'approved' | 'rejected';
    via: 'phone' | 'passkey' | 'offline_qr' | 'offline_code' | 'recovery_code' | 'risk_engine' | string | null;
    reason: string | null;
    provisional: boolean;
    assurance: string | null;
  };
  risk: { score: number | null; factors: string[] };
}

/** shield.decision, fraud.reported, device.*, user.unlinked, passkey.*, recovery.updated. */
export interface FactEvent extends ActionEventBase {
  type?: string;
  request?: { id: string; action: Partial<ActionRequestAction>; referenceId?: string | null; status?: string };
  details: Record<string, unknown>;
}

export type ActionEvent = LoginRequestEvent | RiskCheckEvent | ApprovalDecidedEvent | FactEvent;

export interface ActionFetchResponse {
  status: number;
  ok: boolean;
  headers: Record<string, string>;
  text(): Promise<string>;
  json<T = unknown>(): Promise<T>;
}

export interface ActionLocalTime {
  timeZone: string;
  /** YYYY-MM-DD */
  date: string;
  hour: number;
  minute: number;
  /** 0 = Sunday */
  weekday: number;
}

/** What every Action can do: notify, freeze the user, call allowed hosts. */
export interface ActionApi {
  notify: {
    /** Uses the secret SLACK_WEBHOOK_URL unless `options.secret` names another. */
    slack(message: string | { text: string; blocks?: unknown[] }, options?: { secret?: string }): void;
    /** Uses the secret TEAMS_WEBHOOK_URL unless `options.secret` names another. */
    teams(message: string | { text: string }, options?: { secret?: string }): void;
    /** A URL on one of the version's allowedHosts, or `{ secret }` holding the URL. */
    webhook(target: string | { secret: string }, payload?: unknown): void;
    email(options: { to: string | string[]; from: string; subject?: string; text: string; provider?: 'resend' | 'postmark' | 'sendgrid'; secret?: string }): void;
  };
  /** Freezes the user's approvals (1 minute to 7 days); never shortens a longer freeze. */
  freezeUser(options: { minutes?: number; reason?: string }): void;
  /** https only, to the version's allowedHosts; at most 3 calls per run; off in dry runs. */
  fetch(url: string, init?: { method?: string; headers?: Record<string, string>; body?: string | object }): Promise<ActionFetchResponse>;
  time: { local(timeZone: string): ActionLocalTime };
}

export interface LoginRequestApi extends ActionApi {
  deny(reason?: string): void;
  /** Number matching on the phone. */
  stepUp(reason?: string): void;
  /** Only a passkey may approve (refused when the user has none). */
  requirePasskey(reason?: string): void;
  /** Needs the skip_number_match capability. */
  skipNumberMatch(reason?: string): void;
  /** Needs the override_block capability. */
  overrideBlock(reason?: string): void;
}

export interface RiskCheckApi extends ActionApi {
  /** The sign-in asks the phone. */
  prompt(reason?: string): void;
  /** Needs the allow_silent capability. */
  allowSilent(reason?: string): void;
}

/** The shape of `exports.onExecute`. */
export type ActionHandler<E extends ActionEvent = ActionEvent, A extends ActionApi = ActionApi> = (event: E, api: A) => void | Promise<void>;

// ─── The management API ──────────────────────────────────────────────────

export interface ActionTemplateRef {
  id: 'alert' | 'block_or_step_up' | 'require_passkey_for_role' | 'always_ask_when' | string;
  params?: Record<string, unknown>;
}

export interface DeployActionOptions {
  /** Required for a new Action; cannot change later. */
  trigger?: ActionTrigger;
  name?: string;
  /** JavaScript exporting onExecute. */
  code?: string;
  /**
   * A self-contained function deployed as onExecute (its source text is sent,
   * so it must not use variables from outside itself or imports).
   */
  handler?: ActionHandler<any, any>;
  template?: ActionTemplateRef;
  secrets?: string[];
  allowedHosts?: string[];
  capabilities?: ActionCapability[];
  /** Pre triggers: what an error or timeout means (default `continue`, never blocks). */
  onFailure?: 'continue' | 'step_up' | 'deny';
  order?: number;
  enabled?: boolean;
  /** `false` saves the version without making it live. */
  activate?: boolean;
}

export interface ActionSummary {
  slug: string;
  name: string;
  trigger: ActionTrigger;
  enabled: boolean;
  order: number;
  onFailure: 'continue' | 'step_up' | 'deny';
  activeVersion: number | null;
  pendingApproval?: number;
  createdAt?: string;
  updatedAt?: string;
}

export interface ActionVersion {
  number: number;
  status: 'ready' | 'pending_approval' | 'rejected';
  active: boolean;
  capabilities: ActionCapability[];
  approvedCapabilities: ActionCapability[];
  allowedHosts: string[];
  secrets: string[];
  template: ActionTemplateRef | null;
  codeHash: string;
  code?: string;
  createdAt: string;
  createdBy: string | null;
  approvedAt: string | null;
}

export interface ActionDeployResult {
  action: ActionSummary;
  version: ActionVersion;
  /** This version runs now. */
  deployed: boolean;
  /** Set when the version loosens security and waits for an admin's phone approval. */
  approval: { required: boolean; capabilities: ActionCapability[]; message: string } | null;
  warnings: string[];
}

export interface ActionDetail {
  action: ActionSummary;
  code: string | null;
  versions: ActionVersion[];
}

export interface UpdateActionOptions {
  name?: string;
  enabled?: boolean;
  order?: number;
  onFailure?: 'continue' | 'step_up' | 'deny';
}

export interface ActionCall {
  kind: 'deny' | 'stepUp' | 'requirePasskey' | 'prompt' | 'skipNumberMatch' | 'overrideBlock' | 'allowSilent';
  reason: string;
}

export interface ActionLogLine {
  level: string;
  message: string;
  at: number;
}

interface DraftOptions {
  trigger?: ActionTrigger;
  code?: string;
  handler?: ActionHandler<any, any>;
  template?: ActionTemplateRef;
  /** Test or replay the deployed version of this Action instead of a draft. */
  slug?: string;
  secrets?: string[];
  allowedHosts?: string[];
  capabilities?: ActionCapability[];
}

export interface TestActionOptions extends DraftOptions {
  /** A recorded event (`actions.events()`). */
  eventId?: string;
  /** Your own event, merged over the trigger's sample event. */
  event?: Record<string, unknown>;
  /** `false` turns api.fetch off. */
  network?: boolean;
}

export interface ActionTestResult {
  outcome: 'ok' | 'error' | 'timeout';
  error: string | null;
  durationMs: number;
  cpuMs: number;
  calls: ActionCall[];
  /** What it would have sent (a test run sends nothing). */
  notifications: Array<Record<string, unknown>>;
  logs: ActionLogLine[];
  reasons: Array<{ code: string; text: string; action?: string }>;
  /** For a recorded pre-trigger event: the decision with this Action. */
  wouldBe: { verdict: string; reason: string | null; reasons?: string[] } | null;
  eventId: string | null;
  event: Record<string, unknown>;
  assumedCapabilities: ActionCapability[];
}

export interface DryRunActionOptions extends DraftOptions {
  /** The deployed Action this draft would replace (left out of the comparison). */
  replaces?: string;
  onFailure?: 'continue' | 'step_up' | 'deny';
  /** How many recent events (1-1000, default 500). */
  limit?: number;
  since?: Date | string;
}

export interface ActionDryRunResult {
  trigger: ActionTrigger;
  evaluated: number;
  from: string | null;
  to: string | null;
  matched: number;
  /** Pre triggers: decisions that would have come out differently. */
  changed: number | null;
  /** e.g. `{ 'push→number_match': 12 }`. */
  transitions: Record<string, number> | null;
  notifications: Record<string, number>;
  errors: number;
  timeouts: number;
  errorSamples: Array<{ eventId: string; error: string | null }>;
  p50Ms: number;
  p95Ms: number;
  samples: Array<Record<string, unknown>>;
  assumedCapabilities: ActionCapability[];
}

export interface RecordedActionEvent {
  id: string;
  trigger: ActionTrigger;
  time: string;
  user: string | null;
  requestId: string | null;
  outcome: Record<string, unknown> | null;
  event: ActionEvent;
}

export interface ActionRun {
  id: string;
  time: string;
  version: number | null;
  eventId: string | null;
  requestId: string | null;
  outcome: 'ok' | 'error' | 'timeout';
  decision: string | null;
  calls: ActionCall[];
  notifications: Array<{ type: string; status: 'sent' | 'failed' | 'skipped'; detail?: string }>;
  logs: ActionLogLine[];
  error: string | null;
  durationMs: number;
}

export interface ActionMetrics {
  window: '1h' | '24h' | '7d' | '30d';
  runs: number;
  errors: number;
  timeouts: number;
  errorRate: number;
  p50Ms: number;
  p95Ms: number;
  decisions: Record<string, number>;
  notifications: { sent: number; failed: number; skipped: number };
}

export interface ActionSecretInfo {
  name: string;
  createdAt: string;
  updatedAt: string;
}

export interface RenderedTemplate {
  code: string;
  secrets: string[];
  allowedHosts: string[];
  capabilities: ActionCapability[];
}

const SLUG_RE = /^[a-z0-9][a-z0-9-]{1,62}$/;
const SECRET_RE = /^[A-Z][A-Z0-9_]{0,63}$/;

function slugPath(slug: string): string {
  if (typeof slug !== 'string' || !SLUG_RE.test(slug)) {
    throw new TouchQueConfigError('An Action slug is 2-63 lowercase letters, digits or - (e.g. "night-alert")');
  }
  return `/actions/${slug}`;
}

function secretPath(name: string): string {
  if (typeof name !== 'string' || !SECRET_RE.test(name)) {
    throw new TouchQueConfigError('A secret name is capital letters, digits or _ (e.g. SLACK_WEBHOOK_URL)');
  }
  return `/actions/secrets/${name}`;
}

/** Turns a function into Action code: `exports.onExecute = <its source>;`. */
export function handlerToCode(handler: ActionHandler<any, any>): string {
  if (typeof handler !== 'function') throw new TouchQueConfigError('handler must be a function');
  const src = handler.toString();
  // A method shorthand ("onExecute(event, api) { … }") is not an expression.
  const expr = /^(async\s+)?(function\b|\(|[A-Za-z_$][\w$]*\s*=>)/.test(src) ? src : `${src.startsWith('async ') ? 'async ' : ''}function ${src.replace(/^async\s+/, '')}`;
  return `exports.onExecute = ${expr};\n`;
}

function draftBody(o: DraftOptions): Record<string, unknown> {
  if (o.code !== undefined && o.handler !== undefined) throw new TouchQueConfigError('Pass code or handler, not both');
  const code = o.handler ? handlerToCode(o.handler) : o.code;
  return {
    ...(o.trigger !== undefined && { trigger: o.trigger }),
    ...(o.slug !== undefined && { slug: o.slug }),
    ...(code !== undefined && { code }),
    ...(o.template !== undefined && { template: o.template }),
    ...(o.secrets !== undefined && { secrets: o.secrets }),
    ...(o.allowedHosts !== undefined && { allowedHosts: o.allowedHosts }),
    ...(o.capabilities !== undefined && { capabilities: o.capabilities }),
  };
}

export class ActionSecrets {
  constructor(private readonly http: HttpClient) {}

  /** Stores a value (encrypted; never readable again through the API). */
  async set(name: string, value: string): Promise<ActionSecretInfo> {
    if (typeof value !== 'string' || !value) throw new TouchQueConfigError('A secret value is a non-empty string');
    return this.http.put<ActionSecretInfo>(secretPath(name), { value });
  }

  /** Names only. */
  async list(): Promise<ActionSecretInfo[]> {
    const res = await this.http.get<{ secrets: ActionSecretInfo[] }>('/actions/secrets');
    return Array.isArray(res?.secrets) ? res.secrets : [];
  }

  async delete(name: string): Promise<{ deleted: boolean }> {
    return this.http.delete<{ deleted: boolean }>(secretPath(name));
  }
}

export class Actions {
  public readonly secrets: ActionSecrets;

  constructor(private readonly http: HttpClient) {
    this.secrets = new ActionSecrets(http);
  }

  /**
   * Creates the Action or adds a version and makes it live (idempotent: the
   * same code and settings change nothing). A version asking for a loosening
   * capability waits for an admin's phone approval (`approval.required`).
   *
   * @example
   * await tq.actions.deploy('admins-use-passkeys', {
   *   trigger: 'login.request',
   *   handler: async (event, api) => {
   *     if ((event.context?.roles as string[] | undefined)?.includes('admin')) api.requirePasskey('Admins approve with a passkey');
   *   },
   * });
   */
  async deploy(slug: string, options: DeployActionOptions): Promise<ActionDeployResult> {
    const path = slugPath(slug);
    const body: Record<string, unknown> = {
      ...draftBody(options),
      ...(options.name !== undefined && { name: options.name }),
      ...(options.onFailure !== undefined && { onFailure: options.onFailure }),
      ...(options.order !== undefined && { order: options.order }),
      ...(options.enabled !== undefined && { enabled: options.enabled }),
      ...(options.activate !== undefined && { activate: options.activate }),
    };
    if (body.code === undefined && body.template === undefined) throw new TouchQueConfigError('deploy() needs code, handler or template');
    return this.http.put<ActionDeployResult>(path, body);
  }

  async list(): Promise<ActionSummary[]> {
    const res = await this.http.get<{ actions: ActionSummary[] }>('/actions');
    return Array.isArray(res?.actions) ? res.actions : [];
  }

  /** The Action, the active version's code and its versions. */
  async get(slug: string): Promise<ActionDetail> {
    return this.http.get<ActionDetail>(slugPath(slug));
  }

  /** One version, with its code. */
  async version(slug: string, number: number): Promise<ActionVersion> {
    if (!Number.isInteger(number)) throw new TouchQueConfigError('version() needs a version number');
    return this.http.get<ActionVersion>(`${slugPath(slug)}/versions/${number}`);
  }

  /** Rename, turn on or off, reorder, change onFailure. */
  async update(slug: string, changes: UpdateActionOptions): Promise<ActionSummary> {
    const res = await this.http.patch<{ action: ActionSummary }>(slugPath(slug), { ...changes });
    return res.action;
  }

  async delete(slug: string): Promise<{ deleted: boolean }> {
    return this.http.delete<{ deleted: boolean }>(slugPath(slug));
  }

  /** Back to `version`, or to the newest runnable version before the active one. Takes effect at once. */
  async rollback(slug: string, version?: number): Promise<{ action: ActionSummary; version: ActionVersion }> {
    return this.http.post(`${slugPath(slug)}/rollback`, version === undefined ? {} : { version });
  }

  /** Runs a draft (or a deployed Action) once on a recorded, given or sample event. Sends no notification. */
  async test(options: TestActionOptions): Promise<ActionTestResult> {
    return this.http.post<ActionTestResult>('/actions/test', {
      ...draftBody(options),
      ...(options.eventId !== undefined && { eventId: options.eventId }),
      ...(options.event !== undefined && { event: options.event }),
      ...(options.network !== undefined && { network: options.network }),
    });
  }

  /** Replays a draft against recent real decisions: how many it would have changed, and how. */
  async dryRun(options: DryRunActionOptions): Promise<ActionDryRunResult> {
    const since = options.since instanceof Date ? options.since.toISOString() : options.since;
    return this.http.post<ActionDryRunResult>('/actions/dry-run', {
      ...draftBody(options),
      ...(options.replaces !== undefined && { replaces: options.replaces }),
      ...(options.onFailure !== undefined && { onFailure: options.onFailure }),
      ...(options.limit !== undefined && { limit: options.limit }),
      ...(since !== undefined && { since }),
    });
  }

  /** Recorded events (newest first, kept 30 days); use an id with test(). */
  async events(options: { trigger?: ActionTrigger; limit?: number } = {}): Promise<RecordedActionEvent[]> {
    const params: Record<string, string | number> = {};
    if (options.trigger) params.trigger = options.trigger;
    if (options.limit !== undefined) params.limit = options.limit;
    const res = await this.http.get<{ events: RecordedActionEvent[] }>('/actions/events', params);
    return Array.isArray(res?.events) ? res.events : [];
  }

  /** Live runs of an Action: decision, notifications, console output, errors. */
  async logs(slug: string, options: { limit?: number; before?: Date | string } = {}): Promise<ActionRun[]> {
    const params: Record<string, string | number> = {};
    if (options.limit !== undefined) params.limit = options.limit;
    if (options.before !== undefined) params.before = options.before instanceof Date ? options.before.toISOString() : options.before;
    const res = await this.http.get<{ logs: ActionRun[] }>(`${slugPath(slug)}/logs`, params);
    return Array.isArray(res?.logs) ? res.logs : [];
  }

  async metrics(slug: string, options: { window?: '1h' | '24h' | '7d' | '30d' } = {}): Promise<ActionMetrics> {
    return this.http.get<ActionMetrics>(`${slugPath(slug)}/metrics`, options.window ? { window: options.window } : undefined);
  }

  /** Every trigger with its decisions, capabilities, notification types and a sample event. */
  async triggers(): Promise<{ triggers: Array<Record<string, unknown>>; capabilities: Array<Record<string, unknown>>; limits: Record<string, number> }> {
    return this.http.get('/actions/triggers');
  }

  /** No-code templates. */
  async templates(): Promise<Array<{ id: string; name: string; description: string; triggers: ActionTrigger[]; params: Record<string, string> }>> {
    const res = await this.http.get<{ templates: Array<{ id: string; name: string; description: string; triggers: ActionTrigger[]; params: Record<string, string> }> }>('/actions/templates');
    return Array.isArray(res?.templates) ? res.templates : [];
  }

  /** A template as plain code (to read, or to start a code Action from). */
  async renderTemplate(id: string, trigger: ActionTrigger, params: Record<string, unknown> = {}): Promise<RenderedTemplate> {
    if (typeof id !== 'string' || !/^[a-z_]{1,64}$/.test(id)) throw new TouchQueConfigError('Unknown template id');
    return this.http.post<RenderedTemplate>(`/actions/templates/${id}/render`, { trigger, params });
  }
}
