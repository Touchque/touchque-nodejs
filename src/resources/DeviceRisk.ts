// src/resources/DeviceRisk.ts
// Device risk (a paid add-on, off until your workspace turns it on): a
// visitor ID for every browser on your sign-up, password-reset, sign-in or
// approval page. The page identifies with `@touchque/web`
// (`deviceRisk.identify({ siteKey, purpose })` → `{ visitorId, requestId,
// confidence }`) and sends you the requestId; never trust the page's copy:
// read the identification here (`getEvent`) or check it for an account
// (`check`). TouchQue keeps keyed hashes only, with a key of your workspace
// alone, and its risk engine decides.
//
// Every signal only ever asks for more: `stepUp` means an extra check on
// this page (an emailed code, a passkey, a number-matched approval), never a
// refusal. For sign-ins, pass the requestId to `login.request` / `risk.check`
// as `deviceRiskRequestId` instead.
//
// With the script tag (device.js), the form arrives with `touchque_request_id`:
//   const r = await tq.deviceRisk.check(req.body.touchque_request_id, { event: 'sign_in', externalUsername });
// Pass it as it came. Missing, empty, made up or expired, it is still a
// verdict (`report: 'missing' | 'unknown' | 'expired'`, the signal
// device_identification_missing), never an exception: a page without the
// tag, or with it blocked, only gets the visitor a step-up.

import { HttpClient } from '../core/HttpClient';
import { TouchQueConfigError } from '../errors';
import { DeviceRiskCheckOptions, DeviceRiskCheckRequest, DeviceRiskCheckResult, DeviceRiskEvent, DeviceRiskEventResult, DeviceRiskSearchOptions, DeviceRiskSearchResult } from '../types';

export const DEVICE_RISK_EVENTS: readonly DeviceRiskEvent[] = ['sign_in', 'sign_up', 'password_reset', 'approval'];
/** What the page had sent: `ok`, `replayed`, or not a usable identification (`missing`, `unknown`, `expired`, `invalid`). */
export const DEVICE_RISK_REPORTS: readonly DeviceRiskCheckResult['report'][] = ['ok', 'replayed', 'missing', 'unknown', 'expired', 'invalid'];

/** The page's form field as it came: a string, or nothing (TouchQue answers `missing`). */
const fieldValue = (v: unknown): string | null => (typeof v === 'string' && v !== '' ? v.slice(0, 64) : null);
/** The relayed report (`deviceRisk.collect()`, a few KB) goes whole: a cut one cannot be decoded. Touchque checks its size. */
const reportValue = (v: unknown): string | null => (typeof v === 'string' && v !== '' ? v : null);

/** Reads a `POST /device-risk/check` answer, failing toward asking: `stepUp` is true unless it says exactly `false`. */
export function parseDeviceRiskCheck(raw: unknown): DeviceRiskCheckResult {
  const body = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {};
  const signals = Array.isArray(body.signals)
    ? body.signals
      .filter((s): s is Record<string, unknown> => Boolean(s) && typeof (s as { code?: unknown }).code === 'string')
      .map((s) => ({
        code: s.code as string,
        text: typeof s.text === 'string' ? s.text : '',
        strength: (s.strength === 'passkey' || s.strength === 'none' ? s.strength : 'number_match') as DeviceRiskCheckResult['signals'][number]['strength'],
        ...(typeof s.enforced === 'boolean' ? { enforced: s.enforced } : {}),
        ...(s.evidence && typeof s.evidence === 'object' ? { evidence: s.evidence as Record<string, unknown> } : {}),
      }))
    : [];
  const report = DEVICE_RISK_REPORTS.includes(body.report as DeviceRiskCheckResult['report']) ? (body.report as DeviceRiskCheckResult['report']) : 'invalid';
  return {
    report,
    requestId: typeof body.requestId === 'string' ? body.requestId : null,
    visitorId: typeof body.visitorId === 'string' ? body.visitorId : null,
    confidence: typeof body.confidence === 'number' ? body.confidence : null,
    visitor: body.visitor && typeof body.visitor === 'object' ? (body.visitor as DeviceRiskCheckResult['visitor']) : null,
    counts: body.counts && typeof body.counts === 'object' ? (body.counts as DeviceRiskCheckResult['counts']) : null,
    network: body.network && typeof body.network === 'object' ? (body.network as DeviceRiskCheckResult['network']) : null,
    velocity: body.velocity && typeof body.velocity === 'object' ? (body.velocity as DeviceRiskCheckResult['velocity']) : null,
    bot: body.bot && typeof body.bot === 'object' ? (body.bot as DeviceRiskCheckResult['bot']) : null,
    signals,
    stepUp: body.stepUp !== false,
    wouldStepUp: body.wouldStepUp === true,
    requires: body.requires === 'passkey' || body.requires === 'number_match' ? body.requires : 'none',
    mode: body.mode === 'enforce' ? 'enforce' : 'shadow',
    engine: typeof body.engine === 'string' ? body.engine : null,
    ...(typeof body.caseCode === 'string' && { caseCode: body.caseCode }),
  };
}

const REQUEST_ID = /^dre_[A-Za-z0-9_-]{22}$/;

export class DeviceRisk {
  constructor(private readonly http: HttpClient) {}

  /**
   * Checks the page's identification for an account: binds it (one account
   * per identification, 15 minutes) and asks the risk engine. Pass the form
   * field as it came: no requestId, an empty or a made-up one is still a
   * verdict, never an exception. 409 `device_risk_off` until your workspace
   * turns Device risk on.
   *
   * @example
   * const r = await tq.deviceRisk.check(req.body.touchque_request_id, { event: 'sign_up', externalUsername: email, clientIp: req.ip });
   * if (r.stepUp) return askForEmailCode(); // never refuse on it alone
   */
  async check(requestId?: string | null | DeviceRiskCheckOptions, options: DeviceRiskCheckRequest = {}): Promise<DeviceRiskCheckResult> {
    // The object form: check({ requestId | deviceRisk, event, externalUsername, clientIp }).
    const o: DeviceRiskCheckOptions = requestId !== null && typeof requestId === 'object'
      ? requestId
      : { ...options, requestId: requestId as string | null | undefined };
    if (o.event !== undefined && !DEVICE_RISK_EVENTS.includes(o.event)) {
      throw new TouchQueConfigError(`deviceRisk.check() event must be one of ${DEVICE_RISK_EVENTS.join(', ')}`);
    }
    const id = fieldValue(o.requestId);
    const report = id ? null : reportValue(o.deviceRisk);
    const raw = await this.http.post<unknown>('/device-risk/check', {
      ...(id ? { requestId: id } : report ? { deviceRisk: report } : {}),
      ...(o.event && { event: o.event }),
      ...(o.externalUsername && { externalUsername: o.externalUsername }),
      ...(o.clientIp && { clientIp: o.clientIp }),
    });
    return parseDeviceRiskCheck(raw);
  }

  /**
   * Your workspace's identifications, newest first, one page at a time: a
   * date range (7 days by default, at most 90, within your retention) and any
   * of the filters. Pass `nextCursor` back as `cursor` until it is null; do
   * not page by moving `from`/`to`. A search that would read too much is a
   * 422 `search_too_broad`: narrow the range or add a filter. An address is a
   * filter only: no identification carries one.
   *
   * @example
   * let cursor = null;
   * do {
   *   const page = await tq.deviceRisk.searchEvents({ signal: 'device_tampered', from: '2026-11-01', cursor });
   *   for (const e of page.events) console.log(e.at, e.visitorId, e.caseCode);
   *   cursor = page.nextCursor;
   * } while (cursor);
   */
  async searchEvents(options: DeviceRiskSearchOptions = {}): Promise<DeviceRiskSearchResult> {
    const params: Record<string, string | number | boolean> = {};
    const day = (v: Date | string) => (v instanceof Date ? v.toISOString() : v);
    if (options.from !== undefined) params.from = day(options.from);
    if (options.to !== undefined) params.to = day(options.to);
    for (const k of ['signal', 'kind', 'origin', 'ip', 'account', 'visitorId', 'requestId'] as const) {
      const v = options[k];
      if (typeof v === 'string' && v) params[k] = v;
    }
    if (typeof options.stepUp === 'boolean') params.stepUp = options.stepUp;
    if (typeof options.cursor === 'string' && options.cursor) params.cursor = options.cursor;
    if (options.limit !== undefined) {
      if (!Number.isInteger(options.limit) || options.limit < 1 || options.limit > 100) throw new TouchQueConfigError('deviceRisk.searchEvents() limit must be 1 to 100');
      params.limit = options.limit;
    }
    const raw = await this.http.get<Partial<DeviceRiskSearchResult>>('/device-risk/events', params);
    return {
      events: Array.isArray(raw?.events) ? raw.events : [],
      nextCursor: typeof raw?.nextCursor === 'string' && raw.nextCursor ? raw.nextCursor : null,
      from: typeof raw?.from === 'string' ? raw.from : '',
      to: typeof raw?.to === 'string' ? raw.to : '',
    };
  }

  /** The trusted identification behind a requestId: the visitor, how sure, what the page showed, the engine's verdict. Read-only. */
  async getEvent(requestId: string): Promise<DeviceRiskEventResult> {
    if (typeof requestId !== 'string' || !REQUEST_ID.test(requestId)) throw new TouchQueConfigError('deviceRisk.getEvent() needs a requestId (dre_…)');
    return this.http.get<DeviceRiskEventResult>(`/device-risk/events/${encodeURIComponent(requestId)}`);
  }
}
