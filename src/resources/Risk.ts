// src/resources/Risk.ts
// Silent sign-ins: ask TouchQue's risk engine whether a sign-in needs the
// phone at all, and manage the browsers it knows for a user.
//
// A browser becomes known when the user approves a request on the phone (or
// with a passkey) that carried the browser's device-bound key proof
// (`login.request({ browserProof })`). Later, `risk.check` with a fresh proof
// from the same browser answers `prompt: false` when nothing about the
// sign-in is new. Nothing is sent to the phone by `risk.check`.

import { HttpClient } from '../core/HttpClient';
import { TouchQueConfigError } from '../errors';
import {
  ForgetBrowsersOptions,
  ForgetBrowsersResponse,
  RiskBrowsersOptions,
  RiskBrowsersResponse,
  RiskCheckOptions,
  RiskCheckResult,
  RiskReason,
} from '../types';

const ASSURANCE = new Set(['high', 'normal', 'low']);

/**
 * Reads a `POST /risk/check` answer, failing closed: `prompt` is false ONLY
 * when the answer says exactly `prompt: false` (a boolean). Malformed
 * `reasons` become `[]`, and an unknown or missing `assurance` is `'normal'`.
 */
export function parseRiskCheck(raw: unknown): RiskCheckResult {
  const body = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {};
  const reasons: RiskReason[] = Array.isArray(body.reasons)
    ? body.reasons
      .filter((r): r is { code: string; text?: unknown } => Boolean(r) && typeof (r as { code?: unknown }).code === 'string')
      .map((r) => ({ code: r.code, text: typeof r.text === 'string' ? r.text : '' }))
    : [];
  return {
    prompt: body.prompt !== false,
    reasons,
    assurance: typeof body.assurance === 'string' && ASSURANCE.has(body.assurance) ? (body.assurance as RiskCheckResult['assurance']) : 'normal',
    silentMode: body.silentMode === 'shadow' ? 'shadow' : 'enforce',
  };
}

export class Risk {
  constructor(private readonly http: HttpClient) {}

  /**
   * Should this sign-in ask the phone? Sends nothing to the phone.
   * Skip the push only when `prompt` is `false`; on any error, ask as usual.
   *
   * @example
   * const browserProof = req.get('x-touchque-browser');
   * const risk = await tq.risk.check({ externalUsername: user, browserProof, clientIp: req.ip });
   * if (!risk.prompt) return signIn(user); // known browser, nothing new
   * await tq.login.request({ externalUsername: user, type: 'LOGIN', browserProof });
   */
  async check(options: RiskCheckOptions): Promise<RiskCheckResult> {
    if (!options?.externalUsername) throw new TouchQueConfigError('risk.check() needs the user (externalUsername)');
    const raw = await this.http.post<unknown>('/risk/check', {
      externalUsername: options.externalUsername,
      ...(options.type && { type: options.type }),
      ...(options.clientIp && { clientIp: options.clientIp }),
      ...(options.userAgent && { userAgent: options.userAgent }),
      ...(options.browserProof && { browserProof: options.browserProof }),
      ...(options.maxAgeSeconds !== undefined && { maxAgeSeconds: options.maxAgeSeconds }),
    });
    return parseRiskCheck(raw);
  }

  /** The browsers TouchQue knows for a user (for an "approved browsers" list in your settings page). */
  async browsers(options: RiskBrowsersOptions): Promise<RiskBrowsersResponse> {
    if (!options?.externalUsername) throw new TouchQueConfigError('risk.browsers() needs the user (externalUsername)');
    const res = await this.http.get<RiskBrowsersResponse>('/risk/browsers', { externalUsername: options.externalUsername });
    return { browsers: Array.isArray(res?.browsers) ? res.browsers : [] };
  }

  /**
   * Forgets one browser (`thumbprint`) or all of a user's browsers: their next
   * sign-in asks the phone again. Call it after a password reset or when the
   * user signs out everywhere.
   */
  async forgetBrowsers(options: ForgetBrowsersOptions): Promise<ForgetBrowsersResponse> {
    if (!options?.externalUsername) throw new TouchQueConfigError('risk.forgetBrowsers() needs the user (externalUsername)');
    return this.http.post<ForgetBrowsersResponse>('/risk/browsers/forget', {
      externalUsername: options.externalUsername,
      ...(options.thumbprint && { thumbprint: options.thumbprint }),
    });
  }
}
