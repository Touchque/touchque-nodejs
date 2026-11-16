// Secret management — generate, reset

import { HttpClient } from '../core/HttpClient';
import {
  GenerateSecretOptions,
  GenerateSecretResponse,
  GetUserResponse,
  ResetSecretOptions,
  ResetSecretResponse,
  SetupContext,
  ValidateSecretOptions,
  ValidateSecretResponse,
} from '../types';

/** A JSON object (not an array), or null. */
const objectOf = (v: unknown): Record<string, unknown> | null =>
  (v !== null && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : null);
/** A string, or null for anything else (a number, an object, null…). */
const textOf = (v: unknown): string | null => (typeof v === 'string' ? v : null);

/**
 * Reads the `setupContext` of a `POST /auth/secret/validate` answer, leniently:
 * a missing or null one, or one that is not an object, is null; inside it a
 * field that is missing, null or of another type is null (a `location` or
 * `device` that is not an object too), and unknown fields are dropped.
 * `requestedAt` stays the string Touchque sent. Never throws.
 */
export function parseSetupContext(raw: unknown): SetupContext | null {
  const c = objectOf(raw);
  if (!c) return null;
  const location = objectOf(c.location);
  const device = objectOf(c.device);
  return {
    ip: textOf(c.ip),
    location: location ? { city: textOf(location.city), country: textOf(location.country), countryCode: textOf(location.countryCode) } : null,
    device: device ? { browser: textOf(device.browser), os: textOf(device.os), model: textOf(device.model) } : null,
    requestedAt: textOf(c.requestedAt),
    farFromPhone: typeof c.farFromPhone === 'boolean' ? c.farFromPhone : null,
  };
}

export class Auth {
  constructor(private readonly http: HttpClient) {}

  /**
   * Generate a new setup secret for a user.
   * Show this secret to the user ONCE (e.g. as a QR code) so they can
   * link their Touchque app.
   *
   * The secret expires after 60 seconds if not used (scanned by the mobile app).
   * After expiry, calling this method again will automatically rotate the secret.
   *
   * Pass `clientIp` and `userAgent` from the browser's request, as for a login
   * request: Touchque records them with the secret (never in the QR), and the
   * phone shows where the QR was asked for before it links (`setupContext` on
   * `validateSecret`).
   *
   * @example
   * const { secret, expiresAt } = await tq.auth.generateSecret({
   *   externalUsername: 'user@company.com',
   *   clientIp: req.ip,
   *   userAgent: req.get('user-agent'),
   * });
   * // Show `secret` to user as QR code
   * // Secret expires at `expiresAt` if not scanned
   */
  async generateSecret(options: GenerateSecretOptions): Promise<GenerateSecretResponse> {
    return this.http.post<GenerateSecretResponse>('/auth/generate-secret', {
      externalUsername: options.externalUsername,
      // The same rule as login.request: only a value that is given (not empty), as given.
      ...(options.clientIp && { clientIp: options.clientIp }),
      ...(options.userAgent && { userAgent: options.userAgent }),
    });
  }


  /**
   * Reset (regenerate) a user's secret.
   * This invalidates the old secret and generates a new one.
   * Show the new secret to the user.
   *
   * `clientIp` and `userAgent`: the browser asking for the new QR, sent as
   * `generateSecret` sends them.
   *
   * @example
   * const { secret } = await tq.auth.resetSecret({
   *   externalUsername: 'user@company.com',
   *   clientIp: req.ip,
   *   userAgent: req.get('user-agent'),
   * });
   * // Show new secret to user
   */
  async resetSecret(options: ResetSecretOptions): Promise<ResetSecretResponse> {
    return this.http.post<ResetSecretResponse>('/auth/secret/reset', {
      externalUsername: options.externalUsername,
      ...(options.clientIp && { clientIp: options.clientIp }),
      ...(options.userAgent && { userAgent: options.userAgent }),
    });
  }

  /**
   * Validate a secret code.
   * Useful if you want to verify the user entered the correct setup secret.
   * Note: The backend allows this without an API key, but the SDK sends it for consistency.
   *
   * The answer's `setupContext` is where the QR was asked for (IP address,
   * place, browser and device, time), as the phone shows it before linking, or
   * null; see {@link parseSetupContext} for how it is read.
   */
  async validateSecret(options: ValidateSecretOptions): Promise<ValidateSecretResponse> {
    const res = await this.http.post<ValidateSecretResponse>('/auth/secret/validate', {
      secret: options.secret,
    });
    // Anything but a JSON object (never from the API) comes back as it came.
    if (!objectOf(res)) return res;
    return { ...res, setupContext: parseSetupContext(res.setupContext) };
  }

  /**
   * Look up a user's current link status — no push notification is sent.
   * Useful for detecting "the mobile app just linked this secret" (`used`
   * flips true, `deviceId` gets set) without sending a LOGIN challenge to
   * their device, e.g. while polling during enrollment.
   *
   * `device` is the linked phone's posture for device trust (`DevicePosture`:
   * OS version, screen lock, jailbreak/root, hardware key, `state`, `issues`),
   * or `null` before a phone is linked.
   *
   * @example
   * const { used, deviceId, device } = await tq.auth.getUser({
   *   externalUsername: 'user@company.com'
   * });
   * if (used && deviceId) {
   *   // Device has linked — no approval push needed to confirm this.
   * }
   * if (device?.state === 'compromised') {
   *   // The phone is jailbroken/rooted or tampered with.
   * }
   */
  async getUser(options: { externalUsername: string }): Promise<GetUserResponse> {
    return this.http.get<GetUserResponse>(`/users/${encodeURIComponent(options.externalUsername)}`);
  }

}
