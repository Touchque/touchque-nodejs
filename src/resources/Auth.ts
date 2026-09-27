// Secret management — generate, reset

import { HttpClient } from '../core/HttpClient';
import {
  GenerateSecretOptions,
  GenerateSecretResponse,
  GetUserResponse,
  ResetSecretOptions,
  ResetSecretResponse,
  ValidateSecretOptions,
  ValidateSecretResponse,
} from '../types';

export class Auth {
  constructor(private readonly http: HttpClient) {}

  /**
   * Generate a new setup secret for a user.
   * Show this secret to the user ONCE (e.g. as a QR code) so they can
   * link their TouchQue app.
   *
   * The secret expires after 60 seconds if not used (scanned by the mobile app).
   * After expiry, calling this method again will automatically rotate the secret.
   *
   * @example
   * const { secret, expiresAt } = await tq.auth.generateSecret({
   *   externalUsername: 'user@company.com'
   * });
   * // Show `secret` to user as QR code
   * // Secret expires at `expiresAt` if not scanned
   */
  async generateSecret(options: GenerateSecretOptions): Promise<GenerateSecretResponse> {
    return this.http.post<GenerateSecretResponse>('/auth/generate-secret', {
      externalUsername: options.externalUsername,
    });
  }


  /**
   * Reset (regenerate) a user's secret.
   * This invalidates the old secret and generates a new one.
   * Show the new secret to the user.
   *
   * @example
   * const { secret } = await tq.auth.resetSecret({
   *   externalUsername: 'user@company.com'
   * });
   * // Show new secret to user
   */
  async resetSecret(options: ResetSecretOptions): Promise<ResetSecretResponse> {
    return this.http.post<ResetSecretResponse>('/auth/secret/reset', {
      externalUsername: options.externalUsername,
    });
  }

  /**
   * Validate a secret code.
   * Useful if you want to verify the user entered the correct setup secret.
   * Note: The backend allows this without an API key, but the SDK sends it for consistency.
   */
  async validateSecret(options: ValidateSecretOptions): Promise<ValidateSecretResponse> {
    return this.http.post<ValidateSecretResponse>('/auth/secret/validate', {
      secret: options.secret,
    });
  }

  /**
   * Look up a user's current link status — no push notification is sent.
   * Useful for detecting "the mobile app just linked this secret" (`used`
   * flips true, `deviceId` gets set) without sending a LOGIN challenge to
   * their device, e.g. while polling during enrollment.
   *
   * @example
   * const { used, deviceId } = await tq.auth.getUser({
   *   externalUsername: 'user@company.com'
   * });
   * if (used && deviceId) {
   *   // Device has linked — no approval push needed to confirm this.
   * }
   */
  async getUser(options: { externalUsername: string }): Promise<GetUserResponse> {
    return this.http.get<GetUserResponse>(`/users/${encodeURIComponent(options.externalUsername)}`);
  }

}
