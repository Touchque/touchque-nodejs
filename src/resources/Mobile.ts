// src/resources/Mobile.ts
// TouchQue Mobile SDK, your backend's side: your own iOS/Android app is the
// approver of your users (white-label); they never install the TouchQue app.
//
// 1. A user signed in to your app turns approvals on: `createEnrollment`
//    gives a one-time token; your app hands it to the SDK (`TouchQue.enroll`).
// 2. Ask for approvals as always (`tq.login.request`, `tq.start`, guards…):
//    they reach your app over the SDK's encrypted connection.
// 3. TouchQue holds no push key of your app. For each request it sends you a
//    signed MOBILE_PUSH webhook: verify it (`tq.webhook.verify`), then
//    `mobilePushFromWebhook(event)` gives the APNs payload / FCM data to send
//    with your own credentials.

import { HttpClient } from '../core/HttpClient';
import { TouchQueConfigError } from '../errors';

export interface MobileEnrollment {
  enrollmentId: string;
  /** One-time `tqe_…` token. Hand it to your app over your own signed-in API; never put it in a URL or QR code. */
  enrollmentToken: string;
  externalUsername: string;
  expiresAt: string;
  replace: boolean;
  /** With `replace`: the device that approves today and stops when the token is used. */
  replacesDeviceId?: string;
}

export interface CreateMobileEnrollmentOptions {
  externalUsername: string;
  /** Move the user from the device they approve with today (409 `already_enrolled` otherwise). */
  replace?: boolean;
  /** 60–86400; default the workspace's `enrollTtlSeconds` (600). */
  ttlSeconds?: number;
}

export interface MobileDevice {
  deviceId: string;
  externalUsername: string;
  platform: 'ios' | 'android';
  appId: string | null;
  sdkVersion: string | null;
  /** `apple-appattest` / `android-key` when the app and its key were proven at enrollment. */
  attestation: string | null;
  status: 'active' | 'revoked';
  revokedReason: 'replaced' | 'removed' | 'signed_out' | null;
  revokedAt: string | null;
  enrolledAt: string;
  lastSeenAt: string | null;
  /** getDevice only: whether it is the user's approver right now. */
  linked?: boolean;
  hardwareKey: { registered: boolean; attestation: string | null; lostAt: string | null } | null;
  pushToken: boolean;
  posture: { report: Record<string, unknown>; at: string; signed: boolean } | null;
}

export interface ListMobileDevicesOptions {
  externalUsername?: string;
  status?: 'active' | 'revoked' | 'all';
  limit?: number;
  cursor?: string;
}

export interface MobileSdkSettings {
  /** `TEAMID.bundle.id` of your iOS apps: only they may enrol, and App Attest is checked against them. */
  iosAppIds: string[];
  /** Your Android package names: only they may enrol, and Key Attestation is checked against them. */
  androidPackages: string[];
  /** SHA-256 of each Android app's signing certificate ("AB:CD:…"), by package: Key Attestation must name one. */
  androidCerts: Record<string, string[]>;
  /** `required`: an app that can't prove itself can't enrol. */
  attestation: 'off' | 'optional' | 'required';
  enrollTtlSeconds: number;
  /** Who sends the push per platform: `touchque` (with your own keys, given below) or `webhook` (MOBILE_PUSH to you). */
  push: MobilePushSettings;
  updatedAt?: string | null;
}

/** Your push keys as TouchQue shows them (never the keys themselves). */
export interface MobilePushSettings {
  ios: 'touchque' | 'webhook';
  android: 'touchque' | 'webhook';
  apns: { keyId: string; teamId: string; topic: string; production: boolean } | null;
  fcm: { projectId: string; clientEmail: string } | null;
}

/** What `mobile.updateSettings` changes; only the fields given. */
export interface MobileSdkSettingsUpdate {
  iosAppIds?: string[];
  androidPackages?: string[];
  /** Package name → SHA-256 fingerprints of its signing certificate (Play app signing key; upload key while testing). */
  androidCerts?: Record<string, string[]>;
  attestation?: 'off' | 'optional' | 'required';
  enrollTtlSeconds?: number;
  /**
   * Your APNs key: TouchQue then sends the iOS push itself instead of the MOBILE_PUSH webhook. `key` is the .p8
   * file's text (leave it out to keep the stored key); `topic` your app's bundle id. null removes it.
   */
  apns?: { keyId?: string; teamId?: string; topic?: string; key?: string; production?: boolean } | null;
  /** Your Firebase service account (the JSON, as an object or text): TouchQue then sends the Android push. null removes it. */
  fcm?: { serviceAccount: Record<string, unknown> | string } | null;
}

/** A MOBILE_PUSH webhook, ready to send with your own APNs / FCM credentials. */
export interface MobilePush {
  deviceId: string;
  externalUsername: string;
  platform: 'ios' | 'android';
  /** The token your app handed to the SDK, or null: then send to the user's devices by your own mapping. */
  pushToken: string | null;
  requestId: string | null;
  /** Drop the push after this. */
  expiresAt: string | null;
  /** `test`: a test push sent from the dashboard (or POST /mobile/devices/:id/test-push). */
  kind: 'approval' | 'notice' | 'test';
  /** Suggested text (English); translate or replace it. */
  alert: { title: string; body: string } | null;
  /** iOS: the APNs payload (alert + the custom key `touchque`). Add your own keys if you like. */
  apns: { aps: { alert?: { title: string; body: string }; sound: string; 'interruption-level': string }; touchque: string };
  /** Android: the FCM data map (a data message; your app builds the notification). */
  fcmData: Record<string, string>;
}

export class Mobile {
  constructor(private readonly http: HttpClient) {}

  /**
   * A one-time enrollment token for a user you signed in. Whoever spends it
   * becomes the user's approver, so authenticate the user first. Throws
   * TouchQueAPIError `already_enrolled` (send `replace: true`) or `account_frozen`.
   *
   * @example
   * const { enrollmentToken } = await tq.mobile.createEnrollment({ externalUsername: user.id });
   * res.json({ enrollmentToken }); // the app calls TouchQue.enroll(token)
   */
  async createEnrollment(options: CreateMobileEnrollmentOptions): Promise<MobileEnrollment> {
    if (!options?.externalUsername) throw new TouchQueConfigError('mobile.createEnrollment() needs the user (externalUsername)');
    return this.http.post<MobileEnrollment>('/mobile/enrollments', {
      externalUsername: options.externalUsername,
      ...(options.replace && { replace: true }),
      ...(options.ttlSeconds !== undefined && { ttlSeconds: options.ttlSeconds }),
    });
  }

  /** The devices inside your app (default: active ones), newest first. */
  async listDevices(options: ListMobileDevicesOptions = {}): Promise<{ devices: MobileDevice[]; nextCursor: string | null }> {
    return this.http.get('/mobile/devices', {
      ...(options.externalUsername && { externalUsername: options.externalUsername }),
      ...(options.status && { status: options.status }),
      ...(options.limit !== undefined && { limit: options.limit }),
      ...(options.cursor && { cursor: options.cursor }),
    });
  }

  async getDevice(deviceId: string): Promise<MobileDevice> {
    if (!deviceId) throw new TouchQueConfigError('mobile.getDevice() needs the device id');
    return (await this.http.get<{ device: MobileDevice }>(`/mobile/devices/${encodeURIComponent(deviceId)}`)).device;
  }

  /** Stops a device from approving (the user has no approver until you enrol again). */
  async removeDevice(deviceId: string): Promise<{ removed: boolean; wasLinked: boolean }> {
    if (!deviceId) throw new TouchQueConfigError('mobile.removeDevice() needs the device id');
    return this.http.delete(`/mobile/devices/${encodeURIComponent(deviceId)}`);
  }

  /**
   * A harmless push to the device, the way a request would reach it: by TouchQue with your key for its
   * platform, else the MOBILE_PUSH webhook (kind `test`). `ok`: APNs / FCM accepted it (or the webhook left).
   */
  async testPush(deviceId: string): Promise<{ via: 'touchque' | 'webhook'; ok: boolean; reason?: string }> {
    if (!deviceId) throw new TouchQueConfigError('mobile.testPush() needs the device id');
    return this.http.post(`/mobile/devices/${encodeURIComponent(deviceId)}/test-push`, {});
  }

  async settings(): Promise<MobileSdkSettings> {
    return (await this.http.get<{ settings: MobileSdkSettings }>('/mobile/settings')).settings;
  }

  /** Which apps may enrol, whether they must prove themselves, and your push keys. Only the fields given change. */
  async updateSettings(changes: MobileSdkSettingsUpdate): Promise<MobileSdkSettings> {
    return (await this.http.put<{ settings: MobileSdkSettings }>('/mobile/settings', changes as Record<string, unknown>)).settings;
  }
}

/**
 * The push to send for a verified MOBILE_PUSH webhook, or null for any other
 * event. The data carries no secret, no details and no matching number.
 *
 * @example
 * const event = tq.webhook.verify({ rawBody, headers });
 * const push = mobilePushFromWebhook(event);
 * if (push?.platform === 'ios') await apns.send(push.pushToken, push.apns);
 * if (push?.platform === 'android') await fcm.send({ token: push.pushToken, data: push.fcmData, android: { priority: 'high' } });
 */
export function mobilePushFromWebhook(event: Record<string, unknown> | null | undefined): MobilePush | null {
  if (!event || event.event !== 'MOBILE_PUSH') return null;
  const data = (event.data || {}) as Record<string, unknown>;
  const touchque = typeof data.touchque === 'string' ? data.touchque : JSON.stringify(data.touchque ?? {});
  const alert = (event.alert as MobilePush['alert']) || null;
  return {
    deviceId: String(event.deviceId),
    externalUsername: String(event.externalUsername),
    platform: event.platform === 'android' ? 'android' : 'ios',
    pushToken: typeof event.pushToken === 'string' ? event.pushToken : null,
    requestId: typeof event.requestId === 'string' ? event.requestId : null,
    expiresAt: typeof event.expiresAt === 'string' ? event.expiresAt : null,
    kind: event.kind === 'notice' || event.kind === 'test' ? event.kind : 'approval',
    alert,
    apns: { aps: { ...(alert && { alert }), sound: 'default', 'interruption-level': 'time-sensitive' }, touchque },
    fcmData: { touchque },
  };
}

/** True once a push is past its request's expiry (don't send it any more). */
export function isMobilePushExpired(push: Pick<MobilePush, 'expiresAt'>, now: Date = new Date()): boolean {
  return Boolean(push.expiresAt) && new Date(push.expiresAt as string).getTime() <= now.getTime();
}
