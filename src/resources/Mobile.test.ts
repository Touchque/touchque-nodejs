// Mobile SDK (the partner's own app as the approver) in the Node SDK, against
// the shared fake API (testing/fake-touchque-api.mjs): an enrollment token the
// app spends once, replace for a second phone, the devices, the settings, and
// the push a MOBILE_PUSH webhook becomes.
import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import { spawn, type ChildProcess } from 'node:child_process';
import { resolve } from 'node:path';
import { Touchque, TouchqueAPIError, TouchqueConfigError, isMobilePushExpired, mobilePushFromWebhook } from '../index';

describe('Mobile SDK against the fake API', () => {
  let fake: ChildProcess;
  let base = '';
  let tq: Touchque;
  beforeAll(async () => {
    fake = spawn(process.execPath, [resolve(__dirname, '../../testing/fake-touchque-api.mjs')], { stdio: ['ignore', 'pipe', 'inherit'] });
    const port = await new Promise<number>((res, rej) => {
      fake.once('error', rej);
      fake.stdout!.once('data', (chunk) => res(JSON.parse(String(chunk).split('\n')[0]).port));
    });
    base = `http://127.0.0.1:${port}`;
    tq = new Touchque({ apiKey: 'tq_test_key', apiSecret: 'test_secret', baseUrl: base });
  });
  afterAll(() => { fake?.kill(); });
  // The app's side: what Touchque.enroll(token) does in the iOS / Android SDK.
  const app = (body: Record<string, unknown>) => fetch(`${base}/__test/mobile-enroll`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }).then((r) => r.json() as Promise<Record<string, string>>);

  test('a token is spent once; a second phone needs replace and revokes the first', async () => {
    const first = await tq.mobile.createEnrollment({ externalUsername: 'ada@shop.example' });
    expect(first.enrollmentToken).toMatch(/^tqe_[A-Za-z0-9_-]{43}$/);
    const device = await app({ enrollmentToken: first.enrollmentToken, platform: 'android' });
    expect((await app({ enrollmentToken: first.enrollmentToken })).code).toBe('enrollment_used');

    const again = await tq.mobile.createEnrollment({ externalUsername: 'ada@shop.example' }).catch((e) => e);
    expect(again).toBeInstanceOf(TouchqueAPIError);
    expect(again.code).toBe('already_enrolled');

    const second = await tq.mobile.createEnrollment({ externalUsername: 'ada@shop.example', replace: true, ttlSeconds: 300 });
    expect(second.replacesDeviceId).toBe(device.deviceId);
    await app({ enrollmentToken: second.enrollmentToken });
    const { devices } = await tq.mobile.listDevices({ externalUsername: 'ada@shop.example' });
    expect(devices.map((d) => d.platform)).toEqual(['ios']);
    expect((await tq.mobile.getDevice(device.deviceId)).revokedReason).toBe('replaced');
    expect((await tq.mobile.listDevices({ externalUsername: 'ada@shop.example', status: 'all' })).devices).toHaveLength(2);
    expect(await tq.mobile.testPush(devices[0].deviceId)).toEqual({ via: 'webhook', ok: true });
    expect(await tq.mobile.removeDevice(devices[0].deviceId)).toEqual({ removed: true, wasLinked: true });
    await expect(tq.mobile.testPush(devices[0].deviceId)).rejects.toMatchObject({ code: 'device_revoked' });
    await expect(tq.mobile.createEnrollment({ externalUsername: '' })).rejects.toBeInstanceOf(TouchqueConfigError);
  });

  test('settings change only what is given', async () => {
    expect((await tq.mobile.settings()).attestation).toBe('optional');
    const s = await tq.mobile.updateSettings({ androidPackages: ['com.shop.app'], androidCerts: { 'com.shop.app': ['AB:CD'] }, attestation: 'required' });
    expect(s.androidCerts).toEqual({ 'com.shop.app': ['AB:CD'] });
    expect(s).toMatchObject({ androidPackages: ['com.shop.app'], attestation: 'required', enrollTtlSeconds: 600 });
    expect(s.push).toMatchObject({ ios: 'webhook', android: 'webhook' });
  });

  test('your own push keys: Touchque sends that platform\'s push, and never shows the key back', async () => {
    const s = await tq.mobile.updateSettings({
      apns: { keyId: 'ABC123DEFG', teamId: 'TEAM123456', topic: 'com.shop.app', key: '-----BEGIN PRIVATE KEY-----…' },
      fcm: { serviceAccount: { project_id: 'shop', client_email: 'push@shop.iam.gserviceaccount.com', private_key: '…' } },
    });
    expect(s.push).toEqual({
      ios: 'touchque', android: 'touchque',
      apns: { keyId: 'ABC123DEFG', teamId: 'TEAM123456', topic: 'com.shop.app', production: false },
      fcm: { projectId: 'shop', clientEmail: 'push@shop.iam.gserviceaccount.com' },
    });
    expect((await tq.mobile.updateSettings({ apns: null })).push.ios).toBe('webhook');
  });
});

describe('mobilePushFromWebhook', () => {
  const event = {
    event: 'MOBILE_PUSH', externalUsername: 'ada@shop.example', deviceId: 'd1', platform: 'android', pushToken: 'fcm-token',
    kind: 'approval', requestId: 'r1', expiresAt: '2026-10-26T10:00:30.000Z',
    alert: { title: 'Change delivery address', body: 'Demo Shop is waiting for your approval.' },
    data: { touchque: '{"v":1,"k":"approval","did":"d1","rid":"r1"}' },
  };

  test('the APNs payload and FCM data carry the touchque key unchanged; other events are not pushes', () => {
    const push = mobilePushFromWebhook(event)!;
    expect(push).toMatchObject({ deviceId: 'd1', platform: 'android', pushToken: 'fcm-token', requestId: 'r1' });
    expect(push.fcmData).toEqual({ touchque: event.data.touchque });
    expect(push.apns).toEqual({ aps: { alert: event.alert, sound: 'default', 'interruption-level': 'time-sensitive' }, touchque: event.data.touchque });
    expect(mobilePushFromWebhook({ ...event, event: 'DEVICE_LINKED' })).toBeNull();
    expect(isMobilePushExpired(push, new Date('2026-10-26T10:01:00Z'))).toBe(true);
    expect(isMobilePushExpired(push, new Date('2026-10-26T10:00:00Z'))).toBe(false);
  });
});
