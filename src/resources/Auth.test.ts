import { describe, test, expect, vi } from 'vitest';
import { Auth } from './Auth';
import type { HttpClient } from '../core/HttpClient';
import type { DevicePosture } from '../types';

function fakeHttp() {
  return { post: vi.fn(), get: vi.fn(), delete: vi.fn() } as unknown as HttpClient;
}

describe('Auth resource', () => {
  test('generateSecret() POSTs to /auth/generate-secret with externalUsername', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ secret: 's', expiresAt: 't', ttlMs: 60000, recoveryCodes: [], externalUsername: 'a@b.com' });
    const auth = new Auth(http);

    const result = await auth.generateSecret({ externalUsername: 'a@b.com' });

    expect(http.post).toHaveBeenCalledWith('/auth/generate-secret', { externalUsername: 'a@b.com' });
    expect(result.secret).toBe('s');
  });

  test('resetSecret() POSTs to /auth/secret/reset', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ secret: 'new', externalUsername: 'a@b.com' });
    const auth = new Auth(http);

    await auth.resetSecret({ externalUsername: 'a@b.com' });

    expect(http.post).toHaveBeenCalledWith('/auth/secret/reset', { externalUsername: 'a@b.com' });
  });

  test('validateSecret() POSTs to /auth/secret/validate with the secret code', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ valid: true });
    const auth = new Auth(http);

    const result = await auth.validateSecret({ secret: '123456' });

    expect(http.post).toHaveBeenCalledWith('/auth/secret/validate', { secret: '123456' });
    expect(result.valid).toBe(true);
  });

  test('getUser() GETs /users/:externalUsername with the username URL-encoded', async () => {
    const http = fakeHttp();
    (http.get as any).mockResolvedValue({ used: true, deviceId: 'dev_1' });
    const auth = new Auth(http);

    const result = await auth.getUser({ externalUsername: 'a b@company.com' });

    expect(http.get).toHaveBeenCalledWith('/users/a%20b%40company.com');
    expect(result).toEqual({ used: true, deviceId: 'dev_1' });
  });

  test('getUser() passes the linked phone\'s posture through as `device`', async () => {
    const http = fakeHttp();
    const device: DevicePosture = {
      platform: 'ios', model: 'iPhone15,3', osVersion: '18.1', securityPatch: null, appVersion: '1.2.0', screenLock: true,
      biometrics: 'face', jailbroken: false, compromised: false, hardwareKey: true, attestation: 'apple-appattest',
      signed: true, reportedAt: '2026-10-25T10:00:00.000Z', lastSeenAt: '2026-10-25T10:05:00.000Z',
      linkedAt: '2026-10-20T09:00:00.000Z', state: 'healthy', issues: [],
    };
    (http.get as any).mockResolvedValueOnce({ externalUsername: 'a@b.c', used: true, deviceId: 'dev_1', device });
    (http.get as any).mockResolvedValueOnce({ externalUsername: 'd@e.f', used: false, deviceId: null, device: null });
    const auth = new Auth(http);

    const linked = await auth.getUser({ externalUsername: 'a@b.c' });
    expect(linked.device).toEqual(device);
    expect(linked.device?.state).toBe('healthy');

    const pending = await auth.getUser({ externalUsername: 'd@e.f' });
    expect(pending.device).toBeNull();
  });
});
