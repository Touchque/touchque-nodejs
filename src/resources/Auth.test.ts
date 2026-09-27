import { describe, test, expect, vi } from 'vitest';
import { Auth } from './Auth';
import type { HttpClient } from '../core/HttpClient';

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
});
