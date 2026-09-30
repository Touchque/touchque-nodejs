import { describe, test, expect, vi } from 'vitest';
import { Offline } from './Offline';
import { TouchQueAPIError } from '../errors';
import type { HttpClient } from '../core/HttpClient';

function fakeHttp() {
  return { post: vi.fn(), get: vi.fn(), delete: vi.fn() } as unknown as HttpClient;
}

describe('Offline resource', () => {
  test('challenge() POSTs required fields, forwards optional ones, omits unset ones', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ challengeId: 'c1', qr: 'TQ1.x.y', qrDataUrl: 'data:image/png;base64,z', expiresAt: 't', expiresInSeconds: 120, totpAvailable: false });
    const offline = new Offline(http);

    await offline.challenge({ externalUsername: 'a@b.com', type: 'LOGIN' });
    expect(http.post).toHaveBeenCalledWith('/offline/challenge', { externalUsername: 'a@b.com', type: 'LOGIN' });

    await offline.challenge({
      externalUsername: 'a@b.com', type: 'WITHDRAW', clientIp: '203.0.113.7', userAgent: 'Mozilla/5.0',
      details: { Amount: '5' }, ttlSeconds: 60, includeQrImage: false,
    });
    expect(http.post).toHaveBeenLastCalledWith('/offline/challenge', {
      externalUsername: 'a@b.com', type: 'WITHDRAW', clientIp: '203.0.113.7', userAgent: 'Mozilla/5.0',
      details: { Amount: '5' }, ttlSeconds: 60, includeQrImage: false,
    });
  });

  test('challenge() links the QR to its push and asks for number matching; the number comes back', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ challengeId: 'c1', qr: 'TQ2.x', qrDataUrl: null, expiresAt: 't', expiresInSeconds: 120, totpAvailable: false, challengeCode: '47' });
    const offline = new Offline(http);
    const ch = await offline.challenge({ externalUsername: 'a@b.com', type: 'LOGIN', requestId: 'req-1', requireNumberMatch: true });
    expect(http.post).toHaveBeenCalledWith('/offline/challenge', { externalUsername: 'a@b.com', type: 'LOGIN', requestId: 'req-1', requireNumberMatch: true });
    expect(ch.challengeCode).toBe('47');
  });

  test('verifyTotp() forwards requestId; a rejected request comes back as a not-approved result', async () => {
    const http = fakeHttp();
    const offline = new Offline(http);
    (http.post as any).mockRejectedValueOnce(new TouchQueAPIError(410, { approved: false, reason: 'request_rejected' } as any));
    const r = await offline.verifyTotp({ externalUsername: 'a@b.com', code: 'ABCDEFG', requestId: 'req-1' });
    expect((http.post as any).mock.calls[0][1]).toMatchObject({ requestId: 'req-1' });
    expect(r).toEqual({ approved: false, reason: 'request_rejected', attemptsLeft: undefined });
  });

  test('verify() resolves { approved: true } on success', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ approved: true, challengeId: 'c1', externalUsername: 'a@b.com', type: 'LOGIN' });
    const r = await new Offline(http).verify({ challengeId: 'c1', code: 'ABC-DEFG' });
    expect(http.post).toHaveBeenCalledWith('/offline/verify', { challengeId: 'c1', code: 'ABC-DEFG' });
    expect(r).toMatchObject({ approved: true, externalUsername: 'a@b.com' });
  });

  test('verify() turns "not approved" responses into a result instead of throwing', async () => {
    const http = fakeHttp();
    const offline = new Offline(http);
    (http.post as any).mockRejectedValueOnce(new TouchQueAPIError(401, { approved: false, reason: 'invalid_code', attemptsLeft: 3 } as any));
    expect(await offline.verify({ challengeId: 'c1', code: 'AAAAAAA' })).toEqual({ approved: false, reason: 'invalid_code', attemptsLeft: 3 });
    (http.post as any).mockRejectedValueOnce(new TouchQueAPIError(410, { approved: false, reason: 'expired' } as any));
    expect((await offline.verify({ challengeId: 'c1', code: 'AAAAAAA' })).reason).toBe('expired');
    (http.post as any).mockRejectedValueOnce(new TouchQueAPIError(429, { approved: false, reason: 'too_many_failures' } as any));
    expect((await offline.verify({ challengeId: 'c1', code: 'AAAAAAA' })).approved).toBe(false);
  });

  test('verify() still throws for real failures (5xx, network, bad request)', async () => {
    const http = fakeHttp();
    const offline = new Offline(http);
    (http.post as any).mockRejectedValueOnce(new TouchQueAPIError(500, { error: 'boom' }));
    await expect(offline.verify({ challengeId: 'c1', code: 'AAAAAAA' })).rejects.toBeInstanceOf(TouchQueAPIError);
    (http.post as any).mockRejectedValueOnce(new TouchQueAPIError(400, { error: 'challengeId is required' }));
    await expect(offline.verify({ challengeId: '', code: 'AAAAAAA' })).rejects.toBeInstanceOf(TouchQueAPIError);
    (http.post as any).mockRejectedValueOnce(new Error('ECONNREFUSED'));
    await expect(offline.verify({ challengeId: 'c1', code: 'AAAAAAA' })).rejects.toThrow('ECONNREFUSED');
  });

  test('verifyTotp() POSTs to /offline/totp/verify with the action type and maps refusals', async () => {
    const http = fakeHttp();
    const offline = new Offline(http);
    (http.post as any).mockResolvedValueOnce({ approved: true, externalUsername: 'a@b.com' });
    await offline.verifyTotp({ externalUsername: 'a@b.com', code: 'ABCDEFG', type: 'LOGIN', clientIp: '1.2.3.4' });
    expect(http.post).toHaveBeenCalledWith('/offline/totp/verify', { externalUsername: 'a@b.com', code: 'ABCDEFG', type: 'LOGIN', clientIp: '1.2.3.4' });
    (http.post as any).mockRejectedValueOnce(new TouchQueAPIError(403, { error: 'offline_totp_not_allowed_for_critical' }));
    expect(await offline.verifyTotp({ externalUsername: 'a@b.com', code: 'ABCDEFG' })).toEqual({ approved: false, reason: 'offline_totp_not_allowed_for_critical', attemptsLeft: undefined });
  });
});
