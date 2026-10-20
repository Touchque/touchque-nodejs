import { describe, test, expect, vi } from 'vitest';
import { Recovery, isRecoveryOpen } from './Recovery';
import { TouchQueConfigError } from '../errors';
import type { HttpClient } from '../core/HttpClient';

function fakeHttp() {
  return { post: vi.fn(), get: vi.fn(), delete: vi.fn() } as unknown as HttpClient;
}

describe('Recovery resource', () => {
  test('vouchers() GETs and setVouchers() POSTs the list', async () => {
    const http = fakeHttp();
    (http.get as any).mockResolvedValue({ externalUsername: 'a@b.com', vouchers: [], updatedAt: null, probationUntil: null });
    (http.post as any).mockResolvedValue({ externalUsername: 'a@b.com', vouchers: [{ externalUsername: 'c@b.com', eligible: true }] });
    const r = new Recovery(http);
    await r.vouchers({ externalUsername: 'a@b.com' });
    expect(http.get).toHaveBeenCalledWith('/recovery/vouchers', { externalUsername: 'a@b.com' });
    const out = await r.setVouchers({ externalUsername: 'a@b.com', vouchers: ['c@b.com'] });
    expect(http.post).toHaveBeenCalledWith('/recovery/vouchers', { externalUsername: 'a@b.com', vouchers: ['c@b.com'] });
    expect(out.vouchers[0].eligible).toBe(true);
  });

  test('start() sends only the given fields; status(), list() and veto() address the recovery', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ recoveryId: 'r1', bindUri: 'touchque://recover?id=r1&code=c', status: 'AWAITING_DEVICE' });
    (http.get as any).mockResolvedValue({ recoveries: [{ recoveryId: 'r1', status: 'COOLING' }] });
    const r = new Recovery(http);
    await r.start({ externalUsername: 'a@b.com' });
    expect(http.post).toHaveBeenLastCalledWith('/recovery/start', { externalUsername: 'a@b.com' });
    await r.start({ externalUsername: 'a@b.com', clientIp: '203.0.113.7', userAgent: 'UA', displayName: 'Ada', fallbackVouchers: ['x@b.com'], required: 3, coolOffMinutes: 90, details: [{ label: 'L', value: 'V' }], noticeDetails: [{ label: 'N', value: 'O' }] });
    expect(http.post).toHaveBeenLastCalledWith('/recovery/start', {
      externalUsername: 'a@b.com', clientIp: '203.0.113.7', userAgent: 'UA', displayName: 'Ada', fallbackVouchers: ['x@b.com'], required: 3, coolOffMinutes: 90, details: [{ label: 'L', value: 'V' }], noticeDetails: [{ label: 'N', value: 'O' }],
    });
    await r.status('r/1');
    expect(http.get).toHaveBeenLastCalledWith('/recovery/r%2F1');
    expect(await r.list({ open: true })).toEqual([{ recoveryId: 'r1', status: 'COOLING' }]);
    expect(http.get).toHaveBeenLastCalledWith('/recovery', { open: 'true' });
    await r.veto('r1', { by: 'admin@b.com' });
    expect(http.post).toHaveBeenLastCalledWith('/recovery/r1/veto', { by: 'admin@b.com' });
  });

  test('missing arguments are clear errors before any request', async () => {
    const http = fakeHttp();
    const r = new Recovery(http);
    await expect(r.start({} as never)).rejects.toBeInstanceOf(TouchQueConfigError);
    await expect(r.setVouchers({ externalUsername: 'a@b.com' } as never)).rejects.toBeInstanceOf(TouchQueConfigError);
    await expect(r.status('')).rejects.toBeInstanceOf(TouchQueConfigError);
    await expect(r.list({})).rejects.toBeInstanceOf(TouchQueConfigError);
    expect(http.post).not.toHaveBeenCalled();
    expect(http.get).not.toHaveBeenCalled();
  });

  test('isRecoveryOpen', () => {
    expect(isRecoveryOpen({ status: 'COOLING' })).toBe(true);
    expect(isRecoveryOpen({ status: 'COMPLETED' })).toBe(false);
  });
});
