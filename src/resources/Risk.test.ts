import { describe, test, expect, vi } from 'vitest';
import { Risk } from './Risk';
import { TouchQueConfigError } from '../errors';
import type { HttpClient } from '../core/HttpClient';

function fakeHttp() {
  return { post: vi.fn(), get: vi.fn(), delete: vi.fn() } as unknown as HttpClient;
}

describe('Risk resource', () => {
  test('check() POSTs the user and omits unset optional fields', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ prompt: true, reasons: [], assurance: 'normal', silentMode: 'enforce' });
    await new Risk(http).check({ externalUsername: 'a@b.com' });
    expect(http.post).toHaveBeenCalledWith('/risk/check', { externalUsername: 'a@b.com' });
  });

  test('check() sends every given field, maxAgeSeconds 0 included', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ prompt: false, reasons: [{ code: 'known_browser', text: 't' }], assurance: 'high', silentMode: 'enforce' });
    const res = await new Risk(http).check({
      externalUsername: 'a@b.com', type: 'LOGIN', clientIp: '203.0.113.7', userAgent: 'UA', browserProof: 'eyJ2IjoxfQ', maxAgeSeconds: 0,
    });
    expect(http.post).toHaveBeenCalledWith('/risk/check', {
      externalUsername: 'a@b.com', type: 'LOGIN', clientIp: '203.0.113.7', userAgent: 'UA', browserProof: 'eyJ2IjoxfQ', maxAgeSeconds: 0,
    });
    expect(res).toEqual({ prompt: false, reasons: [{ code: 'known_browser', text: 't' }], assurance: 'high', silentMode: 'enforce' });
  });

  test('browsers() GETs with the user as a query parameter; forgetBrowsers() sends the thumbprint only when given', async () => {
    const http = fakeHttp();
    (http.get as any).mockResolvedValue({ browsers: [{ thumbprint: 'tp' }] });
    (http.post as any).mockResolvedValue({ forgotten: 2 });
    const risk = new Risk(http);
    expect((await risk.browsers({ externalUsername: 'a@b.com' })).browsers).toEqual([{ thumbprint: 'tp' }]);
    expect(http.get).toHaveBeenCalledWith('/risk/browsers', { externalUsername: 'a@b.com' });
    await risk.forgetBrowsers({ externalUsername: 'a@b.com' });
    expect(http.post).toHaveBeenLastCalledWith('/risk/browsers/forget', { externalUsername: 'a@b.com' });
    expect(await risk.forgetBrowsers({ externalUsername: 'a@b.com', thumbprint: 'tp' })).toEqual({ forgotten: 2 });
    expect(http.post).toHaveBeenLastCalledWith('/risk/browsers/forget', { externalUsername: 'a@b.com', thumbprint: 'tp' });
  });

  test('a missing user is a clear error before any request', async () => {
    const http = fakeHttp();
    const risk = new Risk(http);
    await expect(risk.check({} as never)).rejects.toBeInstanceOf(TouchQueConfigError);
    await expect(risk.browsers({} as never)).rejects.toBeInstanceOf(TouchQueConfigError);
    await expect(risk.forgetBrowsers({} as never)).rejects.toBeInstanceOf(TouchQueConfigError);
    expect(http.post).not.toHaveBeenCalled();
    expect(http.get).not.toHaveBeenCalled();
  });
});
