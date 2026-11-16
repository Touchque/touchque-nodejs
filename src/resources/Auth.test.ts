import { describe, test, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Auth, parseSetupContext } from './Auth';
import { Login } from './Login';
import type { HttpClient } from '../core/HttpClient';
import type { DevicePosture, SetupContext, ValidateSecretResponse } from '../types';
import * as sdk from '../index';

function fakeHttp() {
  return { post: vi.fn(), get: vi.fn(), delete: vi.fn() } as unknown as HttpClient;
}

/** The shared 2FA setup-context cases (fixtures/setup-context.json): each a 200 validate answer, and `expected`. */
const SETUP = JSON.parse(readFileSync(resolve(__dirname, '../../fixtures/setup-context.json'), 'utf8')) as
  Record<'full' | 'allNull' | 'missing' | 'null' | 'wrongTypes' | 'extraFields', Record<string, unknown>> & { expected: Record<string, SetupContext | null> };
const CASES = ['full', 'allNull', 'missing', 'null', 'wrongTypes', 'extraFields'] as const;

/** The body `call` POSTs through a mocked HttpClient. */
async function bodyOf(call: (http: HttpClient) => Promise<unknown>): Promise<Record<string, unknown>> {
  const http = fakeHttp();
  (http.post as any).mockResolvedValue({});
  await call(http);
  return (http.post as any).mock.calls[0][1];
}
const browserFields = (body: Record<string, unknown>) =>
  Object.fromEntries(Object.entries(body).filter(([k]) => k === 'clientIp' || k === 'userAgent'));

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

describe('Auth resource — 2FA setup context: the browser asking for the QR', () => {
  const UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1';

  test('generateSecret() and resetSecret() send clientIp and userAgent next to externalUsername, as given', async () => {
    const options = { externalUsername: 'a@b.com', clientIp: '203.0.113.7', userAgent: UA };
    expect(await bodyOf((http) => new Auth(http).generateSecret(options))).toEqual(options);
    expect(await bodyOf((http) => new Auth(http).resetSecret(options))).toEqual(options);
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({});
    await new Auth(http).generateSecret(options);
    await new Auth(http).resetSecret(options);
    expect((http.post as any).mock.calls.map((c: unknown[]) => c[0])).toEqual(['/auth/generate-secret', '/auth/secret/reset']);
  });

  test('left out when not given or empty: the body is { externalUsername } alone', async () => {
    for (const extra of [{}, { clientIp: '', userAgent: '' }, { clientIp: undefined, userAgent: undefined }, { clientIp: null, userAgent: null }]) {
      const options = { externalUsername: 'a@b.com', ...extra } as unknown as sdk.GenerateSecretOptions;
      expect(await bodyOf((http) => new Auth(http).generateSecret(options))).toEqual({ externalUsername: 'a@b.com' });
      expect(await bodyOf((http) => new Auth(http).resetSecret(options))).toEqual({ externalUsername: 'a@b.com' });
    }
    expect(await bodyOf((http) => new Auth(http).generateSecret({ externalUsername: 'a@b.com', clientIp: '203.0.113.7' })))
      .toEqual({ externalUsername: 'a@b.com', clientIp: '203.0.113.7' });
    expect(await bodyOf((http) => new Auth(http).resetSecret({ externalUsername: 'a@b.com', userAgent: UA })))
      .toEqual({ externalUsername: 'a@b.com', userAgent: UA });
  });

  test('exactly the rule of a login request: the same values are sent, as given, or left out', async () => {
    // No trimming, no length cap, no check of the address: what login.request sends, generate and reset send.
    const values: unknown[] = [undefined, null, '', ' ', '  203.0.113.7 ', '::ffff:127.0.0.1', 'not an ip', 'x'.repeat(5000), 'Mozilla/5.0\r\nX: y', 0, 7];
    for (const clientIp of values) {
      for (const userAgent of [undefined, '', 'curl/8.4.0', UA]) {
        const browser = { clientIp, userAgent } as unknown as { clientIp?: string; userAgent?: string };
        const login = browserFields(await bodyOf((http) => new Login(http).request({ externalUsername: 'a@b.com', type: 'LOGIN', ...browser })));
        expect(browserFields(await bodyOf((http) => new Auth(http).generateSecret({ externalUsername: 'a@b.com', ...browser })))).toEqual(login);
        expect(browserFields(await bodyOf((http) => new Auth(http).resetSecret({ externalUsername: 'a@b.com', ...browser })))).toEqual(login);
      }
    }
  });

  test('validateSecret() reads setupContext as the shared fixture expects: full, all null, missing, null, wrong types, extra fields', async () => {
    for (const name of CASES) {
      const http = fakeHttp();
      (http.post as any).mockResolvedValue(structuredClone(SETUP[name]));
      const res = await new Auth(http).validateSecret({ secret: 'S' });
      expect(res.setupContext, name).toEqual(SETUP.expected[name]);
      // Everything else in the answer comes back as it came.
      const { setupContext: _sent, ...rest } = SETUP[name];
      const { setupContext: _read, ...same } = res;
      expect(same, name).toEqual(rest);
      expect(parseSetupContext(SETUP[name].setupContext), name).toEqual(SETUP.expected[name]);
    }
  });

  test('validateSecret() sets setupContext null when the answer has none (an older QR or server)', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ valid: true });
    const res: ValidateSecretResponse = await new Auth(http).validateSecret({ secret: '123456' });
    expect(res).toEqual({ valid: true, setupContext: null });
    expect('setupContext' in res).toBe(true);
  });

  test('wrong types become null field by field; a location or device that is not an object is null; unknown fields are dropped', () => {
    expect(parseSetupContext({})).toEqual({ ip: null, location: null, device: null, requestedAt: null, farFromPhone: null });
    expect(parseSetupContext({
      ip: ['203.0.113.7'], location: ['Berlin'], device: 'Safari on iOS', requestedAt: 1763285400000, farFromPhone: 1,
    })).toEqual({ ip: null, location: null, device: null, requestedAt: null, farFromPhone: null });
    expect(parseSetupContext({
      ip: { v4: '203.0.113.7' }, location: { city: 1, country: true, countryCode: ['DE'] }, device: { browser: null, os: 'iOS' },
      requestedAt: { at: 'now' }, farFromPhone: 'false',
    })).toEqual({
      ip: null, location: { city: null, country: null, countryCode: null }, device: { browser: null, os: 'iOS', model: null },
      requestedAt: null, farFromPhone: null,
    });
    expect(parseSetupContext({ ip: '', location: { city: '' }, device: {}, requestedAt: '', farFromPhone: false })).toEqual({
      ip: '', location: { city: '', country: null, countryCode: null }, device: { browser: null, os: null, model: null }, requestedAt: '', farFromPhone: false,
    });
    const extra = parseSetupContext({ ip: '203.0.113.7', asn: 7922, location: { city: 'Berlin', region: 'BE' }, device: { os: 'iOS', deviceType: 'phone' } });
    expect(Object.keys(extra!)).toEqual(['ip', 'location', 'device', 'requestedAt', 'farFromPhone']);
    expect(Object.keys(extra!.location!)).toEqual(['city', 'country', 'countryCode']);
    expect(Object.keys(extra!.device!)).toEqual(['browser', 'os', 'model']);
  });

  test('never throws: anything that is not an object is null', async () => {
    for (const raw of [undefined, null, 'x', '', 0, 1, true, false, [], [{ ip: '203.0.113.7' }], () => 1, Symbol('s'), 10n]) {
      expect(parseSetupContext(raw)).toBeNull();
      const http = fakeHttp();
      (http.post as any).mockResolvedValue({ valid: true, setupContext: raw });
      expect((await new Auth(http).validateSecret({ secret: 'S' })).setupContext).toBeNull();
    }
    expect(parseSetupContext(Object.create(null))).toEqual({ ip: null, location: null, device: null, requestedAt: null, farFromPhone: null });
    // An answer that is not a JSON object (never from the API) comes back as it came.
    for (const raw of ['ok', null, [1]]) {
      const http = fakeHttp();
      (http.post as any).mockResolvedValue(raw);
      expect(await new Auth(http).validateSecret({ secret: 'S' })).toEqual(raw);
    }
  });

  test('the types and parseSetupContext are exported from the package entry', () => {
    expect(sdk.parseSetupContext).toBe(parseSetupContext);
    const context: sdk.SetupContext = {
      ip: null, location: { city: null, country: null, countryCode: null } satisfies sdk.SetupLocation,
      device: { browser: null, os: null, model: null } satisfies sdk.SetupDevice, requestedAt: '2026-11-16T09:30:00.000Z', farFromPhone: null,
    };
    const answer: sdk.ValidateSecretResponse = { valid: true, setupContext: context };
    const reset: sdk.ResetSecretOptions = { externalUsername: 'a@b.com', clientIp: '203.0.113.7', userAgent: UA };
    expect([answer.setupContext, reset.clientIp]).toEqual([context, '203.0.113.7']);
  });
});
