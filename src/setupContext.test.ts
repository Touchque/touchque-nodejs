// 2FA setup context end to end, against the shared fake API (testing/fake-touchque-api.mjs):
// the browser named with a first-time QR (by hand, by touchqueRelay's POST /enroll/start, by the
// guard) is what validateSecret, the phone after scanning, shows. It is never in the QR.
import { describe, test, expect, beforeAll, beforeEach, afterAll } from 'vitest';
import { spawn, type ChildProcess } from 'node:child_process';
import { resolve } from 'node:path';
import { Touchque, touchqueRelay, runGuard, ipFromVercel } from './index';

const IPHONE = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1';
const FIREFOX = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0';
const BERLIN = { city: 'Berlin', country: 'Germany', countryCode: 'DE' };
const NEW_YORK = { city: 'New York', country: 'United States', countryCode: 'US' };

let fake: ChildProcess;
let base = '';
let tq: Touchque;

const control = (path: string, body: Record<string, unknown> = {}) =>
  fetch(`${base}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
/** What the fake API was sent, oldest first. */
const calls = async () => (await (await fetch(`${base}/__test/calls`)).json()) as Array<{ method: string; path: string; body: Record<string, unknown> }>;
const sentTo = async (path: string) => (await calls()).filter((c) => c.path === path).map((c) => c.body);

beforeAll(async () => {
  fake = spawn(process.execPath, [resolve(__dirname, '../testing/fake-touchque-api.mjs')], { stdio: ['ignore', 'pipe', 'inherit'] });
  const port = await new Promise<number>((res, rej) => {
    fake.once('error', rej);
    fake.stdout!.once('data', (chunk) => res(JSON.parse(String(chunk).split('\n')[0]).port));
  });
  base = `http://127.0.0.1:${port}`;
  tq = new Touchque({ apiKey: 'tq_test_key', apiSecret: 'test_secret', baseUrl: base });
});
afterAll(() => { fake?.kill(); });
beforeEach(async () => { await control('/__test/reset'); });

describe('2FA setup context against the shared fake API', () => {
  test('generateSecret with the browser: validateSecret shows where the QR was asked for', async () => {
    const qr = await tq.auth.generateSecret({ externalUsername: 'new@acme.com', clientIp: '203.0.113.7', userAgent: IPHONE });
    expect(await sentTo('/auth/generate-secret')).toEqual([{ externalUsername: 'new@acme.com', clientIp: '203.0.113.7', userAgent: IPHONE }]);
    const res = await tq.auth.validateSecret({ secret: qr.secret });
    expect(res).toMatchObject({ valid: true, externalUsername: 'new@acme.com', integrationId: 'int-1', integration: { companyName: 'Fake workspace' } });
    expect(res.setupContext).toEqual({
      ip: '203.0.113.7', location: BERLIN, device: { browser: 'Safari', os: 'iOS', model: 'iPhone' }, requestedAt: expect.any(String), farFromPhone: null,
    });
    const at = Date.parse(res.setupContext!.requestedAt!);
    expect(at).toBeLessThanOrEqual(Date.now());
    expect(at).toBeGreaterThan(Date.now() - 60_000);
  });

  test('resetSecret sends the browser too; the QR it replaced is no longer found', async () => {
    const first = await tq.auth.generateSecret({ externalUsername: 'new@acme.com', clientIp: '203.0.113.7', userAgent: IPHONE });
    const reset = await tq.auth.resetSecret({ externalUsername: 'new@acme.com', clientIp: '198.51.100.23', userAgent: FIREFOX });
    expect(await sentTo('/auth/secret/reset')).toEqual([{ externalUsername: 'new@acme.com', clientIp: '198.51.100.23', userAgent: FIREFOX }]);
    expect((await tq.auth.validateSecret({ secret: reset.secret })).valid).toBe(true);
    expect(reset.secret).not.toBe(first.secret);
    await expect(tq.auth.validateSecret({ secret: first.secret })).rejects.toMatchObject({ name: 'TouchqueAPIError', status: 404, data: { reason: 'not_found' } });
  });

  test('no browser named, or a server that answers none: setupContext null', async () => {
    const plain = await tq.auth.generateSecret({ externalUsername: 'plain@acme.com', clientIp: '', userAgent: '' });
    expect(await sentTo('/auth/generate-secret')).toEqual([{ externalUsername: 'plain@acme.com' }]);
    const res = await tq.auth.validateSecret({ secret: plain.secret });
    expect(res).toMatchObject({ valid: true, setupContext: null });

    await control('/__test/reset');
    await control('/__test/opts', { setupContextNull: true });
    const qr = await tq.auth.generateSecret({ externalUsername: 'new@acme.com', clientIp: '203.0.113.7', userAgent: IPHONE });
    expect((await tq.auth.validateSecret({ secret: qr.secret })).setupContext).toBeNull();
  });

  test('touchqueRelay: POST /enroll/start names the browser of the request, read as for POST /login', async () => {
    const relay = touchqueRelay(tq, { getUserId: () => 'new@acme.com', ip: ipFromVercel, rateLimit: false });
    const res = await relay(new Request('http://app.test/touchque/enroll/start', {
      method: 'POST', headers: { 'X-Real-IP': '198.51.100.23', 'X-Forwarded-For': '203.0.113.7, 198.51.100.23', 'User-Agent': FIREFOX },
    }));
    expect(res.status).toBe(200);
    const { secret } = (await res.json()) as { secret: string };
    expect((await tq.auth.validateSecret({ secret })).setupContext).toMatchObject({
      ip: '198.51.100.23', location: NEW_YORK, device: { browser: 'Firefox', os: 'Windows', model: null }, farFromPhone: null,
    });
  });

  test('the guard: a user with no phone gets a QR that names the browser of the request', async () => {
    const result = await runGuard(tq, { user: 'new@acme.com', action: 'LOGIN', ip: '203.0.113.7', userAgent: IPHONE });
    expect(result.body?.touchque.state).toBe('enroll');
    expect(await sentTo('/login/request')).toMatchObject([{ externalUsername: 'new@acme.com', clientIp: '203.0.113.7', userAgent: IPHONE }]);
    expect(await sentTo('/auth/generate-secret')).toEqual([{ externalUsername: 'new@acme.com', clientIp: '203.0.113.7', userAgent: IPHONE }]);
    // The page gets the QR image only; the fake API's first-time secret is always 'S'.
    expect((await tq.auth.validateSecret({ secret: 'S' })).setupContext).toMatchObject({
      ip: '203.0.113.7', location: BERLIN, device: { browser: 'Safari', os: 'iOS', model: 'iPhone' },
    });
  });
});
