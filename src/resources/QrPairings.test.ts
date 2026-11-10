// QR pairing in the Node SDK, against the shared fake API
// (testing/fake-touchque-api.mjs): register, the QR's text and hash, the
// phone's scan, a request for the phone that scanned, and refusals.
import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import { spawn, type ChildProcess } from 'node:child_process';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { TouchQue, TouchQueConfigError, qrPairingUri } from '../index';

const THUMB = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';

describe('QR pairing against the fake API', () => {
  let fake: ChildProcess;
  let base = '';
  let tq: TouchQue;
  const control = (p: string, body: object) => fetch(`${base}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }).then((r) => r.json());
  beforeAll(async () => {
    fake = spawn(process.execPath, [resolve(__dirname, '../../testing/fake-touchque-api.mjs')], { stdio: ['ignore', 'pipe', 'inherit'] });
    const port = await new Promise<number>((res, rej) => {
      fake.once('error', rej);
      fake.stdout!.once('data', (chunk) => res(JSON.parse(String(chunk).split('\n')[0]).port));
    });
    base = `http://127.0.0.1:${port}`;
    tq = new TouchQue({ apiKey: 'tq_test_key', apiSecret: 'test_secret', baseUrl: base });
    await control('/__test/link', { user: 'ayse@acme.com' });
  });
  afterAll(() => { fake?.kill(); });

  test('create, scan, then ask the phone that scanned, once', async () => {
    const p = await tq.qrPairings.create({ keyThumbprint: THUMB, clientIp: '203.0.113.7', userAgent: 'Mozilla/5.0', browser: 'Chrome 155', os: 'macOS 15' });
    expect(p.uri).toBe(qrPairingUri(p.pairingId, p.nonce, THUMB));
    expect(p.uri).toMatch(/^touchque:\/\/pair-browser\?v=1&p=[\w-]{22}&n=[\w-]{43}&k=[\w-]{43}$/);
    const stored = (await fetch(`${base}/__test/qr-pairings`).then((r) => r.json())).pop();
    expect(stored.nonceHash).toBe(createHash('sha256').update(p.nonce).digest('base64url'));
    expect(stored.nonceHash).not.toContain(p.nonce);
    expect((await tq.qrPairings.get(p.pairingId)).state).toBe('waiting');
    await expect(tq.login.request({ externalUsername: 'ayse@acme.com', type: 'LOGIN', qrPairing: p.pairingId })).rejects.toMatchObject({ code: 'pairing_not_confirmed' });

    await control('/__test/qr-scan', { id: p.pairingId, user: 'ayse@acme.com' });
    const seen = await tq.qrPairings.get(p.pairingId);
    expect(seen).toMatchObject({ state: 'confirmed', externalUsername: 'ayse@acme.com', proximity: { warnings: [] } });
    const req = await tq.login.request({ externalUsername: 'ayse@acme.com', type: 'LOGIN', qrPairing: p.pairingId });
    expect(req.requestId).toBeTruthy();
    expect((await tq.qrPairings.get(p.pairingId))).toMatchObject({ state: 'requested', requestId: req.requestId });
  });

  test('refuse after the scan; checks before the call', async () => {
    const p = await tq.qrPairings.create({ keyThumbprint: THUMB, ttlSeconds: 60 });
    await expect(tq.qrPairings.refuse(p.pairingId, { reason: 'policy', message: 'Not yet' })).rejects.toMatchObject({ status: 409, code: 'not_open' });
    await control('/__test/qr-scan', { id: p.pairingId, user: 'ayse@acme.com', confirm: false });
    const refused = await tq.qrPairings.refuse(p.pairingId, { reason: 'device_not_approved', message: 'Ask IT to approve this computer.', deviceCode: 'ABC-123' });
    expect(refused).toMatchObject({ state: 'refused', outcome: { reason: 'device_not_approved', message: 'Ask IT to approve this computer.', deviceCode: 'ABC-123' } });

    await expect(tq.qrPairings.create({ keyThumbprint: 'short' })).rejects.toBeInstanceOf(TouchQueConfigError);
    await expect(tq.qrPairings.create({ keyThumbprint: THUMB, ttlSeconds: 10 })).rejects.toBeInstanceOf(TouchQueConfigError);
    expect(() => tq.qrPairings.refuse(p.pairingId, { reason: 'nope' as never, message: 'x' })).toThrow(TouchQueConfigError);
    expect(() => tq.qrPairings.refuse(p.pairingId, { reason: 'other', message: ' ' })).toThrow(TouchQueConfigError);
  });
});
