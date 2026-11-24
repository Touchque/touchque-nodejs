import { describe, test, expect, vi } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { Offline, formatDeviceCode, normalizeDeviceCode, verifyDeviceCode } from './Offline';
import { TouchqueAPIError } from '../errors';
import type { HttpClient } from '../core/HttpClient';
import { devicePackCode, startFakeApi } from '../testing/fakeApi';

// Offline sign-in packs' shared vectors (fixtures/offline-device-vectors.json, made by the platform).
const deviceVectors = JSON.parse(readFileSync(resolve(__dirname, '../../fixtures/offline-device-vectors.json'), 'utf8'));

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

  test('challenge() asks for the compact QR and its terminal drawing; the answer says the format', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ challengeId: 'c1', qr: 'TQ3:X', qrFormat: 'compact', qrDataUrl: null, qrTerminal: '█▀█\n▀▀▀', expiresAt: 't', expiresInSeconds: 120, totpAvailable: false });
    const offline = new Offline(http);
    const ch = await offline.challenge({ externalUsername: 'a@b.com', type: 'LOGIN', includeQrImage: false, qrFormat: 'compact', includeQrTerminal: true });
    expect(http.post).toHaveBeenCalledWith('/offline/challenge', { externalUsername: 'a@b.com', type: 'LOGIN', includeQrImage: false, qrFormat: 'compact', includeQrTerminal: true });
    expect([ch.qr, ch.qrFormat, ch.qrTerminal]).toEqual(['TQ3:X', 'compact', '█▀█\n▀▀▀']);
    await offline.challenge({ externalUsername: 'a@b.com', type: 'LOGIN', qrFormat: 'standard', includeQrTerminal: false });
    expect(http.post).toHaveBeenLastCalledWith('/offline/challenge', { externalUsername: 'a@b.com', type: 'LOGIN', qrFormat: 'standard' });
  });

  test('challenge() against the fake API: the compact QR with qrTerminal, the standard QR by default', async () => {
    const api = await startFakeApi();
    try {
      const compact = await api.client.offline.challenge({ externalUsername: 'a@b.com', type: 'LOGIN', qrFormat: 'compact', includeQrTerminal: true });
      expect(api.calls[api.calls.length - 1].body).toEqual({ externalUsername: 'a@b.com', type: 'LOGIN', qrFormat: 'compact', includeQrTerminal: true });
      expect(compact.qr.startsWith('TQ3:')).toBe(true);
      expect(compact.qrFormat).toBe('compact');
      expect(compact.qrTerminal).toContain('\n');
      const standard = await api.client.offline.challenge({ externalUsername: 'a@b.com', type: 'LOGIN' });
      expect(api.calls[api.calls.length - 1].body).toEqual({ externalUsername: 'a@b.com', type: 'LOGIN' });
      expect([standard.qr, standard.qrFormat, standard.qrTerminal]).toEqual(['TQ2.x', 'standard', undefined]);
    } finally {
      await api.close();
    }
  });

  test('totpVerifiers() POSTs the users, the scope and the window, omits unset ones', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ stepSeconds: 30, fromStep: 10, steps: 2, notAfterStep: 11, scope: { id: 'acme', name: 'Acme' }, digestsPerStep: 1, kdf: { name: 'pbkdf2-sha256', iterations: 2000, length: 6 }, users: [] });
    const offline = new Offline(http);
    const scope = { id: 'acme', name: 'Acme' };
    await offline.totpVerifiers({ externalUsernames: ['a@b.com'], scope });
    expect(http.post).toHaveBeenCalledWith('/offline/totp/verifiers', { externalUsernames: ['a@b.com'], scope });
    const r = await offline.totpVerifiers({ externalUsernames: ['a@b.com'], scope, fromStep: 10, steps: 2 });
    expect(http.post).toHaveBeenLastCalledWith('/offline/totp/verifiers', { externalUsernames: ['a@b.com'], scope, fromStep: 10, steps: 2 });
    expect(r.notAfterStep).toBe(11);
    expect(r.digestsPerStep).toBe(1);
  });

  test('matchTotpVerifier() finds the step of a typed outage code (one digest a step), one step either side, offline', () => {
    const crypto = require('crypto');
    const salt = Buffer.alloc(16, 7);
    const h = (code: string, step: number) => crypto.pbkdf2Sync(code, Buffer.concat([salt, Buffer.from(`:${step}`)]), 10, 6, 'sha256');
    const from = 1000;
    const parts: Buffer[] = [];
    for (let s = from; s < from + 4; s++) parts.push(h(`AAAAAA${s - from + 2}`, s));
    const v = { stepSeconds: 30, fromStep: from, steps: 4, notAfterStep: from + 3, scope: { id: 'acme', name: 'Acme' }, digestsPerStep: 1, kdf: { name: 'pbkdf2-sha256' as const, iterations: 10, length: 6 }, users: [] };
    const user = { externalUsername: 'a@b.com', fromStep: from, salt: salt.toString('base64'), digests: Buffer.concat(parts).toString('base64') };
    const offline = new Offline(fakeHttp());
    const at = new Date((from + 1) * 30000 + 5000);
    expect(offline.matchTotpVerifier(v, user, 'aaa-aaa3', at)).toBe(from + 1);
    expect(offline.matchTotpVerifier(v, user, 'AAAAAA2', at)).toBe(from);
    expect(offline.matchTotpVerifier(v, user, 'AAAAAA4', at)).toBe(from + 2);
    expect(offline.matchTotpVerifier(v, user, 'AAAAAA5', at)).toBeNull(); // two steps ahead
    expect(offline.matchTotpVerifier(v, user, 'AAAAAA1', at)).toBeNull(); // 1 is not in the alphabet
    expect(offline.matchTotpVerifier(v, user, 'AAAAAA3', new Date((from + 9) * 30000))).toBeNull(); // past notAfterStep
  });

  test('matchTotpVerifier() still reads an answer without digestsPerStep (two digests a step)', () => {
    const crypto = require('crypto');
    const salt = Buffer.alloc(16, 7);
    const h = (code: string, step: number) => crypto.pbkdf2Sync(code, Buffer.concat([salt, Buffer.from(`:${step}`)]), 10, 4, 'sha256');
    const from = 1000;
    const parts: Buffer[] = [];
    for (let s = from; s < from + 4; s++) parts.push(h(`AAAAAA${s - from + 2}`, s), h(`BBBBBB${s - from + 2}`, s));
    const v = { stepSeconds: 30, fromStep: from, steps: 4, notAfterStep: from + 3, kdf: { name: 'pbkdf2-sha256' as const, iterations: 10, length: 4 }, users: [] };
    const user = { externalUsername: 'a@b.com', fromStep: from, salt: salt.toString('base64'), digests: Buffer.concat(parts).toString('base64') };
    const offline = new Offline(fakeHttp());
    const at = new Date((from + 1) * 30000 + 5000);
    expect(offline.matchTotpVerifier(v, user, 'aaa-aaa3', at)).toBe(from + 1);
    expect(offline.matchTotpVerifier(v, user, 'BBBBBB2', at)).toBe(from);
  });

  test('verifyTotp() forwards requestId; a rejected request comes back as a not-approved result', async () => {
    const http = fakeHttp();
    const offline = new Offline(http);
    (http.post as any).mockRejectedValueOnce(new TouchqueAPIError(410, { approved: false, reason: 'request_rejected' } as any));
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
    (http.post as any).mockRejectedValueOnce(new TouchqueAPIError(401, { approved: false, reason: 'invalid_code', attemptsLeft: 3 } as any));
    expect(await offline.verify({ challengeId: 'c1', code: 'AAAAAAA' })).toEqual({ approved: false, reason: 'invalid_code', attemptsLeft: 3 });
    (http.post as any).mockRejectedValueOnce(new TouchqueAPIError(410, { approved: false, reason: 'expired' } as any));
    expect((await offline.verify({ challengeId: 'c1', code: 'AAAAAAA' })).reason).toBe('expired');
    (http.post as any).mockRejectedValueOnce(new TouchqueAPIError(429, { approved: false, reason: 'too_many_failures' } as any));
    expect((await offline.verify({ challengeId: 'c1', code: 'AAAAAAA' })).approved).toBe(false);
  });

  test('verify() still throws for real failures (5xx, network, bad request)', async () => {
    const http = fakeHttp();
    const offline = new Offline(http);
    (http.post as any).mockRejectedValueOnce(new TouchqueAPIError(500, { error: 'boom' }));
    await expect(offline.verify({ challengeId: 'c1', code: 'AAAAAAA' })).rejects.toBeInstanceOf(TouchqueAPIError);
    (http.post as any).mockRejectedValueOnce(new TouchqueAPIError(400, { error: 'challengeId is required' }));
    await expect(offline.verify({ challengeId: '', code: 'AAAAAAA' })).rejects.toBeInstanceOf(TouchqueAPIError);
    (http.post as any).mockRejectedValueOnce(new Error('ECONNREFUSED'));
    await expect(offline.verify({ challengeId: 'c1', code: 'AAAAAAA' })).rejects.toThrow('ECONNREFUSED');
  });

  test('verifyTotp() POSTs to /offline/totp/verify with the action type and maps refusals', async () => {
    const http = fakeHttp();
    const offline = new Offline(http);
    (http.post as any).mockResolvedValueOnce({ approved: true, externalUsername: 'a@b.com' });
    await offline.verifyTotp({ externalUsername: 'a@b.com', code: 'ABCDEFG', type: 'LOGIN', clientIp: '1.2.3.4' });
    expect(http.post).toHaveBeenCalledWith('/offline/totp/verify', { externalUsername: 'a@b.com', code: 'ABCDEFG', type: 'LOGIN', clientIp: '1.2.3.4' });
    (http.post as any).mockRejectedValueOnce(new TouchqueAPIError(403, { error: 'offline_totp_not_allowed_for_critical' }));
    expect(await offline.verifyTotp({ externalUsername: 'a@b.com', code: 'ABCDEFG' })).toEqual({ approved: false, reason: 'offline_totp_not_allowed_for_critical', attemptsLeft: undefined });
  });
});

describe('Offline sign-in packs', () => {
  test('issueDevicePack() POSTs the person, the device and the account, and count / validDays only when set', async () => {
    const http = fakeHttp();
    const pack = { scope: { id: 'pc-1', name: 'LAPTOP-JANE', epoch: '0123456789abcdef' }, account: 'ACME\\jane', validUntil: '2026-11-26T10:00:00.000Z', codeLength: 10, kdf: { name: 'pbkdf2-sha256', iterations: 600000, length: 16 }, slots: [] };
    (http.post as any).mockResolvedValue(pack);
    const offline = new Offline(http);
    const scope = { id: 'pc-1', name: 'LAPTOP-JANE' };
    expect(await offline.issueDevicePack({ externalUsername: 'jane@acme.com', scope, account: 'ACME\\jane' })).toEqual(pack);
    expect(http.post).toHaveBeenCalledWith('/offline/device-packs', { externalUsername: 'jane@acme.com', scope, account: 'ACME\\jane' });
    await offline.issueDevicePack({ externalUsername: 'jane@acme.com', scope, account: 'ACME\\jane', count: 5, validDays: 7 });
    expect(http.post).toHaveBeenLastCalledWith('/offline/device-packs', { externalUsername: 'jane@acme.com', scope, account: 'ACME\\jane', count: 5, validDays: 7 });
  });

  test('revokeDeviceScope() and reportDevicePackUse() POST the scope id; a Date is sent as ISO 8601', async () => {
    const http = fakeHttp();
    const offline = new Offline(http);
    (http.post as any).mockResolvedValueOnce({ revoked: 2 });
    expect(await offline.revokeDeviceScope({ scopeId: 'pc-1' })).toEqual({ revoked: 2 });
    expect(http.post).toHaveBeenCalledWith('/offline/device-packs/revoke', { scopeId: 'pc-1' });
    (http.post as any).mockResolvedValueOnce({ revoked: 1 });
    await offline.revokeDeviceScope({ scopeId: 'pc-1', externalUsername: 'jane@acme.com', reason: 'lost' });
    expect(http.post).toHaveBeenLastCalledWith('/offline/device-packs/revoke', { scopeId: 'pc-1', externalUsername: 'jane@acme.com', reason: 'lost' });
    (http.post as any).mockResolvedValueOnce({ recorded: 2, ignored: 0 });
    const r = await offline.reportDevicePackUse({ scopeId: 'pc-1', externalUsername: 'jane@acme.com', used: [{ index: 7, at: new Date('2026-11-12T08:30:00Z') }, { index: 8, at: '2026-11-12T09:00:00.000Z' }] });
    expect(http.post).toHaveBeenLastCalledWith('/offline/device-packs/report', {
      scopeId: 'pc-1', externalUsername: 'jane@acme.com', used: [{ index: 7, at: '2026-11-12T08:30:00.000Z' }, { index: 8, at: '2026-11-12T09:00:00.000Z' }],
    });
    expect(r).toEqual({ recorded: 2, ignored: 0 });
  });

  test('normalizeDeviceCode() and formatDeviceCode() follow the shared vectors', () => {
    for (const { input, expected } of deviceVectors.normalize) expect(normalizeDeviceCode(input)).toBe(expected);
    expect(formatDeviceCode(deviceVectors.slotQr.expectedCode)).toBe(deviceVectors.slotQr.expectedFormatted);
    expect(formatDeviceCode(' 5kmy9 tpzaq\n')).toBe('5KMY9-TPZAQ');
    expect([normalizeDeviceCode(undefined), normalizeDeviceCode('5KMY9-TPZAQ1'), formatDeviceCode('5KMY9-TPZA')]).toEqual([null, null, null]);
    for (const code of deviceVectors.codes) expect(normalizeDeviceCode(code.expectedCode)).toBe(code.expectedCode);
  });

  test('verifyDeviceCode() checks the shared digest vector (600,000 iterations) with no network', async () => {
    const d = deviceVectors.digest;
    const slot = { index: d.index, salt: Buffer.from(d.saltHex, 'hex').toString('base64'), digest: Buffer.from(d.expectedDigestHex, 'hex').toString('base64') };
    expect(await verifyDeviceCode(d.kdf, slot, d.code)).toBe(true);
    expect(await verifyDeviceCode(d.kdf, slot, deviceVectors.slotQr.expectedFormatted.toLowerCase())).toBe(true);
    expect(await new Offline(fakeHttp()).verifyDeviceCode(d.kdf, slot, d.code)).toBe(true);
    expect(await verifyDeviceCode(d.kdf, slot, 'PDG4MSATZB')).toBe(false); // another slot's code
    expect(await verifyDeviceCode(d.kdf, { ...slot, index: d.index + 1 }, d.code)).toBe(false); // the index is in the salt
    expect(await verifyDeviceCode({ ...d.kdf, name: 'scrypt' }, slot, d.code)).toBe(false);
    expect(await verifyDeviceCode({ ...d.kdf, length: 32 }, slot, d.code)).toBe(false);
  });

  test('verifyDeviceCode() refuses a malformed code without computing the digest', async () => {
    // A billion iterations would take minutes: an answer in time means nothing was computed.
    const slow = { name: 'pbkdf2-sha256', iterations: 1_000_000_000, length: 16 };
    const slot = { index: 7, salt: Buffer.alloc(16).toString('base64'), digest: Buffer.alloc(16).toString('base64') };
    for (const typed of ['', '5KMY9TPZA', '5KMY9TPZAQ1', 'ABCDEFGHI0', 'ABCDEFGHIO', '5KMY9_TPZAQ']) {
      expect(await verifyDeviceCode(slow, slot, typed)).toBe(false);
    }
  });

  test('against the fake API: issue, check slot codes on the device, report, revoke', async () => {
    const api = await startFakeApi();
    try {
      api.linked.add('jane@acme.com');
      const scope = { id: 'pc-0f1e2d3c4b5a6978', name: 'LAPTOP-JANE' };
      const pack = await api.client.offline.issueDevicePack({ externalUsername: 'jane@acme.com', scope, account: 'ACME\\jane', count: 3 });
      expect(api.calls[api.calls.length - 1].body).toEqual({ externalUsername: 'jane@acme.com', scope, account: 'ACME\\jane', count: 3 });
      expect(pack.slots.map((s) => s.index)).toEqual([1, 2, 3]);
      expect([pack.scope.epoch, pack.codeLength, pack.kdf.iterations, pack.slots[0].qr]).toEqual(['0123456789abcdef', 10, 1000, 'TQ4:SLOT1']);
      expect(await verifyDeviceCode(pack.kdf, pack.slots[0], formatDeviceCode(devicePackCode(1))!.toLowerCase())).toBe(true);
      expect(await verifyDeviceCode(pack.kdf, pack.slots[0], devicePackCode(2))).toBe(false);
      expect(await verifyDeviceCode(pack.kdf, pack.slots[1], devicePackCode(2))).toBe(true);
      // The next pack continues the indexes.
      expect((await api.client.offline.issueDevicePack({ externalUsername: 'jane@acme.com', scope, account: 'ACME\\jane', count: 2 })).slots.map((s) => s.index)).toEqual([4, 5]);

      const report = await api.client.offline.reportDevicePackUse({ scopeId: scope.id, externalUsername: 'jane@acme.com', used: [{ index: 1, at: new Date() }, { index: 99, at: new Date() }] });
      expect(report).toEqual({ recorded: 1, ignored: 1 });
      expect(api.devicePacks.get(`jane@acme.com\n${scope.id}`)!.used.map((u) => u.index)).toEqual([1]);
      await expect(api.client.offline.reportDevicePackUse({ scopeId: 'pc-other', externalUsername: 'jane@acme.com', used: [{ index: 1, at: new Date() }] })).rejects.toMatchObject({ status: 404 });

      expect(await api.client.offline.revokeDeviceScope({ scopeId: scope.id, reason: 'lost' })).toEqual({ revoked: 1 });
      expect(api.calls[api.calls.length - 1].body).toEqual({ scopeId: scope.id, reason: 'lost' });
      await expect(api.client.offline.issueDevicePack({ externalUsername: 'jane@acme.com', scope, account: 'ACME\\jane' })).rejects.toMatchObject({ status: 409 });

      await expect(api.client.offline.issueDevicePack({ externalUsername: 'nobody@acme.com', scope, account: 'ACME\\nobody' })).rejects.toMatchObject({ status: 404 });
      api.opts.devicePacksDisabled = true;
      await expect(api.client.offline.issueDevicePack({ externalUsername: 'jane@acme.com', scope: { id: 'pc-2', name: 'KIOSK' }, account: 'kiosk' })).rejects.toMatchObject({ status: 403 });
    } finally {
      await api.close();
    }
  });
});
