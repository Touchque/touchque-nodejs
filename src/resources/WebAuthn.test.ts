import { describe, test, expect, vi } from 'vitest';
import { WebAuthn } from './WebAuthn';
import type { HttpClient } from '../core/HttpClient';

function fakeHttp() {
  return { post: vi.fn(), get: vi.fn(), delete: vi.fn() } as unknown as HttpClient;
}

describe('WebAuthn resource', () => {
  test('registerOptions() POSTs externalUsername and omits discoverable by default', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ challenge: 'c' });
    const wa = new WebAuthn(http);

    await wa.registerOptions({ externalUsername: 'a@b.com' });

    expect(http.post).toHaveBeenCalledWith('/webauthn/register/options', { externalUsername: 'a@b.com' });
  });

  test('registerOptions() includes discoverable:true only when requested', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ challenge: 'c' });
    const wa = new WebAuthn(http);

    await wa.registerOptions({ externalUsername: 'a@b.com', discoverable: true });

    expect(http.post).toHaveBeenCalledWith('/webauthn/register/options', {
      externalUsername: 'a@b.com',
      discoverable: true,
    });
  });

  test('registerVerify() POSTs response and includes label only when provided', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ verified: true, credentialId: 'cred_1' });
    const wa = new WebAuthn(http);

    const result = await wa.registerVerify({ externalUsername: 'a@b.com', response: { id: 'x' }, label: 'MacBook' });

    expect(http.post).toHaveBeenCalledWith('/webauthn/register/verify', {
      externalUsername: 'a@b.com',
      response: { id: 'x' },
      label: 'MacBook',
    });
    expect(result.credentialId).toBe('cred_1');
  });

  test('registerVerify() omits label when not provided', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ verified: true, credentialId: 'cred_1' });
    const wa = new WebAuthn(http);

    await wa.registerVerify({ externalUsername: 'a@b.com', response: { id: 'x' } });

    expect(http.post).toHaveBeenCalledWith('/webauthn/register/verify', {
      externalUsername: 'a@b.com',
      response: { id: 'x' },
    });
  });

  test('authenticateOptions() POSTs the requestId to /webauthn/login/options', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ challenge: 'c' });
    const wa = new WebAuthn(http);

    await wa.authenticateOptions({ requestId: 'req_1' });

    expect(http.post).toHaveBeenCalledWith('/webauthn/login/options', { requestId: 'req_1' });
  });

  test('authenticateVerify() POSTs requestId + response to /webauthn/login/verify', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ success: true, message: 'ok' });
    const wa = new WebAuthn(http);

    const result = await wa.authenticateVerify({ requestId: 'req_1', response: { id: 'x' } });

    expect(http.post).toHaveBeenCalledWith('/webauthn/login/verify', { requestId: 'req_1', response: { id: 'x' } });
    expect(result.success).toBe(true);
  });

  test('primaryOptions() POSTs externalUsername to /webauthn/authenticate/primary/options', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ attemptId: 'att_1', options: { challenge: 'c' } });
    const wa = new WebAuthn(http);

    const result = await wa.primaryOptions({ externalUsername: 'a@b.com' });

    expect(http.post).toHaveBeenCalledWith('/webauthn/authenticate/primary/options', { externalUsername: 'a@b.com' });
    expect(result.attemptId).toBe('att_1');
    expect(result.options).toEqual({ challenge: 'c' });
  });

  test('primaryVerify() POSTs attemptId + response and surfaces a successful login', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ success: true, requestId: 'lr_1', externalUsername: 'a@b.com', riskScore: 0.4 });
    const wa = new WebAuthn(http);

    const result = await wa.primaryVerify({ attemptId: 'att_1', response: { id: 'x' } });

    expect(http.post).toHaveBeenCalledWith('/webauthn/authenticate/primary/verify', {
      attemptId: 'att_1',
      response: { id: 'x' },
    });
    expect(result).toEqual({ success: true, requestId: 'lr_1', externalUsername: 'a@b.com', riskScore: 0.4 });
  });

  test('primaryVerify() surfaces requiresStepUp when risk/policy demands a second factor', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ success: false, requiresStepUp: true, externalUsername: 'a@b.com', riskScore: 0.95 });
    const wa = new WebAuthn(http);

    const result = await wa.primaryVerify({ attemptId: 'att_1', response: { id: 'x' } });

    expect(result.success).toBe(false);
    expect(result.requiresStepUp).toBe(true);
  });

  test('listCredentials() GETs /webauthn/credentials with externalUsername as a query param', async () => {
    const http = fakeHttp();
    (http.get as any).mockResolvedValue({ credentials: [{ id: 'c1', credentialId: 'cred_1', deviceType: null, backedUp: false, label: null, createdAt: 't', lastUsedAt: null }] });
    const wa = new WebAuthn(http);

    const result = await wa.listCredentials({ externalUsername: 'a@b.com' });

    expect(http.get).toHaveBeenCalledWith('/webauthn/credentials', { externalUsername: 'a@b.com' });
    expect(result.credentials).toHaveLength(1);
  });

  test('deleteCredential() DELETEs /webauthn/credentials/:id with the id URL-encoded', async () => {
    const http = fakeHttp();
    (http.delete as any).mockResolvedValue({ deleted: true });
    const wa = new WebAuthn(http);

    const res = await wa.deleteCredential('cred/with space');

    expect(http.delete).toHaveBeenCalledWith('/webauthn/credentials/cred%2Fwith%20space');
    expect(res).toEqual({ deleted: true });
  });
});
