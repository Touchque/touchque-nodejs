import { describe, test, expect, vi } from 'vitest';
import { Login } from './Login';
import { TouchQueRejectedError, TouchQueTimeoutError } from '../errors';
import type { HttpClient } from '../core/HttpClient';

function fakeHttp() {
  return { post: vi.fn(), get: vi.fn(), delete: vi.fn() } as unknown as HttpClient;
}

describe('Login resource', () => {
  test('request() POSTs required fields and omits unset optional fields', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ requestId: 'req_1', message: 'ok', expiresAt: 't' });
    const login = new Login(http);

    await login.request({ externalUsername: 'a@b.com', type: 'LOGIN' });

    expect(http.post).toHaveBeenCalledWith('/login/request', { externalUsername: 'a@b.com', type: 'LOGIN' });
  });

  test('request() includes optional fields only when provided', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ requestId: 'req_1', message: 'ok', expiresAt: 't' });
    const login = new Login(http);

    await login.request({ externalUsername: 'a@b.com', type: 'WITHDRAW', referenceId: 'txn_1', requireBiometric: true });

    expect(http.post).toHaveBeenCalledWith('/login/request', {
      externalUsername: 'a@b.com',
      type: 'WITHDRAW',
      referenceId: 'txn_1',
      requireBiometric: true,
    });
  });

  test('request() forwards transaction details for the approval screen', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ requestId: 'req_1', message: 'ok', expiresAt: 't' });
    const login = new Login(http);

    await login.request({
      externalUsername: 'a@b.com',
      type: 'WITHDRAW',
      clientIp: '203.0.113.7',
      userAgent: 'Mozilla/5.0',
      details: { Amount: '1,250.00 USD', Recipient: 'Jane Doe' },
    });

    expect(http.post).toHaveBeenCalledWith('/login/request', {
      externalUsername: 'a@b.com',
      type: 'WITHDRAW',
      clientIp: '203.0.113.7',
      userAgent: 'Mozilla/5.0',
      details: { Amount: '1,250.00 USD', Recipient: 'Jane Doe' },
    });
  });

  test('request() passes through telemetryToken when the integration has behavioral biometrics enabled', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ requestId: 'req_1', message: 'ok', expiresAt: 't', telemetryToken: 'tok_abc' });
    const login = new Login(http);

    const result = await login.request({ externalUsername: 'a@b.com', type: 'LOGIN' });

    expect(result.telemetryToken).toBe('tok_abc');
  });

  test('request() omits telemetryToken when the integration has not opted in', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ requestId: 'req_1', message: 'ok', expiresAt: 't' });
    const login = new Login(http);

    const result = await login.request({ externalUsername: 'a@b.com', type: 'LOGIN' });

    expect(result.telemetryToken).toBeUndefined();
  });

  test('status() GETs /login/status/:requestId', async () => {
    const http = fakeHttp();
    (http.get as any).mockResolvedValue({ status: 'PENDING' });
    const login = new Login(http);

    const result = await login.status('req_1');

    expect(http.get).toHaveBeenCalledWith('/login/status/req_1');
    expect(result.status).toBe('PENDING');
  });

  test('waitForApproval() resolves { approved: true } once status flips to CONFIRMED', async () => {
    const http = fakeHttp();
    (http.get as any).mockResolvedValueOnce({ status: 'PENDING' }).mockResolvedValueOnce({ status: 'CONFIRMED' });
    const login = new Login(http);

    const result = await login.waitForApproval({ requestId: 'req_1', pollInterval: 1 });

    expect(result).toEqual({ approved: true, status: 'CONFIRMED' });
  });

  test('waitForApproval() throws TouchQueRejectedError when status becomes REJECTED', async () => {
    const http = fakeHttp();
    (http.get as any).mockResolvedValue({ status: 'REJECTED' });
    const login = new Login(http);

    await expect(login.waitForApproval({ requestId: 'req_1', pollInterval: 1 })).rejects.toThrow(TouchQueRejectedError);
  });

  test('waitForApproval() throws TouchQueTimeoutError when the timeout elapses with no resolution', async () => {
    const http = fakeHttp();
    (http.get as any).mockResolvedValue({ status: 'PENDING' });
    const login = new Login(http);

    await expect(login.waitForApproval({ requestId: 'req_1', timeout: 5, pollInterval: 2 })).rejects.toThrow(
      TouchQueTimeoutError,
    );
  });

  test('verify() composes request() + waitForApproval() and surfaces the requestId/challengeCode', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ requestId: 'req_9', message: 'ok', expiresAt: 't', challengeCode: '42' });
    (http.get as any).mockResolvedValue({ status: 'CONFIRMED' });
    const login = new Login(http);

    const result = await login.verify({ externalUsername: 'a@b.com', type: 'LOGIN', pollInterval: 1 });

    expect(result).toEqual({ approved: true, status: 'CONFIRMED', requestId: 'req_9', challengeCode: '42' });
  });

  test('approveWithRecoveryCode() POSTs to /login/recovery', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ success: true, message: 'approved' });
    const login = new Login(http);

    const result = await login.approveWithRecoveryCode({ requestId: 'req_1', code: 'ABCD-1234' });

    expect(http.post).toHaveBeenCalledWith('/login/recovery', { requestId: 'req_1', code: 'ABCD-1234' });
    expect(result.success).toBe(true);
  });
});

describe('Login — phishing-resistant policy', () => {
  test('verify() throws TouchQuePasskeyRequiredError at once (no 30 s polling) when a passkey is required', async () => {
    const { TouchQuePasskeyRequiredError } = await import('../errors');
    const http = { post: vi.fn(async () => ({ requestId: 'req_p', message: 'Request sent', expiresAt: 't', requiresPasskey: true })), get: vi.fn() } as unknown as HttpClient;
    const login = new Login(http);
    const err = await login.verify({ externalUsername: 'a@b.com', type: 'WITHDRAW' }).catch((e) => e);
    expect(err).toBeInstanceOf(TouchQuePasskeyRequiredError);
    expect(err.requestId).toBe('req_p');
    expect((http as any).get).not.toHaveBeenCalled();
  });
});
