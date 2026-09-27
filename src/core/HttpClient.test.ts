import { describe, test, expect, vi, beforeEach } from 'vitest';
import axios from 'axios';
import { HttpClient } from './HttpClient';
import { TouchQueAPIError, TouchQueConfigError, TouchQueNetworkError } from '../errors';

vi.mock('axios');

const VALID_CONFIG = { apiKey: 'tq_auth_test123', apiSecret: 'shh' };

describe('HttpClient — config validation', () => {
  test('throws TouchQueConfigError when apiKey is missing', () => {
    expect(() => new HttpClient({ apiSecret: 'shh' } as any)).toThrow(TouchQueConfigError);
  });

  test('throws TouchQueConfigError when apiSecret is missing', () => {
    expect(() => new HttpClient({ apiKey: 'tq_auth_test123' } as any)).toThrow(TouchQueConfigError);
  });

  test('throws TouchQueConfigError when apiKey does not start with "tq_"', () => {
    expect(() => new HttpClient({ apiKey: 'wrong_prefix', apiSecret: 'shh' })).toThrow(
      /must start with "tq_"/,
    );
  });

  test('accepts a valid config without throwing', () => {
    const mockAxiosInstance = { get: vi.fn(), post: vi.fn(), delete: vi.fn() };
    (axios.create as any) = vi.fn(() => mockAxiosInstance);
    expect(() => new HttpClient(VALID_CONFIG)).not.toThrow();
  });

  test('defaults baseURL to the real Authenticator API host when not overridden', () => {
    const createSpy = vi.fn(() => ({ get: vi.fn(), post: vi.fn(), delete: vi.fn() }));
    (axios.create as any) = createSpy;
    new HttpClient(VALID_CONFIG);
    expect(createSpy).toHaveBeenCalledWith(
      expect.objectContaining({ baseURL: 'https://api.touchque.com' }),
    );
  });

  test('honors a custom baseUrl override', () => {
    const createSpy = vi.fn(() => ({ get: vi.fn(), post: vi.fn(), delete: vi.fn() }));
    (axios.create as any) = createSpy;
    new HttpClient({ ...VALID_CONFIG, baseUrl: 'http://localhost:9999' });
    expect(createSpy).toHaveBeenCalledWith(expect.objectContaining({ baseURL: 'http://localhost:9999' }));
  });

  test('allows plaintext http only for localhost / loopback', () => {
    (axios.create as any) = vi.fn(() => ({ get: vi.fn(), post: vi.fn(), delete: vi.fn() }));
    expect(() => new HttpClient({ ...VALID_CONFIG, baseUrl: 'http://localhost:5001' })).not.toThrow();
    expect(() => new HttpClient({ ...VALID_CONFIG, baseUrl: 'http://127.0.0.1:5001' })).not.toThrow();
  });

  test('refuses a plaintext http:// baseUrl to a non-localhost host', () => {
    (axios.create as any) = vi.fn(() => ({ get: vi.fn(), post: vi.fn(), delete: vi.fn() }));
    expect(() => new HttpClient({ ...VALID_CONFIG, baseUrl: 'http://api.example.com' })).toThrow(
      TouchQueConfigError,
    );
    expect(() => new HttpClient({ ...VALID_CONFIG, baseUrl: 'http://10.0.0.5' })).toThrow(/https:\/\//);
  });

  test('throws on a non-URL baseUrl', () => {
    (axios.create as any) = vi.fn(() => ({ get: vi.fn(), post: vi.fn(), delete: vi.fn() }));
    expect(() => new HttpClient({ ...VALID_CONFIG, baseUrl: 'not a url' })).toThrow(TouchQueConfigError);
  });

  test('hardens the axios instance: no redirects, capped body size', () => {
    const createSpy = vi.fn(() => ({ get: vi.fn(), post: vi.fn(), delete: vi.fn() }));
    (axios.create as any) = createSpy;
    new HttpClient(VALID_CONFIG);
    expect(createSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        maxRedirects: 0,
        maxContentLength: 10 * 1024 * 1024,
        maxBodyLength: 10 * 1024 * 1024,
      }),
    );
  });
});

describe('HttpClient — signed requests', () => {
  let post: ReturnType<typeof vi.fn>;
  let get: ReturnType<typeof vi.fn>;
  let del: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    post = vi.fn().mockResolvedValue({ data: { ok: true } });
    get = vi.fn().mockResolvedValue({ data: { ok: true } });
    del = vi.fn().mockResolvedValue({ data: { ok: true } });
    (axios.create as any) = vi.fn(() => ({ post, get, delete: del }));
  });

  test('post() attaches x-api-key, x-signature, x-timestamp, x-nonce headers', async () => {
    const client = new HttpClient(VALID_CONFIG);
    await client.post('/auth/generate-secret', { externalUsername: 'a@b.com' });

    expect(post).toHaveBeenCalledTimes(1);
    const [, , options] = post.mock.calls[0];
    expect(options.headers['x-api-key']).toBe(VALID_CONFIG.apiKey);
    expect(typeof options.headers['x-signature']).toBe('string');
    expect(options.headers['x-signature']).toHaveLength(64); // hex sha256
    expect(typeof options.headers['x-timestamp']).toBe('string');
    expect(typeof options.headers['x-nonce']).toBe('string');
  });

  test('two consecutive post() calls produce different nonces/signatures (replay protection)', async () => {
    const client = new HttpClient(VALID_CONFIG);
    await client.post('/login/request', { a: 1 });
    await client.post('/login/request', { a: 1 });

    const sig1 = post.mock.calls[0][2].headers['x-signature'];
    const sig2 = post.mock.calls[1][2].headers['x-signature'];
    const nonce1 = post.mock.calls[0][2].headers['x-nonce'];
    const nonce2 = post.mock.calls[1][2].headers['x-nonce'];
    expect(nonce1).not.toBe(nonce2);
    expect(sig1).not.toBe(sig2);
  });

  test('get() signs an empty-body request', async () => {
    const client = new HttpClient(VALID_CONFIG);
    await client.get('/login/status/req_123');
    expect(get).toHaveBeenCalledTimes(1);
    const [, options] = get.mock.calls[0];
    expect(options.headers['x-signature']).toHaveLength(64);
  });

  test('get() folds query params (sorted) into the request path so they are covered by the signature', async () => {
    const client = new HttpClient(VALID_CONFIG);
    await client.get('/webauthn/credentials', { externalUsername: 'a b@x.com' });

    const [url] = get.mock.calls[0];
    // sorted, url-encoded, sent as part of the path (not via axios `params`)
    expect(url).toBe('/webauthn/credentials?externalUsername=a%20b%40x.com');
    // the signed message includes that exact path+query, so tampering with it
    // downstream would break the signature
    const sigWithQuery = get.mock.calls[0][1].headers['x-signature'];

    await client.get('/webauthn/credentials'); // no params
    const sigNoQuery = get.mock.calls[1][1].headers['x-signature'];
    expect(sigWithQuery).not.toBe(sigNoQuery);
    expect(get.mock.calls[1][0]).toBe('/webauthn/credentials');
  });

  test('delete() signs the request the same way', async () => {
    const client = new HttpClient(VALID_CONFIG);
    await client.delete('/auth/unlink');
    expect(del).toHaveBeenCalledTimes(1);
  });

  test('resolves with response.data (unwraps axios envelope)', async () => {
    post.mockResolvedValueOnce({ data: { secret: 'abc', expiresAt: '2030-01-01' } });
    const client = new HttpClient(VALID_CONFIG);
    const result = await client.post('/auth/generate-secret', {});
    expect(result).toEqual({ secret: 'abc', expiresAt: '2030-01-01' });
  });
});

describe('HttpClient — error handling', () => {
  test('wraps a non-2xx axios error into TouchQueAPIError with status + message', async () => {
    const axiosError = {
      isAxiosError: true,
      response: { status: 401, data: { error: 'unauthorized', message: 'Invalid API key', code: 'AUTH_401' } },
    };
    const post = vi.fn().mockRejectedValue(axiosError);
    (axios.create as any) = vi.fn(() => ({ post, get: vi.fn(), delete: vi.fn() }));
    (axios.isAxiosError as any) = vi.fn(() => true);

    const client = new HttpClient(VALID_CONFIG);
    await expect(client.post('/auth/generate-secret', {})).rejects.toThrow(TouchQueAPIError);

    try {
      await client.post('/auth/generate-secret', {});
    } catch (err) {
      expect(err).toBeInstanceOf(TouchQueAPIError);
      expect((err as TouchQueAPIError).status).toBe(401);
      expect((err as TouchQueAPIError).code).toBe('AUTH_401');
    }
  });

  test('keeps the offline-sign reason and attemptsLeft from a 401 body (so offline.verify can report them)', async () => {
    const axiosError = { isAxiosError: true, response: { status: 401, data: { approved: false, reason: 'invalid_code', attemptsLeft: 4 } } };
    const post = vi.fn().mockRejectedValue(axiosError);
    (axios.create as any) = vi.fn(() => ({ post, get: vi.fn(), delete: vi.fn() }));
    (axios.isAxiosError as any) = vi.fn(() => true);
    const client = new HttpClient(VALID_CONFIG);
    const err: any = await client.post('/offline/verify', {}).catch((e) => e);
    expect(err).toBeInstanceOf(TouchQueAPIError);
    expect(err.data).toMatchObject({ reason: 'invalid_code', attemptsLeft: 4 });
  });

  test('wraps a completely unknown (non-axios) error with a 500 fallback', async () => {
    const post = vi.fn().mockRejectedValue(new Error('socket hang up'));
    (axios.create as any) = vi.fn(() => ({ post, get: vi.fn(), delete: vi.fn() }));
    (axios.isAxiosError as any) = vi.fn(() => false);

    const client = new HttpClient(VALID_CONFIG);
    await expect(client.post('/auth/generate-secret', {})).rejects.toMatchObject({ status: 500 });
  });

  test('an axios error with no response (connection refused, DNS failure, timeout) becomes TouchQueNetworkError, not a fake 500', async () => {
    const axiosError = {
      isAxiosError: true,
      response: undefined,
      code: 'ECONNREFUSED',
      message: 'connect ECONNREFUSED 127.0.0.1:5001',
    };
    const post = vi.fn().mockRejectedValue(axiosError);
    (axios.create as any) = vi.fn(() => ({ post, get: vi.fn(), delete: vi.fn() }));
    (axios.isAxiosError as any) = vi.fn(() => true);

    const client = new HttpClient(VALID_CONFIG);
    await expect(client.post('/auth/generate-secret', {})).rejects.toThrow(TouchQueNetworkError);

    try {
      await client.post('/auth/generate-secret', {});
    } catch (err) {
      expect(err).toBeInstanceOf(TouchQueNetworkError);
      expect(err).not.toBeInstanceOf(TouchQueAPIError);
      expect((err as TouchQueNetworkError).code).toBe('ECONNREFUSED');
    }
  });
});

// ── Cross-language SDK contract fixtures (sdks/fixtures/signature-vectors.json) ──
// Generated by the backend from its own utils/canonicalSignature.js. Asserted
// here and in the go/php/python suites so every SDK signs identically to the
// server. Would have caught the GET-query-not-in-signature regression.
import signatureFixture from '../../fixtures/signature-vectors.json';

describe('HttpClient — SDK signature vectors', () => {
  for (const v of (signatureFixture as any).vectors) {
    test(v.description, () => {
      (axios.create as any) = vi.fn(() => ({ get: vi.fn(), post: vi.fn(), delete: vi.fn() }));
      const client: any = new HttpClient({ apiKey: 'tq_x', apiSecret: (signatureFixture as any).secret });
      const actual = client.sign(v.method, v.signed_path, v.body, v.timestamp, v.nonce);
      expect(actual).toBe(v.expected_signature);
    });
  }

  test('get() sends query params sorted + URL-encoded, folded into the request path', async () => {
    const withQuery = (signatureFixture as any).vectors.filter((v: any) => v.query);
    expect(withQuery.length).toBeGreaterThan(0);
    for (const v of withQuery) {
      const get = vi.fn().mockResolvedValue({ data: {} });
      (axios.create as any) = vi.fn(() => ({ get, post: vi.fn(), delete: vi.fn() }));
      const client = new HttpClient({ apiKey: 'tq_x', apiSecret: (signatureFixture as any).secret });
      await client.get(v.base_path, v.query);
      // the URL on the wire is the exact string the fixture signed
      expect(get.mock.calls[0][0]).toBe(v.signed_path);
    }
  });
});
