// src/core/HttpClient.ts
// The heart of the SDK — all HTTP communication with the TouchQue API.
// Every request is signed with HMAC-SHA256 (the developer never sees this).

import axios, { AxiosInstance, AxiosError } from 'axios';
import * as crypto from 'crypto';
import { TouchQueConfig } from '../types';
import { TouchQueAPIError, TouchQueConfigError, TouchQueNetworkError } from '../errors';

const TEN_MB = 10 * 1024 * 1024;

/** Allow plaintext http only for localhost / loopback (local development). */
function assertSafeBaseUrl(baseUrl: string): void {
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new TouchQueConfigError(`baseUrl is not a valid URL: ${baseUrl}`);
  }
  if (url.protocol === 'https:') return;
  if (url.protocol === 'http:') {
    const host = url.hostname.toLowerCase();
    if (host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]') return;
    throw new TouchQueConfigError(
      `Refusing to use a plaintext http:// baseUrl for "${url.hostname}". ` +
        `The API key and request signature would be sent in the clear — use https://.`,
    );
  }
  throw new TouchQueConfigError(`baseUrl must be http(s): ${baseUrl}`);
}

/** Deterministic query string: keys sorted, values URL-encoded, `?`-prefixed (or ''). */
function buildQuery(params?: Record<string, string | number | boolean>): string {
  if (!params) return '';
  const keys = Object.keys(params).filter((k) => params[k] !== undefined && params[k] !== null);
  if (keys.length === 0) return '';
  keys.sort();
  const parts = keys.map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(String(params[k]))}`);
  return `?${parts.join('&')}`;
}

export class HttpClient {
  private readonly client: AxiosInstance;
  private readonly apiKey: string;
  private readonly apiSecret: string;

  constructor(config: TouchQueConfig) {
    if (!config.apiKey || typeof config.apiKey !== 'string') {
      throw new TouchQueConfigError('apiKey is required and must be a string');
    }
    if (!config.apiSecret || typeof config.apiSecret !== 'string') {
      throw new TouchQueConfigError('apiSecret is required and must be a string');
    }
    if (!config.apiKey.startsWith('tq_')) {
      throw new TouchQueConfigError(
        'apiKey must start with "tq_". Did you accidentally swap apiKey and apiSecret?',
      );
    }

    this.apiKey = config.apiKey;
    this.apiSecret = config.apiSecret;

    const baseURL = config.baseUrl || 'https://api.touchque.com';
    assertSafeBaseUrl(baseURL);

    this.client = axios.create({
      baseURL,
      timeout: config.timeout || 10000,
      headers: { 'Content-Type': 'application/json' },
      // An API endpoint should never redirect; a redirect to another host
      // could leak the signed auth headers.
      maxRedirects: 0,
      // Cap the response/request size so a misbehaving or spoofed endpoint
      // can't exhaust memory.
      maxContentLength: TEN_MB,
      maxBodyLength: TEN_MB,
    });
  }

  /**
   * Canonical signature.
   * Format: HMAC(apiSecret, "METHOD:pathWithQuery:timestamp:nonce:bodyHash")
   *
   * `pathWithQuery` includes the sorted query string so GET/DELETE query
   * params are covered by the signature (older SDKs signed the path only;
   * the backend accepts either form).
   */
  private sign(method: string, pathWithQuery: string, body: string, timestamp: string, nonce: string): string {
    const bodyHash = crypto.createHash('sha256').update(body || '').digest('hex');
    const message = `${method.toUpperCase()}:${pathWithQuery}:${timestamp}:${nonce}:${bodyHash}`;
    return crypto.createHmac('sha256', this.apiSecret).update(message).digest('hex');
  }

  private generateNonce(): string {
    return crypto.randomBytes(16).toString('hex');
  }

  private authHeaders(method: string, pathWithQuery: string, body: string) {
    const timestamp = Date.now().toString();
    const nonce = this.generateNonce();
    return {
      'x-api-key': this.apiKey,
      'x-signature': this.sign(method, pathWithQuery, body, timestamp, nonce),
      'x-timestamp': timestamp,
      'x-nonce': nonce,
    };
  }

  async post<T>(path: string, body: Record<string, unknown> = {}): Promise<T> {
    const bodyStr = JSON.stringify(body);
    try {
      const response = await this.client.post<T>(path, bodyStr, {
        headers: this.authHeaders('POST', path, bodyStr),
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async get<T>(path: string, params?: Record<string, string | number | boolean>): Promise<T> {
    const query = buildQuery(params);
    try {
      // Send the pre-built query string as part of the path (not via axios
      // `params`) so the bytes on the wire match what we signed.
      const response = await this.client.get<T>(path + query, {
        headers: this.authHeaders('GET', path + query, ''),
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async delete<T>(path: string): Promise<T> {
    try {
      const response = await this.client.delete<T>(path, {
        headers: this.authHeaders('DELETE', path, ''),
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  private handleError(error: unknown): TouchQueAPIError | TouchQueNetworkError {
    if (axios.isAxiosError(error)) {
      const axiosErr = error as AxiosError;
      if (!axiosErr.response) {
        // No HTTP response was ever received — connection refused, DNS
        // failure, client-side timeout, etc. Previously this fell through
        // to `status: 500` below and was indistinguishable from TouchQue
        // itself returning a real 500.
        return new TouchQueNetworkError(axiosErr.message, axiosErr.code);
      }
      const status = axiosErr.response.status;
      const data = (axiosErr.response.data as Record<string, unknown>) || {};
      return new TouchQueAPIError(status, {
        error: data.error as string | undefined,
        message: data.message as string | undefined,
        code: data.code as string | undefined,
        reason: typeof data.reason === 'string' ? data.reason : undefined,
        attemptsLeft: typeof data.attemptsLeft === 'number' ? data.attemptsLeft : undefined,
        retryAfter: typeof data.retryAfter === 'number'
          ? data.retryAfter
          : Number(axiosErr.response.headers?.['retry-after']) || undefined,
      });
    }
    return new TouchQueAPIError(500, {
      message: error instanceof Error ? error.message : 'Unknown error',
    });
  }
}
