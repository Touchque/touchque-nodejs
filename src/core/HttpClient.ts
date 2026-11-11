// src/core/HttpClient.ts
// The heart of the SDK — all HTTP communication with the Touchque API.
// Every request is signed with HMAC-SHA256 (the developer never sees this).

import axios, { AxiosInstance, AxiosError } from 'axios';
import * as crypto from 'crypto';
import { TouchqueConfig } from '../types';
import { TouchqueAPIError, TouchqueConfigError, TouchqueNetworkError, apiError } from '../errors';

const TEN_MB = 10 * 1024 * 1024;

/** Allow plaintext http only for localhost / loopback (local development). */
function assertSafeBaseUrl(baseUrl: string): void {
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new TouchqueConfigError(`baseUrl is not a valid URL: ${baseUrl}`);
  }
  if (url.protocol === 'https:') return;
  if (url.protocol === 'http:') {
    const host = url.hostname.toLowerCase();
    if (host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]') return;
    throw new TouchqueConfigError(
      `Refusing to use a plaintext http:// baseUrl for "${url.hostname}". ` +
        `The API key and request signature would be sent in the clear — use https://.`,
    );
  }
  throw new TouchqueConfigError(`baseUrl must be http(s): ${baseUrl}`);
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

/** The SDK's own problems go here: the integrator's logger, `console` with `debug`, else nowhere. */
export interface SdkLog {
  warn(message: string): void;
  error(message: string): void;
}

const SILENT: SdkLog = { warn: () => {}, error: () => {} };

export function sdkLog(config: Pick<TouchqueConfig, 'logger' | 'debug'>): SdkLog {
  const target = config.logger ?? (config.debug ? console : null);
  if (!target) return SILENT;
  return {
    warn: (message) => { try { target.warn(message); } catch { /* a logger must never break a request */ } },
    error: (message) => { try { target.error(message); } catch { /* a logger must never break a request */ } },
  };
}

/** `Name (code): message` for a log line: never the error object, its request or its stack. */
export function describeError(err: unknown): string {
  if (!(err instanceof Error)) return typeof err === 'string' ? err : 'unknown error';
  const code = (err as { code?: unknown }).code;
  return `${err.name}${typeof code === 'string' && code ? ` (${code})` : ''}: ${err.message}`;
}

export class HttpClient {
  private readonly client: AxiosInstance;
  private readonly apiKey: string;
  private readonly apiSecret: string;
  /** Internal: where the SDK reports its own problems (silent by default). */
  readonly log: SdkLog;

  constructor(config: TouchqueConfig) {
    if (!config.apiKey || typeof config.apiKey !== 'string') {
      throw new TouchqueConfigError('apiKey is required and must be a string');
    }
    if (!config.apiSecret || typeof config.apiSecret !== 'string') {
      throw new TouchqueConfigError('apiSecret is required and must be a string');
    }
    if (!config.apiKey.startsWith('tq_')) {
      throw new TouchqueConfigError(
        'apiKey must start with "tq_". Did you accidentally swap apiKey and apiSecret?',
      );
    }

    this.apiKey = config.apiKey;
    this.apiSecret = config.apiSecret;
    this.log = sdkLog(config);
    // console.log(tq) / JSON.stringify(tq) must not show the key or the secret.
    Object.defineProperty(this, 'apiSecret', { enumerable: false });
    Object.defineProperty(this, 'apiKey', { enumerable: false });

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

  async put<T>(path: string, body: Record<string, unknown> = {}): Promise<T> {
    return this.send<T>('PUT', path, body);
  }

  async patch<T>(path: string, body: Record<string, unknown> = {}): Promise<T> {
    return this.send<T>('PATCH', path, body);
  }

  private async send<T>(method: 'PUT' | 'PATCH', path: string, body: Record<string, unknown>): Promise<T> {
    const bodyStr = JSON.stringify(body);
    try {
      const response = await this.client.request<T>({ method, url: path, data: bodyStr, headers: this.authHeaders(method, path, bodyStr) });
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

  private handleError(error: unknown): TouchqueAPIError | TouchqueNetworkError {
    if (axios.isAxiosError(error)) {
      const axiosErr = error as AxiosError;
      if (!axiosErr.response) {
        // No HTTP response was ever received — connection refused, DNS
        // failure, client-side timeout, etc. Previously this fell through
        // to `status: 500` below and was indistinguishable from Touchque
        // itself returning a real 500.
        return new TouchqueNetworkError(axiosErr.message, axiosErr.code);
      }
      const status = axiosErr.response.status;
      const data = (axiosErr.response.data as Record<string, unknown>) || {};
      return apiError(status, {
        error: data.error as string | undefined,
        message: data.message as string | undefined,
        code: data.code as string | undefined,
        reason: typeof data.reason === 'string' ? data.reason : undefined,
        attemptsLeft: typeof data.attemptsLeft === 'number' ? data.attemptsLeft : undefined,
        retryAfter: typeof data.retryAfter === 'number'
          ? data.retryAfter
          : Number(axiosErr.response.headers?.['retry-after']) || undefined,
        caseCode: typeof data.caseCode === 'string' ? data.caseCode : undefined,
        route: typeof data.route === 'string' ? data.route : undefined,
        feature: typeof data.feature === 'string' ? data.feature : undefined,
      });
    }
    return new TouchqueAPIError(500, {
      message: error instanceof Error ? error.message : 'Unknown error',
    });
  }
}
