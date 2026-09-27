import { describe, test, expect } from 'vitest';
import {
  TouchQueError,
  TouchQueAPIError,
  TouchQueTimeoutError,
  TouchQueRejectedError,
  TouchQueWebhookSignatureError,
  TouchQueConfigError,
} from './errors';

describe('error classes', () => {
  test('TouchQueAPIError carries status/code/data and prefers message over error string', () => {
    const err = new TouchQueAPIError(401, { error: 'unauthorized', message: 'Invalid API key', code: 'AUTH_401' });
    expect(err).toBeInstanceOf(TouchQueError);
    expect(err.status).toBe(401);
    expect(err.code).toBe('AUTH_401');
    expect(err.message).toBe('Invalid API key');
  });

  test('TouchQueAPIError falls back to a generic message when no error/message field is present', () => {
    const err = new TouchQueAPIError(500, {});
    expect(err.message).toBe('TouchQue API Error: HTTP 500');
  });

  test('TouchQueTimeoutError carries the requestId and a human-readable seconds figure', () => {
    const err = new TouchQueTimeoutError('req_1', 30000);
    expect(err.requestId).toBe('req_1');
    expect(err.message).toContain('30s');
  });

  test('TouchQueRejectedError carries the requestId', () => {
    const err = new TouchQueRejectedError('req_1');
    expect(err.requestId).toBe('req_1');
  });

  test('TouchQueWebhookSignatureError and TouchQueConfigError construct without arguments/with a message', () => {
    expect(new TouchQueWebhookSignatureError()).toBeInstanceOf(TouchQueError);
    expect(new TouchQueConfigError('apiKey is required').message).toContain('apiKey is required');
  });

  test('every error subclass sets `name` to its own class name (useful for logging/instanceof-free checks)', () => {
    expect(new TouchQueAPIError(500, {}).name).toBe('TouchQueAPIError');
    expect(new TouchQueTimeoutError('r', 1).name).toBe('TouchQueTimeoutError');
    expect(new TouchQueRejectedError('r').name).toBe('TouchQueRejectedError');
    expect(new TouchQueWebhookSignatureError().name).toBe('TouchQueWebhookSignatureError');
    expect(new TouchQueConfigError('x').name).toBe('TouchQueConfigError');
  });
});
