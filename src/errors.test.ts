import { describe, test, expect } from 'vitest';
import {
  TouchqueError,
  TouchqueAPIError,
  TouchqueTimeoutError,
  TouchqueRejectedError,
  TouchqueWebhookSignatureError,
  TouchqueConfigError,
} from './errors';

describe('error classes', () => {
  test('TouchqueAPIError carries status/code/data and prefers message over error string', () => {
    const err = new TouchqueAPIError(401, { error: 'unauthorized', message: 'Invalid API key', code: 'AUTH_401' });
    expect(err).toBeInstanceOf(TouchqueError);
    expect(err.status).toBe(401);
    expect(err.code).toBe('AUTH_401');
    expect(err.message).toBe('Invalid API key');
  });

  test('TouchqueAPIError falls back to a generic message when no error/message field is present', () => {
    const err = new TouchqueAPIError(500, {});
    expect(err.message).toBe('Touchque API Error: HTTP 500');
  });

  test('TouchqueTimeoutError carries the requestId and a human-readable seconds figure', () => {
    const err = new TouchqueTimeoutError('req_1', 30000);
    expect(err.requestId).toBe('req_1');
    expect(err.message).toContain('30s');
  });

  test('TouchqueRejectedError carries the requestId', () => {
    const err = new TouchqueRejectedError('req_1');
    expect(err.requestId).toBe('req_1');
  });

  test('TouchqueWebhookSignatureError and TouchqueConfigError construct without arguments/with a message', () => {
    expect(new TouchqueWebhookSignatureError()).toBeInstanceOf(TouchqueError);
    expect(new TouchqueConfigError('apiKey is required').message).toContain('apiKey is required');
  });

  test('every error subclass sets `name` to its own class name (useful for logging/instanceof-free checks)', () => {
    expect(new TouchqueAPIError(500, {}).name).toBe('TouchqueAPIError');
    expect(new TouchqueTimeoutError('r', 1).name).toBe('TouchqueTimeoutError');
    expect(new TouchqueRejectedError('r').name).toBe('TouchqueRejectedError');
    expect(new TouchqueWebhookSignatureError().name).toBe('TouchqueWebhookSignatureError');
    expect(new TouchqueConfigError('x').name).toBe('TouchqueConfigError');
  });
});

describe('feature errors', () => {
  test('apiError picks the typed error for each feature code and keeps TouchqueAPIError for the rest', async () => {
    const { apiError, TouchqueFeatureError, TouchqueFeatureNotInPlanError, TouchqueFeatureReadOnlyError, TouchqueFeatureOffError } = await import('./errors');
    const notInPlan = apiError(403, { error: 'feature_not_in_plan', feature: 'device_risk', message: 'This feature is not part of your organization’s plan.' });
    expect(notInPlan).toBeInstanceOf(TouchqueFeatureNotInPlanError);
    expect(notInPlan).toBeInstanceOf(TouchqueFeatureError);
    expect(notInPlan).toBeInstanceOf(TouchqueAPIError);
    expect(notInPlan).toMatchObject({ status: 403, feature: 'device_risk', reason: 'not_in_plan', name: 'TouchqueFeatureNotInPlanError' });
    expect(apiError(403, { error: 'feature_read_only', feature: 'ai_agents' })).toMatchObject({ reason: 'read_only', feature: 'ai_agents' });
    expect(apiError(403, { error: 'feature_read_only' })).toBeInstanceOf(TouchqueFeatureReadOnlyError);
    expect(apiError(403, { error: 'feature_off', feature: 'ciam' })).toBeInstanceOf(TouchqueFeatureOffError);
    const plain = apiError(403, { error: 'forbidden' });
    expect(plain).toBeInstanceOf(TouchqueAPIError);
    expect(plain).not.toBeInstanceOf(TouchqueFeatureError);
  });
});
