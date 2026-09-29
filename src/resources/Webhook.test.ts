import { describe, test, expect, vi, afterEach } from 'vitest';
import * as crypto from 'crypto';
import { Webhook, MemoryWebhookReplayCache } from './Webhook';
import { TouchQueWebhookSignatureError, TouchQueWebhookReplayError } from '../errors';

const SECRET = 'whsec_test';

// Reproduce exactly what the API server
// does: sign stableStringify(payload) (top-level keys sorted, no `signature`),
// then send { ...payload, signature } as the JSON body.
function serverWebhook(payload: Record<string, unknown>, secret = SECRET) {
  const sorted: Record<string, unknown> = {};
  for (const k of Object.keys(payload).sort()) sorted[k] = payload[k];
  const canonical = JSON.stringify(sorted);
  const signature = crypto.createHmac('sha256', secret).update(canonical).digest('hex');
  return { rawBody: JSON.stringify({ ...payload, signature }), signature };
}

function freshPayload(overrides: Record<string, unknown> = {}) {
  return {
    status: 'SUCCESS',
    action: 'LOGIN_CONFIRM',
    requestId: 'req_1',
    externalUsername: 'a@b.com',
    integrationId: 'int_1',
    deviceId: null,
    referenceId: null,
    timestamp: new Date().toISOString(),
    jti: 'jti_1',
    riskScore: 0,
    riskFactors: [],
    ...overrides,
  };
}

afterEach(() => vi.useRealTimers());

describe('Webhook.verify — matches the backend signing scheme', () => {
  test('accepts a genuine webhook and returns the payload (signature from the header)', () => {
    const webhook = new Webhook(SECRET);
    const { rawBody, signature } = serverWebhook(freshPayload());

    const result = webhook.verify({ rawBody, signature });

    expect(result.requestId).toBe('req_1');
    expect(result.status).toBe('SUCCESS');
  });

  test('accepts a genuine webhook using the `signature` field embedded in the body', () => {
    const webhook = new Webhook(SECRET);
    const { rawBody } = serverWebhook(freshPayload());

    // no `signature` argument — falls back to the in-body field
    const result = webhook.verify({ rawBody });

    expect(result.requestId).toBe('req_1');
  });

  test('rejects a tampered body (payload changed after signing)', () => {
    const webhook = new Webhook(SECRET);
    const { signature } = serverWebhook(freshPayload({ status: 'SUCCESS' }));
    const tampered = JSON.stringify({ ...freshPayload({ status: 'REJECTED' }), signature });

    expect(() => webhook.verify({ rawBody: tampered, signature })).toThrow(TouchQueWebhookSignatureError);
  });

  test('rejects a wrong secret', () => {
    const webhook = new Webhook(SECRET);
    const { rawBody, signature } = serverWebhook(freshPayload(), 'other_secret');
    expect(() => webhook.verify({ rawBody, signature })).toThrow(TouchQueWebhookSignatureError);
  });

  test('rejects a stale webhook (replay protection, default 5 min tolerance)', () => {
    const webhook = new Webhook(SECRET);
    const old = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    const { rawBody, signature } = serverWebhook(freshPayload({ timestamp: old }));

    expect(() => webhook.verify({ rawBody, signature })).toThrow(TouchQueWebhookSignatureError);
  });

  test('toleranceSeconds: 0 disables the freshness check', () => {
    const webhook = new Webhook(SECRET);
    const old = new Date(Date.now() - 60 * 60 * 1000).toISOString();
    const { rawBody, signature } = serverWebhook(freshPayload({ timestamp: old }));

    expect(webhook.verify({ rawBody, signature, toleranceSeconds: 0 }).jti).toBe('jti_1');
  });

  test('rejects missing / non-string rawBody', () => {
    const webhook = new Webhook(SECRET);
    expect(() => webhook.verify({ rawBody: '', signature: 'x' })).toThrow(TouchQueWebhookSignatureError);
    expect(() => webhook.verify({ rawBody: undefined as any, signature: 'x' })).toThrow(TouchQueWebhookSignatureError);
  });

  test('rejects when no signature is available anywhere', () => {
    const webhook = new Webhook(SECRET);
    const rawBody = JSON.stringify(freshPayload()); // no signature field, none passed
    expect(() => webhook.verify({ rawBody })).toThrow(TouchQueWebhookSignatureError);
  });

  test('rejects a non-JSON body without crashing', () => {
    const webhook = new Webhook(SECRET);
    expect(() => webhook.verify({ rawBody: 'not json', signature: 'x' })).toThrow(TouchQueWebhookSignatureError);
  });

  test('rejects a JSON array body', () => {
    const webhook = new Webhook(SECRET);
    expect(() => webhook.verify({ rawBody: '[1,2,3]', signature: 'x' })).toThrow(TouchQueWebhookSignatureError);
  });

  test('isValid() never throws', () => {
    const webhook = new Webhook(SECRET);
    const { rawBody, signature } = serverWebhook(freshPayload());
    expect(webhook.isValid({ rawBody, signature })).toBe(true);
    expect(webhook.isValid({ rawBody: 'garbage', signature: 'x' })).toBe(false);
  });

  // Regression lock: canonicalization sorts ONLY the top-level keys. Nested
  // objects (in `extra` / any custom field) and their key order, empty objects,
  // and precise numbers must pass through verbatim — matching the server's
  // stableStringify + JSON.stringify.
  test('preserves nested object key order, empty objects and precise numbers', () => {
    const webhook = new Webhook(SECRET);
    const { rawBody, signature } = serverWebhook(
      freshPayload({
        context: { z: 1, a: 2, inner: { y: true, x: false } },
        meta: {},
        ledgerBalance: 123456789.123456789,
        riskFactors: ['new_device', 'unusual_time_of_day'],
      }),
    );

    const result = webhook.verify({ rawBody, signature });

    expect(result.requestId).toBe('req_1');
    expect(result.context).toEqual({ z: 1, a: 2, inner: { y: true, x: false } });
  });
});

describe('Webhook.verify — replay protection (A12)', () => {
  test('a signed webhook without a timestamp is rejected, not waved through', () => {
    const webhook = new Webhook(SECRET);
    const { timestamp: _t, ...noTs } = freshPayload();
    const { rawBody, signature } = serverWebhook(noTs);
    expect(() => webhook.verify({ rawBody, signature })).toThrow(TouchQueWebhookSignatureError);
  });

  test('an unparseable timestamp is rejected', () => {
    const webhook = new Webhook(SECRET);
    const { rawBody, signature } = serverWebhook(freshPayload({ timestamp: 'not-a-date' }));
    expect(() => webhook.verify({ rawBody, signature })).toThrow(TouchQueWebhookSignatureError);
  });

  test('with a replay cache, the second delivery of the same jti throws TouchQueWebhookReplayError', () => {
    const webhook = new Webhook(SECRET);
    const replayCache = new MemoryWebhookReplayCache();
    const { rawBody, signature } = serverWebhook(freshPayload({ jti: 'jti_once' }));
    expect(webhook.verify({ rawBody, signature, replayCache }).jti).toBe('jti_once');
    let caught: unknown;
    try { webhook.verify({ rawBody, signature, replayCache }); } catch (e) { caught = e; }
    expect(caught).toBeInstanceOf(TouchQueWebhookReplayError);
    expect(caught).toBeInstanceOf(TouchQueWebhookSignatureError); // old catch blocks still reject it
    expect((caught as TouchQueWebhookReplayError).jti).toBe('jti_once');
  });

  test('a different jti passes; a missing jti is rejected when a cache is configured', () => {
    const webhook = new Webhook(SECRET);
    const replayCache = new MemoryWebhookReplayCache();
    const a = serverWebhook(freshPayload({ jti: 'a' }));
    const b = serverWebhook(freshPayload({ jti: 'b' }));
    webhook.verify({ ...a, replayCache });
    expect(() => webhook.verify({ ...b, replayCache })).not.toThrow();
    const { jti: _j, ...noJti } = freshPayload();
    expect(() => webhook.verify({ ...serverWebhook(noJti), replayCache })).toThrow(TouchQueWebhookSignatureError);
  });

  test('a forged webhook never poisons the cache', () => {
    const webhook = new Webhook(SECRET);
    const replayCache = new MemoryWebhookReplayCache();
    const forged = serverWebhook(freshPayload({ jti: 'victim' }), 'wrong-secret');
    expect(() => webhook.verify({ ...forged, replayCache })).toThrow();
    expect(() => webhook.verify({ ...serverWebhook(freshPayload({ jti: 'victim' })), replayCache })).not.toThrow();
  });

  test('MemoryWebhookReplayCache forgets entries after their TTL', () => {
    vi.useFakeTimers();
    const cache = new MemoryWebhookReplayCache();
    expect(cache.checkAndSet('x', 10)).toBe(true);
    expect(cache.checkAndSet('x', 10)).toBe(false);
    vi.advanceTimersByTime(11_000);
    expect(cache.checkAndSet('x', 10)).toBe(true);
  });
});
