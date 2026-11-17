// Touchque Login user-store requests exactly as the platform POSTs them (fixtures/user-store-vectors.json, shared
// with every server SDK): each genuine one verifies with webhook.verify, from the x-signature header or from the
// body's own signature, and hands back its payload with each unpaired UTF-16 surrogate as U+FFFD; a tampered body,
// another secret or a wrong signature fails.
import { describe, test, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import * as crypto from 'node:crypto';
import { Webhook } from './resources/Webhook';
import { TouchqueWebhookSignatureError } from './errors';

interface UserStoreVector {
  name: string;
  event: string;
  valid: boolean;
  note: string;
  secret: string;
  body: string;
  x_signature: string;
  canonical: string;
  expected_payload: Record<string, unknown> | null;
}

const { vectors } = JSON.parse(readFileSync(resolve(__dirname, '../fixtures/user-store-vectors.json'), 'utf8')) as { vectors: UserStoreVector[] };

/** Every string in `value`, member names included. */
function strings(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.flatMap(strings);
  if (value !== null && typeof value === 'object') return Object.entries(value).flatMap(([name, member]) => [name, ...strings(member)]);
  return [];
}

describe('user-store-vectors.json', () => {
  test('the file has genuine requests of each event and refused ones', () => {
    expect(new Set(vectors.map((v) => v.name)).size).toBe(vectors.length);
    expect(new Set(vectors.filter((v) => v.valid).map((v) => v.event))).toEqual(new Set(['user_store.verify_password', 'user_store.get_user', 'user_store.ping']));
    expect(vectors.some((v) => !v.valid)).toBe(true);
  });

  for (const v of vectors) {
    test(`${v.name}: ${v.valid ? 'verifies' : 'is refused'}`, () => {
      // The vector itself: hex HMAC-SHA256 of the canonical string matches x-signature exactly when it is genuine.
      expect(crypto.createHmac('sha256', v.secret).update(v.canonical, 'utf8').digest('hex') === v.x_signature).toBe(v.valid);
      expect(JSON.parse(v.body).signature).toBe(v.x_signature);

      const webhook = new Webhook(v.secret);
      // Timestamps are fixed in the past: no freshness check.
      for (const options of [{ rawBody: v.body, signature: v.x_signature, toleranceSeconds: 0 }, { rawBody: v.body, toleranceSeconds: 0 }]) {
        if (!v.valid) {
          expect(() => webhook.verify(options)).toThrow(TouchqueWebhookSignatureError);
          expect(webhook.isValid(options)).toBe(false);
          continue;
        }
        const payload = webhook.verify(options);
        expect(payload).toEqual(v.expected_payload);
        expect(Object.keys(payload)).toEqual(Object.keys(v.expected_payload!));
        // Every string can be written as UTF-8 and read back unchanged: no unpaired surrogate is left.
        for (const s of strings(payload)) expect(Buffer.from(s, 'utf8').toString('utf8')).toBe(s);
      }

      if (v.valid) {
        // Changed after signing, or checked against a wrong signature: refused.
        const tampered = v.body.replace('"tenant":"acme"', '"tenant":"acmf"');
        expect(tampered).not.toBe(v.body);
        expect(() => webhook.verify({ rawBody: tampered, signature: v.x_signature, toleranceSeconds: 0 })).toThrow(TouchqueWebhookSignatureError);
        expect(() => webhook.verify({ rawBody: tampered, toleranceSeconds: 0 })).toThrow(TouchqueWebhookSignatureError);
        const wrong = (v.x_signature[0] === '0' ? '1' : '0') + v.x_signature.slice(1);
        expect(() => webhook.verify({ rawBody: v.body, signature: wrong, toleranceSeconds: 0 })).toThrow(TouchqueWebhookSignatureError);
        expect(() => new Webhook(`${v.secret}x`).verify({ rawBody: v.body, toleranceSeconds: 0 })).toThrow(TouchqueWebhookSignatureError);
      }
    });
  }
});
