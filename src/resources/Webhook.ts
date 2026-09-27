// src/resources/Webhook.ts
// Webhook signature verification — ensures incoming webhooks are from TouchQue.

import * as crypto from 'crypto';
import { TouchQueWebhookSignatureError } from '../errors';
import { VerifyWebhookOptions, WebhookPayload } from '../types';

/**
 * Reproduce the canonical string the TouchQue backend signs: the JSON body
 * with the `signature` field removed and its **top-level** keys sorted
 * (matching the API server's canonical JSON stringification). Nested values
 * keep their order.
 */
function canonicalize(payload: Record<string, unknown>): string {
  const { signature: _drop, ...rest } = payload;
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(rest).sort()) {
    sorted[key] = rest[key];
  }
  return JSON.stringify(sorted);
}

export class Webhook {
  private readonly apiSecret: string;

  constructor(apiSecret: string) {
    this.apiSecret = apiSecret;
  }

  /**
   * Verify that an incoming webhook request is genuinely from TouchQue and
   * return its parsed payload. Throws `TouchQueWebhookSignatureError` if the
   * signature is invalid, the body is malformed, or the webhook is stale.
   *
   * **Always verify before processing, and de-duplicate on `payload.jti`
   * (or `payload.requestId` + `payload.event`) so a replayed webhook can't
   * re-trigger your logic.**
   *
   * @throws {TouchQueWebhookSignatureError}
   *
   * @example
   * // Express.js — mount with a raw body parser on this route
   * app.post('/webhooks/touchque', express.raw({ type: 'application/json' }), (req, res) => {
   *   try {
   *     const event = tq.webhook.verify({
   *       rawBody: req.body.toString('utf8'),
   *       signature: req.headers['x-signature'] as string,
   *     });
   *     // ... handle event.event, guarded by an idempotency check on event.jti
   *     res.sendStatus(200);
   *   } catch {
   *     res.sendStatus(403); // not from TouchQue, tampered, or replayed
   *   }
   * });
   */
  verify(options: VerifyWebhookOptions): WebhookPayload {
    const { rawBody } = options;

    if (!rawBody || typeof rawBody !== 'string') {
      throw new TouchQueWebhookSignatureError();
    }

    let payload: Record<string, unknown>;
    try {
      const parsed = JSON.parse(rawBody);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('not an object');
      }
      payload = parsed as Record<string, unknown>;
    } catch {
      throw new TouchQueWebhookSignatureError();
    }

    // Signature to check: the caller-supplied header value wins; otherwise
    // fall back to the `signature` field TouchQue also embeds in the body.
    const provided =
      typeof options.signature === 'string' && options.signature
        ? options.signature
        : typeof payload.signature === 'string'
          ? (payload.signature as string)
          : '';
    if (!provided) {
      throw new TouchQueWebhookSignatureError();
    }

    const expected = crypto
      .createHmac('sha256', this.apiSecret)
      .update(canonicalize(payload))
      .digest('hex');

    const providedBuf = Buffer.from(provided, 'utf8');
    const expectedBuf = Buffer.from(expected, 'utf8');
    if (
      providedBuf.length !== expectedBuf.length ||
      !crypto.timingSafeEqual(providedBuf, expectedBuf)
    ) {
      throw new TouchQueWebhookSignatureError();
    }

    // Replay protection: reject a webhook whose timestamp is too far from now.
    const tolerance = options.toleranceSeconds ?? 300;
    if (tolerance > 0 && typeof payload.timestamp === 'string') {
      const ts = Date.parse(payload.timestamp);
      if (!Number.isNaN(ts) && Math.abs(Date.now() - ts) > tolerance * 1000) {
        throw new TouchQueWebhookSignatureError();
      }
    }

    return payload as WebhookPayload;
  }

  /**
   * Check a webhook signature without throwing. Returns `true` / `false`.
   *
   * @example
   * if (tq.webhook.isValid({ rawBody, signature })) {
   *   // process
   * }
   */
  isValid(options: VerifyWebhookOptions): boolean {
    try {
      this.verify(options);
      return true;
    } catch {
      return false;
    }
  }
}
