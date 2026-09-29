// src/resources/Webhook.ts
// Webhook signature verification — ensures incoming webhooks are from TouchQue.

import * as crypto from 'crypto';
import { TouchQueWebhookReplayError, TouchQueWebhookSignatureError } from '../errors';
import { VerifyWebhookOptions, WebhookPayload, WebhookReplayCache } from '../types';

/**
 * In-process `WebhookReplayCache`. Entries expire after their TTL and the map
 * is capped, so it can't grow without bound. Not shared between processes.
 */
export class MemoryWebhookReplayCache implements WebhookReplayCache {
  private readonly seen = new Map<string, number>();
  constructor(private readonly maxEntries = 100_000) {}

  checkAndSet(jti: string, ttlSeconds: number): boolean {
    const now = Date.now();
    const expiresAt = this.seen.get(jti);
    if (expiresAt !== undefined && expiresAt > now) return false;
    if (this.seen.size >= this.maxEntries) {
      for (const [key, exp] of this.seen) {
        if (exp <= now || this.seen.size >= this.maxEntries) this.seen.delete(key);
        if (this.seen.size < this.maxEntries * 0.9) break;
      }
    }
    this.seen.set(jti, now + ttlSeconds * 1000);
    return true;
  }
}

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
   * **Always verify before processing.** Pass `replayCache` (e.g. a shared
   * `MemoryWebhookReplayCache`, or your own Redis-backed one) so a replayed
   * delivery throws `TouchQueWebhookReplayError` instead of re-running your
   * logic; without it, de-duplicate on `payload.jti` yourself.
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
   *       replayCache, // const replayCache = new MemoryWebhookReplayCache();
   *     });
   *     // ... handle event
   *     res.sendStatus(200);
   *   } catch (err) {
   *     if (err instanceof TouchQueWebhookReplayError) return res.sendStatus(200); // already handled
   *     res.sendStatus(403); // not from TouchQue, tampered, or stale
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

    // Replay protection: reject a webhook whose signed timestamp is missing,
    // unparseable or too far from now. TouchQue always sends one, so a
    // missing timestamp is never "skip the check" — it fails closed.
    const tolerance = options.toleranceSeconds ?? 300;
    if (tolerance > 0) {
      const ts = typeof payload.timestamp === 'string' ? Date.parse(payload.timestamp) : NaN;
      if (Number.isNaN(ts) || Math.abs(Date.now() - ts) > tolerance * 1000) {
        throw new TouchQueWebhookSignatureError();
      }
    }

    if (options.replayCache) {
      const jti = payload.jti;
      if (typeof jti !== 'string' || !jti) throw new TouchQueWebhookSignatureError();
      // Remember it for twice the window, so it outlives any timestamp that
      // could still pass the freshness check.
      const ttl = Math.max(tolerance * 2, 600);
      if (!options.replayCache.checkAndSet(jti, ttl)) throw new TouchQueWebhookReplayError(jti);
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
