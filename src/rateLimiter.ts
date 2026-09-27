// A small in-memory fixed-window rate limiter for touchqueRouter's pre-auth
// routes. It protects the partner's own server (and their TouchQue quota) from
// scripted abuse of routes anyone on the internet can call. It is per process:
// behind several instances, each keeps its own counters, which still caps abuse
// per instance. Use your own shared limiter in front of the router if you need
// one global budget, and set `rateLimit: false` here.

export interface RateLimitOptions {
  /** Window length in ms. Default 60000. */
  windowMs?: number;
  /** Requests per client IP per route per window. Default 20. */
  perIp?: number;
  /** Requests per username per route per window (routes that name a user). Default 5. */
  perUser?: number;
}

interface Entry { count: number; resetAt: number }

const MAX_KEYS = 50_000;

export class FixedWindowLimiter {
  private readonly entries = new Map<string, Entry>();
  readonly windowMs: number;
  readonly perIp: number;
  readonly perUser: number;

  constructor(options: RateLimitOptions = {}) {
    this.windowMs = options.windowMs ?? 60_000;
    this.perIp = options.perIp ?? 20;
    this.perUser = options.perUser ?? 5;
  }

  /** Counts one hit. Returns seconds to wait when over `limit`, otherwise 0. */
  hit(key: string, limit: number, now = Date.now()): number {
    let e = this.entries.get(key);
    if (!e || e.resetAt <= now) {
      if (!e && this.entries.size >= MAX_KEYS) this.prune(now);
      e = { count: 0, resetAt: now + this.windowMs };
      this.entries.set(key, e);
    }
    e.count += 1;
    return e.count > limit ? Math.max(1, Math.ceil((e.resetAt - now) / 1000)) : 0;
  }

  private prune(now: number): void {
    for (const [k, v] of this.entries) if (v.resetAt <= now) this.entries.delete(k);
    // Still full (a flood of distinct keys): drop the oldest half rather than grow without bound.
    if (this.entries.size >= MAX_KEYS) {
      let i = 0;
      for (const k of this.entries.keys()) { if (i++ > MAX_KEYS / 2) break; this.entries.delete(k); }
    }
  }
}
