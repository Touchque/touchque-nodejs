import { describe, test, expect } from 'vitest';
import { FixedWindowLimiter } from './rateLimiter';

describe('FixedWindowLimiter', () => {
  test('allows up to the limit per key and window, then reports the wait', () => {
    const l = new FixedWindowLimiter({ windowMs: 10_000 });
    const t = 1_000_000;
    expect([1, 2, 3].map(() => l.hit('k', 3, t))).toEqual([0, 0, 0]);
    expect(l.hit('k', 3, t + 1000)).toBe(9);
    expect(l.hit('other', 3, t + 1000)).toBe(0);
    expect(l.hit('k', 3, t + 10_001)).toBe(0); // new window
  });

  test('is exported from the package with its defaults, for withTouchque and hand-written relays', async () => {
    const pkg = await import('./index');
    expect(pkg.FixedWindowLimiter).toBe(FixedWindowLimiter);
    const l = new pkg.FixedWindowLimiter();
    expect([l.windowMs, l.perIp, l.perUser]).toEqual([60_000, 20, 5]);
    const t = 5_000;
    for (let i = 0; i < 5; i++) expect(l.hit('user|transfer|jane', l.perUser, t)).toBe(0);
    expect(l.hit('user|transfer|jane', l.perUser, t)).toBe(60);
  });

  test('memory stays bounded under a flood of distinct keys', () => {
    const l = new FixedWindowLimiter({ windowMs: 60_000 });
    for (let i = 0; i < 120_000; i++) l.hit(`k${i}`, 5, 1);
    expect((l as any).entries.size).toBeLessThanOrEqual(50_000);
  });
});
