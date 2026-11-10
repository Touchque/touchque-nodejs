// express is an optional peer dependency: the main entry loads without it
// (Next.js, Fastify, a plain script), and only the Express helpers need it
// (middleware/loadExpress.ts).
import { describe, test, expect, vi } from 'vitest';

// A static import of express anywhere in the main entry hits this and fails.
vi.mock('express', () => {
  throw new Error("Cannot find module 'express'");
});

describe('express is optional', () => {
  test('the main entry loads without importing express', async () => {
    const m = await import('./index');
    expect(typeof m.TouchQue).toBe('function');
    expect(typeof m.withTouchQue).toBe('function');
    expect(typeof m.createTouchQueLogin).toBe('function');
    // The helper requires express only when called (installed here, so it works).
    const router = m.touchqueRouter({} as never, { getUserId: () => undefined, getLoginUser: () => undefined });
    expect(typeof router).toBe('function');
  });
});
