// verify() onChallenge against the shared fake API (testing/fake-touchque-api.mjs):
// the number reaches the caller before the wait (the callback approves, so
// verify() could not finish otherwise), and a callback that throws is logged
// while verify() keeps waiting.
import { describe, test, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest';
import { spawn, type ChildProcess } from 'node:child_process';
import { resolve } from 'node:path';
import { TouchQue, type VerifyChallenge } from '../index';

const USER = 'jane@acme.com';
let fake: ChildProcess;
let base = '';
let tq: TouchQue;

const control = (path: string, body: Record<string, unknown> = {}) =>
  fetch(`${base}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

beforeAll(async () => {
  fake = spawn(process.execPath, [resolve(__dirname, '../../testing/fake-touchque-api.mjs')], { stdio: ['ignore', 'pipe', 'inherit'] });
  const port = await new Promise<number>((res, rej) => {
    fake.once('error', rej);
    fake.stdout!.once('data', (chunk) => res(JSON.parse(String(chunk).split('\n')[0]).port));
  });
  base = `http://127.0.0.1:${port}`;
  tq = new TouchQue({ apiKey: 'tq_test_key', apiSecret: 'test_secret', baseUrl: base });
});
afterAll(() => { fake?.kill(); });
beforeEach(async () => {
  await control('/__test/reset');
  await control('/__test/link', { user: USER });
});

describe('login.verify onChallenge', () => {
  test('gets the number, reasons and case code before the wait', async () => {
    await control('/__test/opts', { numberMatch: true });
    const seen: VerifyChallenge[] = [];
    const result = await tq.login.verify({
      externalUsername: USER, type: 'LOGIN', timeout: 5000, pollInterval: 50,
      // A concise arrow returning a value must type-check (onChallenge returns unknown).
      onChallenge: (c) => seen.push(c) && control('/__test/approve', { id: c.requestId }),
    });
    expect(result.approved).toBe(true);
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({ requestId: result.requestId, challengeCode: '47', caseCode: 'K7P-2QX' });
    expect(seen[0].reasons?.[0].code).toBe('number_match_requested');
    expect(seen[0].expiresAt).toBeTruthy();
  });

  test('a throwing callback is logged and verify() keeps waiting', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const result = await tq.login.verify({
        externalUsername: USER, type: 'SEND_MONEY', timeout: 5000, pollInterval: 50,
        onChallenge: (c) => { void control('/__test/approve', { id: c.requestId }); throw new Error('screen gone'); },
      });
      expect(result).toMatchObject({ approved: true, challengeCode: '47' });
      expect(warn).toHaveBeenCalledWith('[TouchQue] onChallenge failed:', 'screen gone');
    } finally {
      warn.mockRestore();
    }
  });
});
