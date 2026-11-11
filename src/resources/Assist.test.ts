// Help desk assist sessions in the Node SDK, against the shared fake API
// (testing/fake-touchque-api.mjs): open, a check the phone passes and is
// used once, a wrong number, unfreeze, and no phone.
import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import { spawn, type ChildProcess } from 'node:child_process';
import { resolve } from 'node:path';
import { Touchque, TouchqueAPIError, TouchqueConfigError, isAssistCheckPassed } from '../index';

describe('Assist against the fake API', () => {
  let fake: ChildProcess;
  let base = '';
  let tq: Touchque;
  const control = (p: string, body: object) => fetch(`${base}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }).then((r) => r.json());
  beforeAll(async () => {
    fake = spawn(process.execPath, [resolve(__dirname, '../../testing/fake-touchque-api.mjs')], { stdio: ['ignore', 'pipe', 'inherit'] });
    const port = await new Promise<number>((res, rej) => {
      fake.once('error', rej);
      fake.stdout!.once('data', (chunk) => res(JSON.parse(String(chunk).split('\n')[0]).port));
    });
    base = `http://127.0.0.1:${port}`;
    tq = new Touchque({ apiKey: 'tq_test_key', apiSecret: 'test_secret', baseUrl: base });
    await control('/__test/link', { user: 'ayse@acme.com' });
  });
  afterAll(() => { fake?.kill(); });

  test('open, a passed check used once for its own action, end', async () => {
    const s = await tq.assist.open({ externalUsername: 'ayse@acme.com', agent: { name: 'Deniz Kaya', title: 'IT help desk' }, reason: 'Ticket 4411' });
    expect(s).toMatchObject({ status: 'OPEN', agent: { name: 'Deniz Kaya', title: 'IT help desk' }, notified: true, phone: true });
    const check = await tq.assist.verify(s.id, { action: 'reset_2fa', actionText: 'reset your two-step verification' });
    expect(check.challengeCode).toMatch(/^\d{2}$/);
    expect((await control('/__test/assist', { requestId: check.requestId, action: 'approve' })).outcome).toBe('verified');
    expect(isAssistCheckPassed(await tq.assist.get(s.id), check.requestId)).toBe(true);
    await expect(tq.assist.spend(s.id, { requestId: check.requestId, action: 'reset_password' })).rejects.toMatchObject({ status: 428 });
    const spent = await tq.assist.spend(s.id, { requestId: check.requestId, action: 'reset_2fa' });
    expect(isAssistCheckPassed(spent, check.requestId)).toBe(false);
    expect((await tq.assist.list({ externalUsername: 'ayse@acme.com' }))[0].id).toBe(s.id);
    expect((await tq.assist.end(s.id)).status).toBe('ENDED');
    await expect(tq.assist.verify(s.id, { action: 'unlock' })).rejects.toMatchObject({ code: 'assist_not_open' });
  });

  test('a wrong number blocks it; "this isn\'t me" freezes, and a passed unlock check lifts it', async () => {
    const s = await tq.assist.open({ externalUsername: 'ayse@acme.com', agent: { name: 'Deniz Kaya' } });
    const bad = await tq.assist.verify(s.id, { action: 'activation_link' });
    await control('/__test/assist', { requestId: bad.requestId, action: 'wrong_number' });
    expect((await tq.assist.get(s.id)).checks[0].outcome).toBe('wrong_number');
    await expect(tq.assist.spend(s.id, { requestId: bad.requestId, action: 'activation_link' })).rejects.toMatchObject({ code: 'check_required' });
    const notMe = await tq.assist.verify(s.id, { action: 'activation_link' });
    await control('/__test/assist', { requestId: notMe.requestId, action: 'not_me' });
    expect((await tq.assist.get(s.id)).frozen).toBe(true);
    const unlock = await tq.assist.verify(s.id, { action: 'unlock' });
    await control('/__test/assist', { requestId: unlock.requestId, action: 'approve' });
    expect(await tq.assist.unfreeze(s.id, { requestId: unlock.requestId })).toMatchObject({ unfrozen: true, session: { frozen: false } });
  });

  test('no phone: routed to Never Locked Out', async () => {
    await tq.auth.generateSecret({ externalUsername: 'can@acme.com' });
    const s = await tq.assist.open({ externalUsername: 'can@acme.com', agent: { name: 'Deniz Kaya' } });
    expect(s.phone).toBe(false);
    const err = await tq.assist.verify(s.id, { action: 'new_phone' }).catch((e) => e);
    expect(err).toBeInstanceOf(TouchqueAPIError);
    expect(err).toMatchObject({ status: 409, code: 'no_phone', data: { route: 'never_locked_out' } });
  });

  test('argument checks', async () => {
    await expect(tq.assist.open({ externalUsername: '', agent: { name: 'x' } })).rejects.toBeInstanceOf(TouchqueConfigError);
    await expect(tq.assist.list({})).rejects.toBeInstanceOf(TouchqueConfigError);
    await expect(tq.assist.verify('id', { action: '' })).rejects.toBeInstanceOf(TouchqueConfigError);
  });
});
