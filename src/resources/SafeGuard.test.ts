// Safe Guard in the Node SDK, against the shared fake API (testing/fake-touchque-api.mjs):
// request with the raw transaction, wait for the phone, check its approval here.
import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import { spawn, type ChildProcess } from 'node:child_process';
import { resolve } from 'node:path';
import vectors from '../../fixtures/safe-guard-vectors.json';
import { TouchQue, TouchQueRejectedError, verifySafeApproval, type SafeGuardTx } from '../index';

const bybit = vectors.vectors.find((v) => v.name === 'bybit_pattern')!;

describe('Safe Guard against the fake API', () => {
  let fake: ChildProcess;
  let base = '';
  let tq: TouchQue;
  const control = (p: string, body: object) => fetch(`${base}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }).then((r) => r.json());
  beforeAll(async () => {
    fake = spawn(process.execPath, [resolve(__dirname, '../../testing/fake-touchque-api.mjs')], { stdio: ['ignore', 'pipe', 'inherit'] });
    const port = await new Promise<number>((res, rej) => {
      fake.once('error', rej);
      fake.stdout!.once('data', (chunk) => res(JSON.parse(String(chunk).split('\n')[0]).port));
    });
    base = `http://127.0.0.1:${port}`;
    tq = new TouchQue({ apiKey: 'tq_test_key', apiSecret: 'test_secret', baseUrl: base });
    await control('/__test/link', { user: 'treasurer@acme.com' });
  });
  afterAll(() => { fake?.kill(); });

  test('request, wait for the phone, then check its approval here', async () => {
    await control('/__test/opts', { safeTxView: { class: bybit.class, flags: ['delegatecall'], safeTxHash: bybit.safeTxHash, governanceHash: bybit.governanceHash, purpose: bybit.purpose } });
    const safeTx = { ...bybit.safeTx, chainId: 1n, tx: { ...bybit.safeTx.tx, safeTxGas: 45746n, nonce: 42n } } as SafeGuardTx;
    const req = await tq.safeGuard.request({ externalUsername: 'treasurer@acme.com', type: 'safe_payment', safeTx, referenceId: 'tx-1' });
    expect(req).toMatchObject({ requestId: expect.any(String), safeTx: { class: 'governance', governanceHash: bybit.governanceHash } });
    const sent = (await fetch(`${base}/__test/calls`).then((r) => r.json())).pop();
    expect(sent).toMatchObject({ method: 'POST', path: '/safe-guard/approvals', body: { type: 'safe_payment', referenceId: 'tx-1', safeTx: { chainId: '1', approverIndex: bybit.safeTx.approverIndex, tx: { nonce: '42', safeTxGas: '45746' } } } });
    expect((await tq.safeGuard.status(req.requestId))).toMatchObject({ status: 'PENDING', safeTx: { purpose: 'schedule' } });
    expect((await tq.safeGuard.status(req.requestId)).safeTx).not.toHaveProperty('approval');

    await control('/__test/approve', { id: req.requestId, safeTx: { approval: bybit.approval, expiresAt: bybit.expiresAt } });
    const done = await tq.safeGuard.waitForApproval({ requestId: req.requestId, pollInterval: 10 });
    expect(done).toMatchObject({ status: 'CONFIRMED', provisional: false, safeTx: { approval: bybit.approval, approverIndex: bybit.safeTx.approverIndex } });
    const check = verifySafeApproval(safeTx, done.safeTx!.approval!, vectors.approverKey, { now: vectors.now, approverIndex: done.safeTx!.approverIndex, purpose: 'schedule' });
    expect(check).toMatchObject({ valid: true, purpose: 'schedule', governanceHash: bybit.governanceHash });
    // Not as an approval to execute: the purpose defaults to approve.
    expect(verifySafeApproval(safeTx, done.safeTx!.approval!, vectors.approverKey, { now: vectors.now })).toMatchObject({ valid: false, reason: 'signature_invalid' });
  });

  test('a refusal on the phone, an unknown id, a missing field', async () => {
    const req = await tq.safeGuard.request({ externalUsername: 'treasurer@acme.com', type: 'safe_payment', safeTx: bybit.safeTx as SafeGuardTx });
    await control('/__test/reject', { id: req.requestId });
    await expect(tq.safeGuard.waitForApproval({ requestId: req.requestId, pollInterval: 10 })).rejects.toBeInstanceOf(TouchQueRejectedError);
    await expect(tq.safeGuard.status('00000000-0000-4000-8000-999999999999')).rejects.toMatchObject({ status: 404, code: 'not_found' });
    await expect(tq.safeGuard.request({ externalUsername: 'nobody@acme.com', type: 'safe_payment', safeTx: bybit.safeTx as SafeGuardTx })).rejects.toMatchObject({ code: 'device_not_linked' });
    await expect(tq.safeGuard.request({ externalUsername: 'treasurer@acme.com', type: '', safeTx: bybit.safeTx as SafeGuardTx })).rejects.toThrow(/type/);
  });
});
