// Agent framework helpers against the shared fake API: a wrapped tool runs only
// after the phone approved (the fake's /__test/approve stands for the phone),
// with the approval token in currentApproval(); a rejection stops it; the
// OpenAI Agents SDK interruptions, the Claude Agent SDK callbacks and an MCP
// client are driven by duck-typed stand-ins of those libraries.
import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import { spawn, type ChildProcess } from 'node:child_process';
import { resolve } from 'node:path';
import {
  TouchQue, TouchQueAgent, TouchQueApprovalError, generateAgentKey,
  withTouchQueApproval, currentApproval, requireAgentApproval, approveInterruptionsWithTouchQue, touchqueCanUseTool, touchquePreToolUseHook, guardMcpClient,
  type ApprovalPolicy,
} from './index';

let fake: ChildProcess;
let base = '';
let agent: TouchQueAgent;
const USER = 'frameworks@example.com';

beforeAll(async () => {
  fake = spawn(process.execPath, [resolve(__dirname, '../testing/fake-touchque-api.mjs')], { stdio: ['ignore', 'pipe', 'inherit'] });
  const port = await new Promise<number>((res, rej) => {
    fake.once('error', rej);
    fake.stdout!.once('data', (chunk) => res(JSON.parse(String(chunk).split('\n')[0]).port));
  });
  base = `http://127.0.0.1:${port}`;
  const tq = new TouchQue({ apiKey: 'tq_test_key', apiSecret: 'test_secret', baseUrl: base });
  await fetch(`${base}/__test/link`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ user: USER }) });
  await tq.actionTypes.define('PAY_INVOICE', { critical: false });
  const key = generateAgentKey();
  const created = await tq.agents.create({ name: 'Framework bot', allowedTypes: ['PAY_INVOICE'], publicKey: key.publicJwk });
  agent = new TouchQueAgent({ agentId: created.id, privateKey: key.privateJwk, baseUrl: base });
});
afterAll(() => { fake?.kill(); });

const phone = (approve: boolean) => (s: { approvalId: string }) => {
  setTimeout(() => { fetch(`${base}/__test/${approve ? 'approve' : 'reject'}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: s.approvalId }) }); }, 50);
};
// Made inside the tests: the agent exists by then.
const policy = (approve: boolean): ApprovalPolicy<{ iban: string; amount: string }> => ({
  agent, user: USER, type: 'PAY_INVOICE',
  details: ({ iban, amount }) => [{ type: 'payment_initiation', instructedAmount: { currency: 'TRY', amount }, creditorAccount: { iban } }],
  onChallenge: phone(approve), timeoutMs: 15000,
});

describe('agent framework helpers', () => {
  test('a wrapped tool runs after the phone approved, with the approval token; a rejection stops it', async () => {
    const seen: string[] = [];
    const pay = withTouchQueApproval(async ({ iban }: { iban: string; amount: string }, runContext?: string) => {
      seen.push(`${iban} ${runContext} ${currentApproval()!.approvalToken ? 'token' : 'none'}`);
      return 'paid';
    }, policy(true));
    expect(await pay({ iban: 'TR330006100519786457841326', amount: '500.00' }, 'ctx')).toBe('paid');
    expect(seen).toEqual(['TR330006100519786457841326 ctx token']);
    expect(currentApproval()).toBeUndefined();

    const refused = withTouchQueApproval(async () => 'paid', policy(false));
    await expect(refused({ iban: 'TR330006100519786457841326', amount: '9.00' })).rejects.toBeInstanceOf(TouchQueApprovalError);
  }, 30000);

  test('OpenAI Agents SDK interruptions, Claude Agent SDK callbacks and an MCP client', async () => {
    // Interruptions: approved and rejected on the run state; a tool without a policy is left alone.
    const approved: string[] = [];
    const rejected: string[] = [];
    const state = { approve: (i: any) => approved.push(i.rawItem.name), reject: (i: any) => rejected.push(i.rawItem.name) };
    const args = JSON.stringify({ iban: 'TR330006100519786457841326', amount: '20.00' });
    await approveInterruptionsWithTouchQue({ interruptions: [{ rawItem: { name: 'pay', arguments: args } }, { rawItem: { name: 'refund', arguments: args } }, { rawItem: { name: 'other', arguments: '{}' } }], state },
      { pay: policy(true), refund: policy(false) });
    expect([approved, rejected]).toEqual([['pay'], ['refund']]);

    // canUseTool: approval token put into the input; others allowed; a refusal denies.
    const can = touchqueCanUseTool({ pay: policy(true) }, { tokenField: 'approvalToken' });
    const allowed = await can('pay', { iban: 'TR330006100519786457841326', amount: '30.00' });
    expect(allowed).toMatchObject({ behavior: 'allow', updatedInput: { iban: 'TR330006100519786457841326', approvalToken: expect.any(String) } });
    expect(await can('Read', { file: 'a' })).toEqual({ behavior: 'allow', updatedInput: { file: 'a' } });
    const hook = touchquePreToolUseHook({ pay: policy(false) });
    expect(await hook({ tool_name: 'pay', tool_input: { iban: 'TR330006100519786457841326', amount: '40.00' } })).toMatchObject({ hookSpecificOutput: { permissionDecision: 'deny' } });
    expect(await hook({ tool_name: 'Read', tool_input: {} })).toEqual({});

    // MCP client: the approval token reaches the server in _meta.
    const sent: any[] = [];
    const client = { callTool: async (params: any) => { sent.push(params); return { content: [] }; }, other: () => 'kept' };
    const guarded = guardMcpClient(client, { pay: policy(true) });
    await guarded.callTool({ name: 'pay', arguments: { iban: 'TR330006100519786457841326', amount: '50.00' } });
    await guarded.callTool({ name: 'list', arguments: {} });
    expect(sent[0]._meta['touchque/approvalToken']).toEqual(expect.any(String));
    expect(sent[1]._meta).toBeUndefined();
    expect(guarded.other()).toBe('kept');

    // The plain call: the approved state.
    const s = await requireAgentApproval(policy(true), { iban: 'TR330006100519786457841326', amount: '60.00' }, 'pay');
    expect(s.status).toBe('approved');
  }, 60000);
});
