// An organization's AI agent on TouchQue SSO against the shared fake API's
// /sso/token: its own key or its platform's token, a DPoP proof, and calls to
// an app that checks the proof against the token's key.
import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import { spawn, type ChildProcess } from 'node:child_process';
import { resolve } from 'node:path';
import { TouchQueOrgAgent, generateAgentKey } from './index';
import { TouchQueAPIError, TouchQueConfigError } from './errors';

let fake: ChildProcess;
let base: string;
const APP = 'tqapp_paymentsapi0000000000';
const post = (path: string, body: unknown) => fetch(`${base}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then((r) => r.json() as Promise<any>);

beforeAll(async () => {
  fake = spawn(process.execPath, [resolve(__dirname, '../testing/fake-touchque-api.mjs')], { stdio: ['ignore', 'pipe', 'inherit'] });
  const port = await new Promise<number>((res, rej) => {
    fake.once('error', rej);
    fake.stdout!.once('data', (chunk) => res(JSON.parse(String(chunk).split('\n')[0]).port));
  });
  base = `http://127.0.0.1:${port}`;
});
afterAll(() => { fake?.kill(); });

describe('TouchQueOrgAgent', () => {
  test('with its own key: a DPoP-bound token, cached, and calls the app with a fresh proof', async () => {
    const keys = generateAgentKey();
    const agentId = 'oagt_abcdefghijkmnpqrstuv';
    await post('/__test/org-agent', { agentId, publicKey: keys.publicJwk, audiences: [APP], scopes: ['invoices:read', 'payments:create'] });
    const agent = new TouchQueOrgAgent({ agentId, privateKey: keys.privateJwk, issuer: base });
    const token = await agent.getToken({ scope: 'invoices:read' });
    expect(token).toMatchObject({ tokenType: 'DPoP', expiresIn: 300, scope: 'invoices:read' });
    expect(await agent.getToken({ scope: 'invoices:read' })).toBe(token);
    const res = await agent.fetch(`${base}/__test/resource`, { scope: 'invoices:read' });
    expect(await res.json() as any).toEqual({ ok: true, sub: agentId, aud: APP, via: 'key' });
    // A proof is for one request: reused, the app refuses it.
    const headers = await agent.authorization('GET', `${base}/__test/resource`, { scope: 'invoices:read' });
    expect((await fetch(`${base}/__test/resource`, { headers })).status).toBe(200);
    expect((await fetch(`${base}/__test/resource`, { headers })).status).toBe(401);
    await expect(agent.getToken({ scope: 'payments:refund' })).rejects.toMatchObject({ status: 400, code: 'invalid_scope' });
  });

  test('with its platform\'s token instead of a key', async () => {
    const agentId = 'oagt_bbbbbbbbbbbbbbbbbbbb';
    await post('/__test/org-agent', { agentId, workload: { subject: 'repo:acme/payments:ref:refs/heads/main', audience: 'touchque' }, audiences: [APP], scopes: ['invoices:read'] });
    const platform = async () => (await post('/__test/workload-token', { sub: 'repo:acme/payments:ref:refs/heads/main', aud: 'touchque' })).token as string;
    const agent = new TouchQueOrgAgent({ agentId, issuer: base, assertion: platform });
    const res = await agent.fetch(`${base}/__test/resource`);
    expect((await res.json() as any).via).toBe('workload');
    const wrong = new TouchQueOrgAgent({ agentId, issuer: base, assertion: async () => (await post('/__test/workload-token', { sub: 'repo:evil/x', aud: 'touchque' })).token });
    await expect(wrong.getToken()).rejects.toBeInstanceOf(TouchQueAPIError);
  });

  test('for a member: with their token, or by asking them on the phone', async () => {
    const keys = generateAgentKey();
    const agentId = 'oagt_cccccccccccccccccccc';
    await post('/__test/org-agent', { agentId, publicKey: keys.publicJwk, audiences: [APP], scopes: ['payments:create'], delegation: ['token_exchange', 'ciba'] });
    const agent = new TouchQueOrgAgent({ agentId, privateKey: keys.privateJwk, issuer: base });
    const exchanged = await agent.exchangeToken({ subjectToken: 'member:ada@acme.com' });
    const call = (t: string) => fetch(`${base}/__test/resource`, { headers: { Authorization: `DPoP ${t}`, DPoP: agent.dpopProof('GET', `${base}/__test/resource`, t) } }).then((r) => r.json() as Promise<any>);
    expect(await call(exchanged.accessToken)).toMatchObject({ sub: 'ada@acme.com', act: agentId });
    // The token vault: Ada's own Google token, never a refresh token.
    expect(await agent.getConnectionToken({ subjectToken: 'member:ada@acme.com', connection: 'google', scope: 'email' })).toEqual({ accessToken: 'ya29.ada@acme.com', tokenType: 'Bearer', expiresIn: 3599, scope: 'email', connection: 'google' });
    await expect(agent.getConnectionToken({ subjectToken: 'member:ada@acme.com', connection: 'github' })).rejects.toMatchObject({ code: 'invalid_grant' });

    const payment = { type: 'payment_initiation', instructedAmount: { currency: 'TRY', amount: '500.00' } };
    const ask = await agent.askMember({ loginHint: 'ada@acme.com', bindingMessage: 'Pay invoice 42', authorizationDetails: [payment] });
    expect(ask).toMatchObject({ bindingCode: '42', interval: 1 });
    const waiting = agent.waitForMember(ask);
    setTimeout(() => { post('/__test/ciba-answer', { authReqId: ask.authReqId, approve: true }); }, 1500);
    const approved = await waiting;
    expect(approved.authorizationDetails).toEqual([payment]);
    expect(await call(approved.accessToken)).toMatchObject({ sub: 'ada@acme.com', act: agentId });

    // A shared account: the member's extension opens it; the agent learns only how it ended.
    await post('/__test/org-agent', { agentId, publicKey: keys.publicJwk, audiences: [APP], scopes: ['payments:create'], delegation: ['token_exchange', 'ciba'], sharedAccounts: ['k3JInstagramAcme01'] });
    await expect(agent.askToOpenSharedAccount({ account: 'other', loginHint: 'ada@acme.com' })).rejects.toMatchObject({ code: 'invalid_target' });
    const shared = await agent.askToOpenSharedAccount({ account: 'k3JInstagramAcme01', loginHint: 'ada@acme.com', message: 'Post the launch photo' });
    expect(shared).toMatchObject({ status: 'waiting_member', expiresIn: 600 });
    expect(shared.openUrl).toContain(`/agent-ask?ask=${shared.askId}`);
    expect(await agent.sharedAccountAskStatus(shared.askId)).toEqual({ status: 'waiting_member' });
    setTimeout(() => { post('/__test/shared-ask-answer', { askId: shared.askId, status: 'opened' }); }, 300);
    expect(await agent.waitForSharedAccount(shared, { intervalMs: 100 })).toEqual({ status: 'opened' });

    const no = await agent.askMember({ loginHint: 'ada@acme.com' });
    await post('/__test/ciba-answer', { authReqId: no.authReqId, approve: false });
    await expect(agent.waitForMember(no)).rejects.toMatchObject({ code: 'access_denied' });
  }, 15000);

  test('configuration mistakes fail early', () => {
    expect(() => new TouchQueOrgAgent({ agentId: 'agt_abcdefghijkmnpqrstuv', privateKey: generateAgentKey().privateJwk })).toThrow(TouchQueConfigError);
    expect(() => new TouchQueOrgAgent({ agentId: 'oagt_abcdefghijkmnpqrstuv', issuer: 'http://sso.example.com', assertion: () => 'x' })).toThrow(/plaintext/);
    expect(() => new TouchQueOrgAgent({ agentId: 'oagt_abcdefghijkmnpqrstuv' })).toThrow(/privateKey|assertion/);
  });
});
