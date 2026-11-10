// AI agents in the Node SDK: management calls send what the shared vectors
// (fixtures/agent-vectors.json) say, and TouchQueAgent signs in with its own
// key against the shared fake API, which checks the private_key_jwt assertion
// and the DPoP proofs like the real API.
import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import { spawn, type ChildProcess } from 'node:child_process';
import { createHash, generateKeyPairSync, createPrivateKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  TouchQue, TouchQueAgent, TouchQueAPIError, TouchQueApprovalError, TouchQueApprovalMismatchError, TouchQueConfigError,
  generateAgentKey, jwkThumbprint, matchesAuthorizationDetails, verifyApprovalTokenWith,
} from '../index';

const vectors = JSON.parse(readFileSync(resolve(__dirname, '../../fixtures/agent-vectors.json'), 'utf8'));
let fake: ChildProcess;
let base = '';
let tq: TouchQue;

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

const calls = async () => (await (await fetch(`${base}/__test/calls`)).json()) as Array<{ method: string; path: string; url: string; body: Record<string, unknown> }>;
const lastCall = async () => (await calls()).at(-1)!;

describe('key helpers', () => {
  test.each(vectors.thumbprints.map((v: any) => [v.jwk.crv, v]))('RFC 7638 thumbprint (%s)', (_crv, v: any) => {
    expect(jwkThumbprint(v.jwk)).toBe(v.thumbprint);
  });

  test('ath is base64url SHA-256 of the token', () => {
    for (const v of vectors.ath) expect(createHash('sha256').update(v.accessToken).digest('base64url')).toBe(v.ath);
  });

  test('generateAgentKey: ES256 by default, EdDSA on request, kid = thumbprint, the public half has no private parts', () => {
    const ec = generateAgentKey();
    expect(ec.publicJwk).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256', kid: jwkThumbprint(ec.publicJwk) });
    expect('d' in ec.publicJwk).toBe(false);
    expect(ec.privateJwk.d).toEqual(expect.any(String));
    expect(generateAgentKey('EdDSA').publicJwk).toMatchObject({ kty: 'OKP', crv: 'Ed25519', alg: 'EdDSA' });
  });
});

describe('tq.agents management calls', () => {
  const k1 = generateAgentKey();
  const k2 = generateAgentKey('EdDSA');
  let id = '';
  const fill = (v: unknown): unknown => JSON.parse(JSON.stringify(v)
    .replace(/"\{publicKey\}"/g, JSON.stringify(k1.publicJwk))
    .replace(/"\{publicKey2\}"/g, JSON.stringify(k2.publicJwk))
    .replace(/\{id\}/g, id)
    .replace(/\{kid\}/g, encodeURIComponent(k2.publicJwk.kid)));

  const run: Record<string, (a: any) => Promise<unknown>> = {
    create: (a) => tq.agents.create({ ...a, publicKey: k1.publicJwk }),
    list: (a) => tq.agents.list(a),
    get: () => tq.agents.get(id),
    update: (a) => tq.agents.update(id, a),
    addKey: () => tq.agents.addKey(id, k2.publicJwk),
    removeKey: () => tq.agents.removeKey(id, k2.publicJwk.kid),
    suspend: (a) => tq.agents.suspend(id, a.reason),
    resume: () => tq.agents.resume(id),
    setPolicy: (a) => tq.agents.setPolicy(id, a.policy),
    getWorkspacePolicy: () => tq.agents.getWorkspacePolicy(),
    listEvents: (a) => tq.agents.listEvents({ after: a.after, limit: a.limit }),
    setWorkspacePolicy: (a) => tq.agents.setWorkspacePolicy(a.policy),
    listBlocks: () => tq.agents.listBlocks(id),
    killSwitch: (a) => tq.agents.setKillSwitch(a.engaged, a.reason),
    killSwitchOff: (a) => tq.agents.setKillSwitch(a.engaged),
    revoke: () => tq.agents.revoke(id),
  };

  test.each(vectors.calls.map((v: any) => [v.name, v]))('%s', async (name, v: any) => {
    const result: any = await run[name as string](v.args);
    if (name === 'create') id = result.id;
    const call = await lastCall();
    const want = fill(v) as any;
    expect(call.method).toBe(want.method);
    expect(call.path).toBe(want.path);
    if (want.query) expect(call.url).toBe(`${want.path}?${want.query}`);
    if (want.body) expect(call.body).toEqual(want.body);
  });

  test('a person\'s block is listed and lifted', async () => {
    const key = generateAgentKey();
    const a = await tq.agents.create({ name: 'blocked', allowedTypes: ['LOGIN'], publicKey: key.publicJwk });
    await fetch(`${base}/__test/agent-block`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ agentId: a.id, user: 'jane@example.com' }) });
    expect((await tq.agents.listBlocks(a.id))[0]).toMatchObject({ externalUsername: 'jane@example.com', reason: 'not_me' });
    await tq.agents.liftBlock(a.id, 'jane@example.com');
    expect((await lastCall()).path).toBe(`/agents/${a.id}/blocks/jane%40example.com`);
    expect(await tq.agents.listBlocks(a.id)).toEqual([]);
  });

  test('a private key is refused before it leaves the process', async () => {
    await expect(tq.agents.create({ name: 'x', allowedTypes: ['LOGIN'], publicKey: k1.privateJwk as any })).rejects.toBeInstanceOf(TouchQueConfigError);
  });
});

describe('TouchQueAgent', () => {
  test('signs in with its own key (JWK, JSON, PEM; ES256 and EdDSA) and calls with DPoP', async () => {
    for (const alg of ['ES256', 'EdDSA'] as const) {
      const key = generateAgentKey(alg);
      const created = await tq.agents.create({ name: `agent ${alg}`, allowedTypes: ['LOGIN'], publicKey: key.publicJwk });
      const pem = createPrivateKey({ key: key.privateJwk as any, format: 'jwk' }).export({ format: 'pem', type: 'pkcs8' }).toString();
      for (const privateKey of [key.privateJwk, JSON.stringify(key.privateJwk), pem]) {
        const agent = new TouchQueAgent({ agentId: created.id, privateKey, baseUrl: base });
        const me = await agent.me();
        expect(me.agent).toMatchObject({ id: created.id, allowedTypes: ['LOGIN'] });
        expect(me.scope).toBe('agent:read approvals:request approvals:read vault:read');
      }
    }
    const tokenCall = (await calls()).filter((c) => c.path === '/agents/token').at(-1)!;
    expect(tokenCall.body).toMatchObject(vectors.tokenRequest.form);
  });

  test('reuses its token until it is close to expiry', async () => {
    const key = generateAgentKey();
    const created = await tq.agents.create({ name: 'reuse', allowedTypes: ['LOGIN'], publicKey: key.publicJwk });
    const agent = new TouchQueAgent({ agentId: created.id, privateKey: key.privateJwk, baseUrl: base });
    const before = (await calls()).filter((c) => c.path === '/agents/token').length;
    await Promise.all([agent.me(), agent.me(), agent.me()]);
    await agent.me();
    expect((await calls()).filter((c) => c.path === '/agents/token').length - before).toBe(1);
  });

  test('a suspended agent, a stranger\'s key and a paused workspace are refused with the reason', async () => {
    const key = generateAgentKey();
    const created = await tq.agents.create({ name: 'refused', allowedTypes: ['LOGIN'], publicKey: key.publicJwk });
    const agent = new TouchQueAgent({ agentId: created.id, privateKey: key.privateJwk, baseUrl: base });
    await agent.me();
    await tq.agents.suspend(created.id, 'looping');
    const blocked = await agent.me().catch((e) => e);
    expect(blocked).toBeInstanceOf(TouchQueAPIError);
    expect(blocked).toMatchObject({ status: 403, code: 'agent_blocked' });
    expect(blocked.data.reason).toBe('suspended');
    const fresh = await new TouchQueAgent({ agentId: created.id, privateKey: key.privateJwk, baseUrl: base }).me().catch((e) => e);
    expect(fresh).toMatchObject({ code: 'unauthorized_client' });
    expect(fresh.data.reason).toBe('suspended');
    await tq.agents.resume(created.id);

    const stranger = generateAgentKey();
    const spoof = await new TouchQueAgent({ agentId: created.id, privateKey: stranger.privateJwk, kid: key.publicJwk.kid, baseUrl: base }).me().catch((e) => e);
    expect(spoof).toMatchObject({ status: 401, code: 'invalid_client' });

    await tq.agents.setKillSwitch(true, 'incident');
    expect((await agent.me().catch((e) => e)).data.reason).toBe('workspace_paused');
    await tq.agents.setKillSwitch(false);
    expect((await agent.me()).agent.id).toBe(created.id);
  });

  test('configuration errors are caught locally', () => {
    expect(() => new TouchQueAgent({ agentId: 'nope', privateKey: generateAgentKey().privateJwk })).toThrow(TouchQueConfigError);
    expect(() => new TouchQueAgent({ agentId: 'agt_abcdefghijkmnpqrstuv', privateKey: 'not a key' })).toThrow(TouchQueConfigError);
    const p384 = generateKeyPairSync('ec', { namedCurve: 'P-384' }).privateKey;
    expect(() => new TouchQueAgent({ agentId: 'agt_abcdefghijkmnpqrstuv', privateKey: p384 })).toThrow(/P-256/);
    expect(() => new TouchQueAgent({ agentId: 'agt_abcdefghijkmnpqrstuv', privateKey: generateAgentKey().privateJwk, baseUrl: 'http://api.example.com' })).toThrow(/https/);
  });
});

describe('approval tokens and matching (shared vectors)', () => {
  const v = vectors.approvalToken;
  test('a token signed by the published key verifies; tampered, wrong type, expired or another workspace do not', () => {
    const at = v.verifyAt * 1000;
    expect(verifyApprovalTokenWith(v.token, v.jwks, { now: at, audience: v.audience })).toMatchObject({ sub: v.claims.sub, act: v.claims.act });
    expect(() => verifyApprovalTokenWith(v.tampered, v.jwks, { now: at, audience: v.audience })).toThrow(TouchQueApprovalMismatchError);
    expect(() => verifyApprovalTokenWith(v.wrongType, v.jwks, { now: at, audience: v.audience })).toThrow(/typ/);
    expect(() => verifyApprovalTokenWith(v.token, v.jwks, { now: (v.claims.exp + 60) * 1000, audience: v.audience })).toThrow(/expired/);
    expect(() => verifyApprovalTokenWith(v.token, v.jwks, { now: at, audience: 'touchque:workspace:other' })).toThrow(/another workspace/);
  });

  test('the audience is required, and a token without aud is refused', () => {
    const at = v.verifyAt * 1000;
    expect(() => verifyApprovalTokenWith(v.token, v.jwks, { now: at } as any)).toThrow(/audience is required/);
    expect(() => verifyApprovalTokenWith(v.token, v.jwks, { now: at, audience: '' })).toThrow(/audience is required/);
    expect(() => verifyApprovalTokenWith(v.noAudience.token, v.noAudience.jwks, { now: at, audience: v.audience })).toThrow(/names no workspace/);
  });

  test.each(vectors.matching.map((m: any) => [m.name, m]))('%s', (_name, m: any) => {
    expect(matchesAuthorizationDetails(v.claims.authorization_details, m.expect)).toBe(m.matches);
  });
});

describe('agent approvals against the fake API', () => {
  const PAYMENT = vectors.approvalToken.claims.authorization_details[0];
  const user = 'agent-approvals@example.com';
  let agent: TouchQueAgent;

  beforeAll(async () => {
    await fetch(`${base}/__test/link`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ user }) });
    await tq.actionTypes.define('PAY_INVOICE', { critical: false });
    const key = generateAgentKey();
    const created = await tq.agents.create({ name: 'Invoice bot', allowedTypes: ['PAY_INVOICE'], publicKey: key.publicJwk });
    agent = new TouchQueAgent({ agentId: created.id, privateKey: key.privateJwk, baseUrl: base });
  });

  const approve = (id: string) => fetch(`${base}/__test/approve`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id }) });

  test('ask, wait, redeem once with the expected details', async () => {
    const ask = await agent.requestApproval({ user, type: 'PAY_INVOICE', authorizationDetails: [PAYMENT], reason: 'October rent' });
    expect(ask).toMatchObject({ status: 'pending', challengeCode: '47' });
    expect((await calls()).at(-1)!.body).toMatchObject({ externalUsername: user, type: 'PAY_INVOICE', authorizationDetails: [PAYMENT], reason: 'October rent' });
    await approve(ask.approvalId);
    const done = await agent.waitForApproval(ask.approvalId, { intervalMs: 500 });
    expect(done.status).toBe('approved');
    const token = done.approvalToken!;

    // The workspace's own audience comes from GET /agents/approval-audience; another one is refused.
    expect(await tq.agents.approvalAudience()).toBe('touchque:workspace:fake-workspace');
    const claims = await tq.agents.verifyApprovalToken(token, { expect: { user, authorizationDetails: PAYMENT } });
    expect(claims.act.sub).toBe(agent.agentId);
    await expect(tq.agents.verifyApprovalToken(token, { audience: 'touchque:workspace:other' })).rejects.toThrow(/another workspace/);

    // A mismatch is refused before anything is used...
    await expect(tq.agents.redeemApproval(token, { authorizationDetails: { ...PAYMENT, instructedAmount: { currency: 'TRY', amount: '5000.00' } } })).rejects.toBeInstanceOf(TouchQueApprovalMismatchError);
    await expect(tq.agents.redeemApproval(token, { user: 'someone@example.com' })).rejects.toBeInstanceOf(TouchQueApprovalMismatchError);
    // ...so the right expectation still redeems it, once.
    const approval = await tq.agents.redeemApproval(token, { user, type: 'PAY_INVOICE', authorizationDetails: { type: 'payment_initiation', instructedAmount: { currency: 'try', amount: '500' }, creditorAccount: { iban: 'TR33 0006 1005 1978 6457 8413 26' } } });
    expect(approval).toMatchObject({ id: ask.approvalId, externalUsername: user, agent: { id: agent.agentId } });
    const again = await tq.agents.redeemApproval(token).catch((e) => e);
    expect(again).toMatchObject({ status: 409, code: 'already_redeemed' });
    expect((await agent.getApproval(ask.approvalId)).status).toBe('redeemed');
  });

  test('a rejection ends the wait with the reason; a type it may not ask for is refused', async () => {
    const ask = await agent.requestApproval({ user, type: 'PAY_INVOICE', authorizationDetails: [PAYMENT], presence: 'background' });
    expect(ask.challengeCode).toBeUndefined();
    await fetch(`${base}/__test/reject`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: ask.approvalId }) });
    const err = await agent.waitForApproval(ask.approvalId, { intervalMs: 500 }).catch((e) => e);
    expect(err).toBeInstanceOf(TouchQueApprovalError);
    expect(err.status).toBe('rejected');
    const refused = await agent.requestApproval({ user, type: 'SEND_MONEY', authorizationDetails: [PAYMENT] }).catch((e) => e);
    expect(refused).toMatchObject({ status: 403, code: 'type_not_allowed' });
  });
});

describe('mandates against the fake API', () => {
  const PAYMENT = vectors.approvalToken.claims.authorization_details[0];
  const user = 'agent-mandates@example.com';

  test('ask once, then requests within it need no push; the partner lists and revokes it', async () => {
    await fetch(`${base}/__test/link`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ user }) });
    await tq.actionTypes.define('PAY_INVOICE', { critical: false });
    const key = generateAgentKey();
    const created = await tq.agents.create({ name: 'Mandate bot', allowedTypes: ['PAY_INVOICE'], publicKey: key.publicJwk });
    const agent = new TouchQueAgent({ agentId: created.id, privateKey: key.privateJwk, baseUrl: base });
    const mandate = await agent.requestMandate({ user, type: 'PAY_INVOICE', maxCount: 2, maxTotal: { currency: 'TRY', amount: '1000' }, recipients: ['TR33 0006 1005 1978 6457 8413 26'], validFor: 3600 });
    expect(mandate).toMatchObject({ status: 'pending', challengeCode: '47', maxCount: 2 });
    expect((await calls()).at(-1)!.body).toMatchObject({ externalUsername: user, maxCount: 2, maxTotal: { currency: 'TRY', amount: '1000' } });
    const r = (await (await fetch(`${base}/__test/requests`)).json()).at(-1);
    await fetch(`${base}/__test/approve`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: r.id }) });
    expect((await agent.getMandate(mandate.mandateId)).status).toBe('active');

    const used = await agent.requestApproval({ user, type: 'PAY_INVOICE', authorizationDetails: [PAYMENT], mandateId: mandate.mandateId });
    expect(used).toMatchObject({ status: 'approved', mandate: { usedCount: 1 } });
    expect((await agent.waitForApproval(used.approvalId, { intervalMs: 500 })).approvalToken).toEqual(expect.any(String));

    expect((await tq.agents.listMandates(created.id, { user })).map((m) => m.mandateId)).toEqual([mandate.mandateId]);
    expect((await tq.agents.revokeMandate(created.id, mandate.mandateId)).status).toBe('revoked');
    const refused = await agent.requestApproval({ user, type: 'PAY_INVOICE', authorizationDetails: [PAYMENT], mandateId: mandate.mandateId }).catch((e) => e);
    expect(refused).toMatchObject({ status: 409, code: 'mandate_revoked' });
    expect((await agent.revokeMandate(mandate.mandateId)).status).toBe('revoked');
  });
});

describe('the token vault against the fake API', () => {
  test('the partner deposits a person\'s tokens; only the agents a connection names get the access token', async () => {
    const key = generateAgentKey();
    const created = await tq.agents.create({ name: 'Calendar bot', allowedTypes: ['PAY_INVOICE'], publicKey: key.publicJwk });
    const agent = new TouchQueAgent({ agentId: created.id, privateKey: key.privateJwk, baseUrl: base });
    const conn = await tq.agents.vault.putConnection('google', { provider: 'google', clientId: 'acme.apps.googleusercontent.com', clientSecret: 'g-secret', agentIds: [created.id] });
    expect(conn).toMatchObject({ name: 'google', provider: 'google', hasClientSecret: true, agentIds: [created.id] });
    const account = await tq.agents.vault.deposit('google', 'jane@example.com', { accessToken: 'ya29.jane', refreshToken: '1//jane', expiresIn: 3599, scope: 'calendar.readonly' });
    expect(account).toMatchObject({ connection: 'google', externalUsername: 'jane@example.com', canRefresh: true });
    expect(JSON.stringify(await tq.agents.vault.listAccounts('jane@example.com'))).not.toContain('ya29');
    expect(await agent.getConnectionToken({ user: 'jane@example.com', connection: 'google' })).toEqual({ accessToken: 'ya29.jane', tokenType: 'Bearer', expiresIn: 3599, scope: 'calendar.readonly', connection: 'google' });
    await expect(agent.getConnectionToken({ user: 'john@example.com', connection: 'google' })).rejects.toMatchObject({ code: 'not_connected' });
    await tq.agents.vault.putConnection('google', { provider: 'google', clientId: 'acme.apps.googleusercontent.com', agentIds: [] });
    await expect(agent.getConnectionToken({ user: 'jane@example.com', connection: 'google' })).rejects.toMatchObject({ code: 'connection_not_allowed' });
    await tq.agents.vault.removeAccount('google', 'jane@example.com');
    expect(await tq.agents.vault.removeConnection('google')).toEqual({ removed: true, tokensDeleted: 0 });
  });
});
