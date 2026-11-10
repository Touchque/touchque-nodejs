// Cross App Access (ID-JAG) and A2A agent card signatures against the shared fake API: an app
// trades a member's ID token for an ID-JAG at the identity provider and redeems it; an
// authorization server checks one (issuer, audience, client, expiry, typ, once); a card signed in
// RFC 8785 form verifies with keys from its own host and fails when changed or pointed elsewhere.
import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import { spawn, type ChildProcess } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { resolve } from 'node:path';
import { IdJagVerifier, IdJagError, requestIdJag, redeemIdJag, verifyAgentCard, signAgentCard, canonicalJson, AgentCardError } from './index';

let fake: ChildProcess;
let base = '';
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

describe('Cross App Access (ID-JAG)', () => {
  test('an app gets an ID-JAG for a member and redeems it; the authorization server checks it once', async () => {
    const { assertion, scope } = await requestIdJag({ issuer: `${base}/idp`, clientId: 'tqapp_test', clientSecret: 'tqs_test', idToken: 'idtoken:ada', audience: 'https://rs.example', resource: 'https://rs.example/files' });
    expect(scope).toBe('files:read');
    await expect(requestIdJag({ issuer: `${base}/idp`, clientId: 'tqapp_test', clientSecret: 'wrong', idToken: 'idtoken:ada', audience: 'https://rs.example' })).rejects.toMatchObject({ code: 'invalid_client', status: 401 });
    await expect(requestIdJag({ issuer: `${base}/idp`, clientId: 'tqapp_test', clientSecret: 'tqs_test', idToken: 'idtoken:ada', audience: 'https://other.example' })).rejects.toMatchObject({ code: 'invalid_target' });

    const verifier = new IdJagVerifier({ issuer: `${base}/idp`, audience: 'https://rs.example' });
    const claims = await verifier.verify(assertion, { clientId: 'acme-at-rs' });
    expect(claims).toMatchObject({ sub: 'ada', clientId: 'acme-at-rs', scopes: ['files:read'], resource: 'https://rs.example/files' });
    await expect(verifier.verify(assertion, { clientId: 'acme-at-rs' })).rejects.toThrow('already used');

    const tokens = await redeemIdJag({ tokenEndpoint: `${base}/rs/token`, clientId: 'acme-at-rs', assertion });
    expect(tokens).toMatchObject({ token_type: 'Bearer', scope: 'files:read' });
  });

  test('refusals: another client, audience or issuer, not an ID-JAG, expired', async () => {
    const verifier = new IdJagVerifier({ issuer: `${base}/idp`, audience: 'https://rs.example' });
    const mint = async (claims: Record<string, unknown>, typ?: string) => (await post('/__test/id-jag', { claims, typ })).assertion as string;
    const reason = (p: Promise<unknown>) => p.then(() => 'accepted', (e: IdJagError) => e.message);
    expect(await reason(verifier.verify(await mint({}), { clientId: 'someone-else' }))).toBe('issued to another client');
    expect(await reason(verifier.verify(await mint({ aud: 'https://evil.example' }), { clientId: 'acme-at-rs' }))).toBe('not for this authorization server');
    expect(await reason(verifier.verify(await mint({ aud: ['https://rs.example', 'https://b.example'] }), { clientId: 'acme-at-rs' }))).toBe('not for this authorization server');
    expect(await reason(verifier.verify(await mint({ iss: 'https://evil.example' }), { clientId: 'acme-at-rs' }))).toBe('another issuer');
    expect(await reason(verifier.verify(await mint({}, 'at+jwt'), { clientId: 'acme-at-rs' }))).toBe('not an ID-JAG (typ oauth-id-jag+jwt)');
    expect(await reason(verifier.verify(await mint({ exp: Math.floor(Date.now() / 1000) - 600 }), { clientId: 'acme-at-rs' }))).toBe('expired');
    const forged = (await mint({})).split('.');
    forged[1] = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(forged[1], 'base64url').toString()), sub: 'mallory' })).toString('base64url');
    expect(await reason(verifier.verify(forged.join('.'), { clientId: 'acme-at-rs' }))).toBe('signature does not verify');
  });
});

describe('A2A agent cards', () => {
  test('a signed card verifies with keys on its own host; a changed card or keys elsewhere do not', async () => {
    const url = `${base}/.well-known/agent-card.json`;
    const card = await fetch(url).then((r) => r.json() as Promise<Record<string, unknown>>);
    expect(await verifyAgentCard(card, { cardUrl: url })).toEqual({ kid: 'a2a-1', alg: 'ES256', keySource: 'jku' });
    const tampered = await fetch(`${url}?tamper=1`).then((r) => r.json() as Promise<Record<string, unknown>>);
    await expect(verifyAgentCard(tampered, { cardUrl: url })).rejects.toMatchObject({ code: 'invalid_signature' });
    // The card names keys on another host: not followed.
    await expect(verifyAgentCard(card, { cardUrl: 'https://agent.example/.well-known/agent-card.json' })).rejects.toMatchObject({ code: 'untrusted_key' });
    await expect(verifyAgentCard({ name: 'x' })).rejects.toMatchObject({ code: 'unsigned' });
  });

  test('sign and verify with a key you hold; RFC 8785 canonical form', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const signed = signAgentCard({ name: 'Mine', url: 'https://mine.example/a2a', skills: [] }, privateKey, { kid: 'k1' });
    const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1' };
    expect(await verifyAgentCard(signed, { keys: [jwk] })).toEqual({ kid: 'k1', alg: 'EdDSA', keySource: 'keys' });
    await expect(verifyAgentCard({ ...signed, url: 'https://evil.example/a2a' }, { keys: [jwk] })).rejects.toBeInstanceOf(AgentCardError);
    // RFC 8785 §3.2.3 example of key order, numbers and escapes.
    expect(canonicalJson({ '€': 'Euro', '\r': 'CR', '😀': 'smile', '1': 'one', a: [1e21, 1e-7, 0.5, -0, 'tab\there'] }))
      .toBe('{"\\r":"CR","1":"one","a":[1e+21,1e-7,0.5,0,"tab\\there"],"€":"Euro","😀":"smile"}');
  });
});
