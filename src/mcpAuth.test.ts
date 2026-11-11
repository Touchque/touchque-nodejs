// McpAuth (an MCP server whose authorization server is Touchque SSO) against
// the shared fake API's MCP issuer: metadata, audience, issuer, expiry,
// scopes per tool, DPoP-bound tokens and their proofs.
import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import { spawn, type ChildProcess } from 'node:child_process';
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { resolve } from 'node:path';
import { McpAuth, McpAuthError } from './index';

let fake: ChildProcess;
let base: string;
const RESOURCE = 'https://mcp.acme.example/mcp';
const post = (path: string, body: unknown) => fetch(`${base}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then((r) => r.json() as Promise<any>);
const token = (claims: Record<string, unknown>) => post('/__test/mcp-token', { aud: RESOURCE, scope: 'tickets:read', ...claims }).then((r) => r.token as string);

beforeAll(async () => {
  fake = spawn(process.execPath, [resolve(__dirname, '../testing/fake-touchque-api.mjs')], { stdio: ['ignore', 'pipe', 'inherit'] });
  const port = await new Promise<number>((res, rej) => {
    fake.once('error', rej);
    fake.stdout!.once('data', (chunk) => res(JSON.parse(String(chunk).split('\n')[0]).port));
  });
  base = `http://127.0.0.1:${port}`;
});
afterAll(() => { fake?.kill(); });

describe('McpAuth', () => {
  const auth = () => new McpAuth({ issuer: `${base}/mcp-as`, resource: RESOURCE, tools: { search_tickets: 'tickets:read', delete_ticket: 'tickets:delete' }, resourceName: 'Support desk' });
  const call = (a: McpAuth, authorization?: string, extra: Record<string, string> = {}) => a.verifyRequest({ method: 'POST', url: RESOURCE, headers: { ...(authorization && { authorization }), ...extra } });

  test('serves the protected resource metadata', () => {
    const a = auth();
    expect(a.metadataPaths()).toEqual(['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp']);
    expect(a.protectedResourceMetadata()).toMatchObject({ resource: RESOURCE, authorization_servers: [`${base}/mcp-as`], scopes_supported: ['tickets:read', 'tickets:delete'], resource_name: 'Support desk' });
  });

  test('a good token passes; the tool scope is checked; 401 and 403 say what to do', async () => {
    const a = auth();
    const claims = await call(a, `Bearer ${await token({})}`);
    expect(claims).toMatchObject({ sub: 'user-1', email: 'ada@acme.com', clientId: 'https://tool.example/client.json', scopes: ['tickets:read'], orgId: 'org-1', dpopBound: false });
    a.requireTool(claims, 'search_tickets');
    expect(() => a.requireTool(claims, 'delete_ticket')).toThrow(McpAuthError);
    try { a.requireTool(claims, 'delete_ticket'); } catch (err) {
      expect(err).toMatchObject({ status: 403, code: 'insufficient_scope' });
      expect((err as McpAuthError).wwwAuthenticate).toContain('scope="tickets:delete"');
    }
    await expect(call(a)).rejects.toMatchObject({ status: 401, wwwAuthenticate: 'Bearer resource_metadata="https://mcp.acme.example/.well-known/oauth-protected-resource/mcp"' });
    await expect(call(a, `Bearer ${await token({ aud: 'https://other.example/mcp' })}`)).rejects.toMatchObject({ status: 401, code: 'invalid_token' });
    await expect(call(a, `Bearer ${await token({ iss: 'https://evil.example/mcp' })}`)).rejects.toMatchObject({ status: 401 });
    await expect(call(a, `Bearer ${await token({ expiresIn: -120 })}`)).rejects.toMatchObject({ status: 401 });
    await expect(call(a, `Bearer ${await token({ typ: 'JWT' })}`)).rejects.toMatchObject({ status: 401 });
    const forged = (await token({})).replace(/\.[^.]+$/, '.AAAA');
    await expect(call(a, `Bearer ${forged}`)).rejects.toMatchObject({ status: 401 });
  });

  test('a DPoP-bound token needs a fresh proof for this request, once', async () => {
    const a = auth();
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' }) as any;
    const jkt = createHash('sha256').update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })).digest('base64url');
    const t = await token({ jkt });
    const proof = (htu = RESOURCE) => {
      const h = Buffer.from(JSON.stringify({ typ: 'dpop+jwt', alg: 'ES256', jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } })).toString('base64url');
      const p = Buffer.from(JSON.stringify({ htm: 'POST', htu, iat: Math.floor(Date.now() / 1000), jti: randomUUID(), ath: createHash('sha256').update(t).digest('base64url') })).toString('base64url');
      return `${h}.${p}.${sign('sha256', Buffer.from(`${h}.${p}`), { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
    };
    await expect(call(a, `Bearer ${t}`)).rejects.toMatchObject({ status: 401 });
    const good = proof();
    expect((await call(a, `DPoP ${t}`, { dpop: good })).dpopBound).toBe(true);
    await expect(call(a, `DPoP ${t}`, { dpop: good })).rejects.toMatchObject({ code: 'invalid_dpop_proof' });
    await expect(call(a, `DPoP ${t}`, { dpop: proof('https://other.example/mcp') })).rejects.toMatchObject({ code: 'invalid_dpop_proof' });
  });
});
