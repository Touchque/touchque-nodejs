// Cross App Access (ID-JAG) and A2A agent card signatures against the shared fake API: an app
// trades a member's ID token for an ID-JAG at the identity provider and redeems it; an
// authorization server checks one (issuer, audience, client, expiry, typ, once); a card signed in
// RFC 8785 form verifies with keys from its own host and fails when changed or pointed elsewhere.
import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import { spawn, type ChildProcess } from 'node:child_process';
import { generateKeyPairSync, createPublicKey, verify as verifySig, createHash } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { createServer as createNetServer, type AddressInfo } from 'node:net';
import { resolve } from 'node:path';
import { IdJagVerifier, IdJagError, requestIdJag, redeemIdJag, createIdJagDpopKey, idJagDpopProof, verifyAgentCard, signAgentCard, canonicalJson, AgentCardError, TouchqueConfigError, type IdJagDpopProofOptions } from './index';

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

  test('DPoP: requestIdJag and redeemIdJag send a proof for each endpoint; a bound ID-JAG needs the same key at the verifier', async () => {
    // An identity provider and an authorization server that check the proof and bind to its key.
    const seen: Array<{ path: string; header: any; payload: any; jkt: string }> = [];
    const thumb = (jwk: any) => createHash('sha256').update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })).digest('base64url');
    const srv: Server = createServer((req, res) => {
      const proof = String(req.headers.dpop || '');
      const [h, p, sig] = proof.split('.');
      const header = JSON.parse(Buffer.from(h, 'base64url').toString());
      const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
      const ok = verifySig('sha256', Buffer.from(`${h}.${p}`), { key: createPublicKey({ key: header.jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, Buffer.from(sig, 'base64url'));
      seen.push({ path: req.url || '', header, payload, jkt: thumb(header.jwk) });
      res.setHeader('Content-Type', 'application/json');
      if (!ok) { res.statusCode = 400; return res.end(JSON.stringify({ error: 'invalid_dpop_proof' })); }
      const jag = `${Buffer.from('{"typ":"oauth-id-jag+jwt","alg":"RS256"}').toString('base64url')}.${Buffer.from(JSON.stringify({ cnf: { jkt: thumb(header.jwk) } })).toString('base64url')}.sig`;
      res.end(JSON.stringify(req.url === '/idp/token?x=1'
        ? { access_token: jag, issued_token_type: 'urn:ietf:params:oauth:token-type:id-jag', token_type: 'N_A' }
        : { access_token: 'at', token_type: 'DPoP' }));
    });
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()));
    const local = `http://127.0.0.1:${(srv.address() as any).port}`;
    try {
      const key = createIdJagDpopKey();
      const got = await requestIdJag({ tokenEndpoint: `${local}/idp/token?x=1`, clientId: 'tqapp_test', clientSecret: 'tqs_test', idToken: 'idtoken:ada', audience: 'https://rs.example', dpopKey: key });
      expect(got.dpopBound).toBe(true);
      expect(await redeemIdJag({ tokenEndpoint: `${local}/rs/token`, clientId: 'acme-at-rs', assertion: got.assertion, dpopKey: key })).toMatchObject({ token_type: 'DPoP' });
      expect(seen).toHaveLength(2);
      expect(seen[0]).toMatchObject({ header: { typ: 'dpop+jwt', alg: 'ES256' }, payload: { htm: 'POST', htu: `${local}/idp/token` }, jkt: key.thumbprint });
      expect(seen[0].header.jwk.d).toBeUndefined();
      expect(seen[1]).toMatchObject({ payload: { htm: 'POST', htu: `${local}/rs/token` }, jkt: key.thumbprint });
      expect(seen[0].payload.jti).not.toBe(seen[1].payload.jti);
    } finally {
      srv.close();
    }
    // An identity provider that ignores DPoP answers with a bearer ID-JAG: dpopBound false.
    expect((await requestIdJag({ issuer: `${base}/idp`, clientId: 'tqapp_test', clientSecret: 'tqs_test', idToken: 'idtoken:ada', audience: 'https://rs.example', dpopKey: createIdJagDpopKey() })).dpopBound).toBe(false);

    // The verifier: a bound ID-JAG needs the proof key's thumbprint, refused before it is used up.
    const verifier = new IdJagVerifier({ issuer: `${base}/idp`, audience: 'https://rs.example' });
    const bound = (await post('/__test/id-jag', { claims: { cnf: { jkt: 'right-key-thumbprint' } } })).assertion as string;
    await expect(verifier.verify(bound, { clientId: 'acme-at-rs' })).rejects.toThrow('bound to a DPoP key: a DPoP proof with that key is required');
    await expect(verifier.verify(bound, { clientId: 'acme-at-rs', dpopJkt: 'other-key' })).rejects.toThrow('the DPoP proof was made with another key');
    expect(await verifier.verify(bound, { clientId: 'acme-at-rs', dpopJkt: 'right-key-thumbprint' })).toMatchObject({ sub: expect.any(String), cnfJkt: 'right-key-thumbprint' });
    const odd = (await post('/__test/id-jag', { claims: { cnf: { x5t: 'abc' } } })).assertion as string;
    await expect(verifier.verify(odd, { clientId: 'acme-at-rs', dpopJkt: 'x' })).rejects.toThrow('unsupported confirmation method');
    // Unbound: as before, with or without a proof key.
    const plain = (await post('/__test/id-jag', { claims: {} })).assertion as string;
    expect((await verifier.verify(plain, { clientId: 'acme-at-rs', dpopJkt: 'any' })).cnfJkt).toBeUndefined();
  });
});

// A proof's header and payload, and whether its raw r||s signature verifies with the jwk in it.
const readProof = (proof: string) => {
  const [h, p, s] = proof.split('.');
  const header = JSON.parse(Buffer.from(h, 'base64url').toString());
  const sig = Buffer.from(s, 'base64url');
  const verifies = sig.length === 64 && verifySig('sha256', Buffer.from(`${h}.${p}`), { key: createPublicKey({ key: header.jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, sig);
  return { header, payload: JSON.parse(Buffer.from(p, 'base64url').toString()), verifies };
};

describe('idJagDpopProof', () => {
  test('a POST by default; method, access token (ath) and nonce when given', () => {
    const key = createIdJagDpopKey();
    const before = Math.floor(Date.now() / 1000);
    const forToken = readProof(idJagDpopProof(key, 'https://sso.touchque.com/sso/token?x=1#f'));
    expect(forToken.header).toEqual({ typ: 'dpop+jwt', alg: 'ES256', jwk: { kty: 'EC', crv: 'P-256', x: key.publicJwk.x, y: key.publicJwk.y } });
    expect([forToken.header.jwk.x.length, forToken.header.jwk.y.length]).toEqual([43, 43]);
    expect(Object.keys(forToken.payload).sort()).toEqual(['htm', 'htu', 'iat', 'jti']);
    expect(forToken.payload).toMatchObject({ htm: 'POST', htu: 'https://sso.touchque.com/sso/token' });
    expect(Number.isInteger(forToken.payload.iat) && forToken.payload.iat >= before && forToken.payload.iat <= Math.floor(Date.now() / 1000)).toBe(true);
    expect(forToken.verifies).toBe(true);

    const accessToken = `at-${Math.random().toString(36).slice(2)}`;
    const forResource = readProof(idJagDpopProof(key, 'https://API.Example.com:443/v1/files?x=1', { method: 'get', accessToken, nonce: 'n-1' }));
    expect(forResource.payload).toMatchObject({ htm: 'GET', htu: 'https://api.example.com/v1/files', nonce: 'n-1', ath: createHash('sha256').update(accessToken, 'ascii').digest('base64url') });
    expect(forResource.payload.ath).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(forResource.payload.jti).not.toBe(forToken.payload.jti);
    expect(forResource.verifies).toBe(true);
    // Only what is given: a method alone adds no ath or nonce; no options is a POST.
    expect(readProof(idJagDpopProof(key, 'https://api.example.com/v1/files', { method: 'delete' })).payload).not.toHaveProperty('ath');
    expect(readProof(idJagDpopProof(key, 'https://api.example.com/v1/files', { method: 'delete' })).payload).toMatchObject({ htm: 'DELETE' });
    expect(readProof(idJagDpopProof(key, 'https://auth.example/token', {})).payload).toMatchObject({ htm: 'POST' });
    expect(readProof(idJagDpopProof(key, 'https://auth.example/token', { nonce: 'n-2' })).payload).toMatchObject({ htm: 'POST', nonce: 'n-2' });
  });

  test('htu: scheme and host lowercased, default port dropped, "/" for an empty path, the path kept as given, no query or fragment', async () => {
    const key = createIdJagDpopKey();
    const htu = (url: string) => readProof(idJagDpopProof(key, url)).payload.htu;
    expect(htu('https://sso.touchque.com/sso/token?x=1#f')).toBe('https://sso.touchque.com/sso/token');
    expect(htu('HTTPS://API.Example.COM:443/v1/files?x=1')).toBe('https://api.example.com/v1/files');
    expect(htu('http://localhost:80/token')).toBe('http://localhost/token');
    expect(htu('https://auth.example:8443/token')).toBe('https://auth.example:8443/token');
    expect(htu('https://auth.example')).toBe('https://auth.example/');
    expect(htu('https://auth.example?x=1#f')).toBe('https://auth.example/');
    expect(htu('https://auth.example/a%2Fb/%7euser/Caf%C3%A9/A?q=1')).toBe('https://auth.example/a%2Fb/%7euser/Caf%C3%A9/A');
    expect(htu('https://user:secret@auth.example/token')).toBe('https://auth.example/token');
    expect(htu('https://[::1]:8443/token')).toBe('https://[::1]:8443/token');
    // What new URL() changes in a path ("." and ".." segments, a space) fetch changes too: htu is the path fetch sends.
    expect(htu('https://auth.example/v1/./a/../Files x/%7e')).toBe('https://auth.example/v1/Files%20x/%7e');
    const paths: string[] = [];
    const srv: Server = createServer((req, res) => { paths.push(req.url || ''); res.end(); });
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()));
    try {
      const url = `http://127.0.0.1:${(srv.address() as any).port}/v1/./a/../Files x/%7e?q=1#f`;
      await fetch(url);
      expect(htu(url)).toBe(`http://127.0.0.1:${(srv.address() as any).port}${paths[0].split('?')[0]}`);
    } finally {
      srv.close();
    }
  });

  test('method: trimmed and uppercased, blank means POST; anything but RFC 9110 token characters is a TouchqueConfigError', () => {
    const key = createIdJagDpopKey();
    const htm = (method?: string) => readProof(idJagDpopProof(key, 'https://api.example.com/v1/files', { method })).payload.htm;
    expect([htm(' get '), htm('\tpatch\n'), htm('m-search'), htm("!#$%&'*+-.^_`|~09az")]).toEqual(['GET', 'PATCH', 'M-SEARCH', "!#$%&'*+-.^_`|~09AZ"]);
    expect([htm(''), htm('   '), htm(undefined), htm(null as unknown as string)]).toEqual(['POST', 'POST', 'POST', 'POST']);
    // Checked before uppercasing: ß would become SS.
    for (const method of ['GE T', 'GET\r\nX-Y: 1', 'G"ET', 'GET,POST', '(GET)', 'GET/1', 'G\\ET', 'GÉT', 'poßt', 'get\u00a0x', 'get\u0000']) {
      expect(() => idJagDpopProof(key, 'https://api.example.com/v1/files', { method })).toThrow(TouchqueConfigError);
    }
  });

  test('url: an absolute http or https URL; anything else is a TouchqueConfigError (not a TypeError) that does not echo it', () => {
    const key = createIdJagDpopKey();
    for (const url of ['ftp://h.example/x', 'ftp://user:s3cret@h.example/x', 'file:///etc/passwd', 'ws://h.example/x', 'mailto:a@h.example', 'data:text/plain,x',
      '/token', 'token', '', ' ', 'h.example/token', '//h.example/token', 'https//h.example/x', 'not a url', 'http://', 'https://[::1/x', undefined, null]) {
      let thrown: unknown;
      try {
        idJagDpopProof(key, url as string);
      } catch (e) {
        thrown = e;
      }
      expect([url, thrown instanceof TouchqueConfigError]).toEqual([url, true]);
      expect((thrown as Error).message).not.toContain('s3cret');
    }
    expect(readProof(idJagDpopProof(key, 'HTTP://h.example/x')).payload.htu).toBe('http://h.example/x');
    expect(readProof(idJagDpopProof(key, 'https://h.example')).payload.htu).toBe('https://h.example/');
  });

  test('method: trimmed of ASCII whitespace only (space, tab, CR, LF, VT, FF), not NUL or Unicode spaces', () => {
    const key = createIdJagDpopKey();
    const htm = (method?: string) => readProof(idJagDpopProof(key, 'https://api.example.com/v1/files', { method })).payload.htm;
    expect([htm('\vget\f'), htm(' \r\n\tpatch \t\r\n'), htm('\f\v \t\r\n'), htm('\v')]).toEqual(['GET', 'PATCH', 'POST', 'POST']);
    // Unicode spaces String#trim would take (U+00A0, U+FEFF, U+2028, U+3000, U+1680, U+2000), NEL and NUL stay: not token characters.
    for (const method of ['\u00a0GET', 'GET\u00a0', '\u00a0', '\ufeffGET', 'GET\u2028', '\u3000GET', '\u1680GET', 'GET\u2000', '\u0085GET', '\u0000GET', 'GET\u0000', '\u0000']) {
      expect(() => idJagDpopProof(key, 'https://api.example.com/v1/files', { method })).toThrow(TouchqueConfigError);
    }
  });

  test('an empty or null access token or nonce is left out; a nonce is sent as given', () => {
    const key = createIdJagDpopKey();
    const payload = (options: object) => readProof(idJagDpopProof(key, 'https://api.example.com/v1/files', options as IdJagDpopProofOptions)).payload;
    for (const options of [{ accessToken: '' }, { nonce: '' }, { accessToken: '', nonce: '' }, { accessToken: null, nonce: null }, { accessToken: undefined, nonce: undefined }]) {
      expect(Object.keys(payload(options)).sort()).toEqual(['htm', 'htu', 'iat', 'jti']);
    }
    // Not checked against the nonce syntax: the caller's value as it is.
    expect(payload({ nonce: 'a b"\\' }).nonce).toBe('a b"\\');
  });

  test('the header jwk is rebuilt from the key: kty, crv, x and y, never d or other members', () => {
    // A key made by hand whose publicJwk is the private JWK with more members.
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const full = privateKey.export({ format: 'jwk' });
    expect(full.d).toEqual(expect.any(String));
    const key = { privateKey, publicJwk: { ...full, kid: 'k1', alg: 'ES256', use: 'sig', key_ops: ['sign'], ext: true }, thumbprint: 'unused' };
    for (const proof of [idJagDpopProof(key, 'https://auth.example/token'), idJagDpopProof(key, 'https://api.example.com/v1/files', { method: 'GET', accessToken: 'at', nonce: 'n-1' })]) {
      const { header, verifies } = readProof(proof);
      expect(Object.keys(header.jwk)).toEqual(['kty', 'crv', 'x', 'y']);
      expect(header.jwk).toEqual({ kty: 'EC', crv: 'P-256', x: full.x, y: full.y });
      expect(verifies).toBe(true);
    }
  });
});

type Seen = { url: string; body: string; authorization?: string; proof?: ReturnType<typeof readProof> };
// A header given as a list is sent once per value; null drops the connection without an answer.
// `raw` is a body sent as it is (not JSON-encoded).
type Reply = { status: number; headers?: Record<string, string | string[]>; body?: unknown; raw?: string };
// A token endpoint that records each request and answers what `reply` says for the nth one.
const tokenEndpoint = async (reply: (n: number, seen: Seen) => Reply | null) => {
  const seen: Seen[] = [];
  const srv: Server = createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      const got: Seen = { url: req.url || '', body, authorization: req.headers.authorization, ...(req.headers.dpop && { proof: readProof(String(req.headers.dpop)) }) };
      seen.push(got);
      const answer = reply(seen.length, got);
      if (!answer) return req.socket.destroy();
      res.writeHead(answer.status, { 'Content-Type': 'application/json', ...answer.headers });
      res.end(answer.raw ?? (answer.body === undefined ? '' : JSON.stringify(answer.body)));
    });
  });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()));
  return { seen, url: `http://127.0.0.1:${(srv.address() as any).port}`, close: () => new Promise<void>((r) => srv.close(() => r())) };
};
const askNonce = (nonce: string): Reply => ({ status: 400, headers: { 'DPoP-Nonce': nonce }, body: { error: 'use_dpop_nonce', error_description: 'Authorization server requires nonce in DPoP proof' } });
// An ID-JAG bound to the key of the request's proof.
const jagFor = (got: Seen) => {
  const jwk = got.proof?.header.jwk;
  const jkt = createHash('sha256').update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })).digest('base64url');
  return `${Buffer.from('{"typ":"oauth-id-jag+jwt","alg":"RS256"}').toString('base64url')}.${Buffer.from(JSON.stringify({ cnf: { jkt } })).toString('base64url')}.sig`;
};
const reason = (p: Promise<unknown>) => p.then(() => 'accepted', (e: IdJagError) => ({ name: e.name, code: e.code, status: e.status, dpopNonce: e.dpopNonce }));

// A token endpoint on a raw socket, for answers Node's http server will not send and fetch will not
// read (control bytes in a header, a 64 KB header line, a body cut short): the nth request gets the
// bytes `reply` returns, as they are, or null resets the connection. Each request is recorded with
// its proof's nonce.
const rawEndpoint = async (reply: (n: number) => string | null) => {
  const nonces: Array<string | undefined> = [];
  const srv = createNetServer((socket) => {
    let got = '';
    socket.on('error', () => {});
    socket.on('data', (chunk) => {
      got += chunk.toString('latin1');
      const end = got.indexOf('\r\n\r\n');
      if (end < 0 || got.length < end + 4 + Number(/\r\ncontent-length: *(\d+)/i.exec(got.slice(0, end))?.[1] || 0)) return;
      const proof = /\r\ndpop: *([^\r\n]+)/i.exec(got.slice(0, end))?.[1];
      nonces.push(proof && readProof(proof).payload.nonce);
      got = '';
      const answer = reply(nonces.length);
      if (answer === null) socket.resetAndDestroy();
      else socket.end(answer, 'latin1');
    });
  });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()));
  return { nonces, url: `http://127.0.0.1:${(srv.address() as AddressInfo).port}`, close: () => new Promise<void>((r) => srv.close(() => r())) };
};
// An HTTP/1.1 answer as bytes: the status line, the header lines as given, then Content-Length (the
// body's unless given) and Connection: close.
const rawAnswer = (status: string, headers: string[], body = '', length = body.length) => `HTTP/1.1 ${status}\r\n${[...headers, `Content-Length: ${length}`, 'Connection: close'].join('\r\n')}\r\n\r\n${body}`;
const rawAskNonce = (nonceLines: string[]) => rawAnswer('400 Bad Request', ['Content-Type: application/json', ...nonceLines], '{"error":"use_dpop_nonce"}');

describe('DPoP nonce (RFC 9449 section 8) at the token endpoint', () => {
  test('requestIdJag and redeemIdJag send the same request once more, with a new proof that carries the nonce', async () => {
    const ep = await tokenEndpoint((n, got) => {
      if (got.proof?.payload.nonce !== 'n-1') return askNonce('n-1');
      return { status: 200, body: got.url.startsWith('/idp/') ? { access_token: jagFor(got), issued_token_type: 'urn:ietf:params:oauth:token-type:id-jag', token_type: 'N_A' } : { access_token: 'at', token_type: 'DPoP' } };
    });
    try {
      const key = createIdJagDpopKey();
      const got = await requestIdJag({ tokenEndpoint: `${ep.url}/idp/token`, clientId: 'tqapp_test', clientSecret: 'tqs_test', idToken: 'idtoken:ada', audience: 'https://rs.example', dpopKey: key });
      expect(got.dpopBound).toBe(true);
      expect(await redeemIdJag({ tokenEndpoint: `${ep.url}/rs/token`, clientId: 'acme-at-rs', clientSecret: 'rs_secret', assertion: got.assertion, dpopKey: key })).toMatchObject({ token_type: 'DPoP' });
      expect(await redeemIdJag({ tokenEndpoint: `${ep.url}/rs/token`, clientId: 'acme-at-rs', assertion: got.assertion, dpopKey: key })).toMatchObject({ token_type: 'DPoP' });
      expect(ep.seen).toHaveLength(6);
      for (const [first, retry] of [[ep.seen[0], ep.seen[1]], [ep.seen[2], ep.seen[3]], [ep.seen[4], ep.seen[5]]]) {
        expect(retry.url).toBe(first.url);
        expect(retry.body).toBe(first.body);
        expect(retry.authorization).toBe(first.authorization);
        expect(first.proof!.payload).not.toHaveProperty('nonce');
        expect(retry.proof!.payload).toMatchObject({ htm: 'POST', htu: `${ep.url}${first.url}`, nonce: 'n-1' });
        expect(retry.proof!.payload.jti).not.toBe(first.proof!.payload.jti);
        expect(Number.isInteger(retry.proof!.payload.iat) && retry.proof!.payload.iat >= first.proof!.payload.iat).toBe(true);
        expect(retry.proof!.verifies && first.proof!.verifies).toBe(true);
        expect(retry.proof!.header.jwk).toEqual(key.publicJwk);
      }
      expect(ep.seen[0].authorization).toMatch(/^Basic /);
      expect(ep.seen[2].authorization).toMatch(/^Basic /);
      expect(ep.seen[4].authorization).toBeUndefined();
      expect(new URLSearchParams(ep.seen[5].body).get('client_id')).toBe('acme-at-rs');
    } finally {
      await ep.close();
    }
  });

  test('a 401 that asks only in its DPoP challenge (WWW-Authenticate) is retried too', async () => {
    const ep = await tokenEndpoint((n, got) => (got.proof?.payload.nonce === 'n-2'
      ? { status: 200, body: { access_token: 'at', token_type: 'DPoP' } }
      : { status: 401, headers: { 'WWW-Authenticate': 'DPoP algs="ES256", error="use_dpop_nonce", error_description="Authorization server requires nonce in DPoP proof"', 'DPoP-Nonce': 'n-2' } }));
    try {
      expect(await redeemIdJag({ tokenEndpoint: `${ep.url}/rs/token`, clientId: 'acme-at-rs', assertion: 'jag', dpopKey: createIdJagDpopKey() })).toMatchObject({ token_type: 'DPoP' });
      expect(ep.seen.map((s) => s.proof?.payload.nonce)).toEqual([undefined, 'n-2']);
    } finally {
      await ep.close();
    }
  });

  test('WWW-Authenticate is read as RFC 9110 challenges: only the DPoP challenge\'s own error parameter asks', async () => {
    const cases: Array<[string | string[], boolean]> = [
      ['Bearer error="use_dpop_nonce", DPoP algs="ES256"', false],
      ['DPoP error="invalid_token", error_description="send error=use_dpop_nonce"', false],
      ['DPoP error_description="a, error=use_dpop_nonce"', false],
      ['DPoP error="USE_DPOP_NONCE"', false],
      ['Basic realm="a, b", DPoP algs="ES256", error=use_dpop_nonce', true],
      ['Bearer realm="x",, dpop ERROR = "use_dpop_nonce"', true],
      ['DPoP error="use\\_dpop_nonce"', true],
      [['Bearer realm="x"', 'DPoP error="use_dpop_nonce"'], true],
      ['Bearer realm=", DPoP error=use_dpop_nonce,"', false],
      // An unclosed quoted string has no value (its closing quote escaped, or none).
      ['DPoP error="use_dpop_nonce', false],
      ['DPoP error="use_dpop_nonce\\"', false],
      ['DPoP error="use_dpop_nonce\\", Bearer realm="x"', false],
      // Exactly use_dpop_nonce: spaces and tabs around it only, not U+00A0 (sent as the byte A0).
      ['DPoP error= \tuse_dpop_nonce \t', true],
      ['DPoP error=use_dpop_nonce\u00a0', false],
      ['DPoP error=\u00a0use_dpop_nonce', false],
      ['DPoP error="use_dpop_nonce"\u00a0', false],
    ];
    let challenge: string | string[] = '';
    const ep = await tokenEndpoint((n, got): Reply => (got.proof?.payload.nonce === 'n-1'
      ? { status: 200, body: { access_token: 'at', token_type: 'DPoP' } }
      : { status: 401, headers: { 'WWW-Authenticate': challenge, 'DPoP-Nonce': 'n-1' } }));
    try {
      for (const [value, asks] of cases) {
        challenge = value;
        const before = ep.seen.length;
        const got = await reason(redeemIdJag({ tokenEndpoint: `${ep.url}/rs/token`, clientId: 'acme-at-rs', assertion: 'jag', dpopKey: createIdJagDpopKey() }));
        expect([value, ep.seen.length - before, got]).toEqual([value, asks ? 2 : 1, asks ? 'accepted' : { name: 'IdJagError', code: 'server_error', status: 401, dpopNonce: 'n-1' }]);
      }
    } finally {
      await ep.close();
    }
  });

  test('never a second retry: asked again, it throws with the latest nonce', async () => {
    const ep = await tokenEndpoint((n) => askNonce(`n-${n}`));
    try {
      const key = createIdJagDpopKey();
      expect(await reason(redeemIdJag({ tokenEndpoint: `${ep.url}/rs/token`, clientId: 'acme-at-rs', assertion: 'jag', dpopKey: key })))
        .toEqual({ name: 'IdJagError', code: 'use_dpop_nonce', status: 400, dpopNonce: 'n-2' });
      expect(ep.seen.map((s) => s.proof?.payload.nonce)).toEqual([undefined, 'n-1']);
      expect(await reason(requestIdJag({ tokenEndpoint: `${ep.url}/idp/token`, clientId: 'tqapp_test', clientSecret: 'tqs_test', idToken: 'idtoken:ada', audience: 'https://rs.example', dpopKey: key })))
        .toEqual({ name: 'IdJagError', code: 'use_dpop_nonce', status: 400, dpopNonce: 'n-4' });
      expect(ep.seen).toHaveLength(4);
    } finally {
      await ep.close();
    }
  });

  test('without a key: no DPoP header and no retry, the nonce is on the error', async () => {
    const ep = await tokenEndpoint(() => askNonce('n-1'));
    try {
      expect(await reason(requestIdJag({ tokenEndpoint: `${ep.url}/idp/token`, clientId: 'tqapp_test', clientSecret: 'tqs_test', idToken: 'idtoken:ada', audience: 'https://rs.example' })))
        .toEqual({ name: 'IdJagError', code: 'use_dpop_nonce', status: 400, dpopNonce: 'n-1' });
      expect(await reason(redeemIdJag({ tokenEndpoint: `${ep.url}/rs/token`, clientId: 'acme-at-rs', assertion: 'jag' })))
        .toEqual({ name: 'IdJagError', code: 'use_dpop_nonce', status: 400, dpopNonce: 'n-1' });
      expect(ep.seen).toHaveLength(2);
      expect(ep.seen.map((s) => s.proof)).toEqual([undefined, undefined]);
    } finally {
      await ep.close();
    }
  });

  test('no retry for another refusal, another status or a missing DPoP-Nonce header', async () => {
    const replies: Reply[] = [
      { status: 400, body: { error: 'use_dpop_nonce' } },
      { status: 400, headers: { 'DPoP-Nonce': 'n-9' }, body: { error: 'invalid_grant', error_description: 'expired' } },
      { status: 401, headers: { 'WWW-Authenticate': 'Bearer error="invalid_token"', 'DPoP-Nonce': 'n-9' } },
      { status: 403, headers: { 'DPoP-Nonce': 'n-9' }, body: { error: 'use_dpop_nonce' } },
    ];
    const ep = await tokenEndpoint((n) => replies[n - 1] || { status: 500, body: { error: 'unexpected_request' } });
    try {
      const key = createIdJagDpopKey();
      const redeem = () => reason(redeemIdJag({ tokenEndpoint: `${ep.url}/rs/token`, clientId: 'acme-at-rs', assertion: 'jag', dpopKey: key }));
      expect(await redeem()).toEqual({ name: 'IdJagError', code: 'use_dpop_nonce', status: 400, dpopNonce: undefined });
      expect(await redeem()).toEqual({ name: 'IdJagError', code: 'invalid_grant', status: 400, dpopNonce: 'n-9' });
      expect(await redeem()).toEqual({ name: 'IdJagError', code: 'server_error', status: 401, dpopNonce: 'n-9' });
      expect(await redeem()).toEqual({ name: 'IdJagError', code: 'use_dpop_nonce', status: 403, dpopNonce: 'n-9' });
      expect(ep.seen).toHaveLength(4);
    } finally {
      await ep.close();
    }
  });

  test('an answer that is JSON but not an object is an IdJagError, not a TypeError', async () => {
    const replies: Reply[] = [
      { status: 400, headers: { 'DPoP-Nonce': 'n-1' }, body: null },
      { status: 401, body: ['use_dpop_nonce'] },
      { status: 400, body: 'use_dpop_nonce' },
      { status: 200, body: null },
      { status: 200, body: null },
      { status: 200, body: 'at' },
      { status: 200, body: ['at'] },
    ];
    const ep = await tokenEndpoint((n) => replies[n - 1] || { status: 500, body: { error: 'unexpected_request' } });
    try {
      const key = createIdJagDpopKey();
      const redeem = () => redeemIdJag({ tokenEndpoint: `${ep.url}/rs/token`, clientId: 'acme-at-rs', assertion: 'jag', dpopKey: key });
      expect(await reason(redeem())).toEqual({ name: 'IdJagError', code: 'server_error', status: 400, dpopNonce: 'n-1' });
      expect(await reason(redeem())).toEqual({ name: 'IdJagError', code: 'server_error', status: 401, dpopNonce: undefined });
      expect(await reason(redeem())).toEqual({ name: 'IdJagError', code: 'server_error', status: 400, dpopNonce: undefined });
      expect(await reason(requestIdJag({ tokenEndpoint: `${ep.url}/idp/token`, clientId: 'tqapp_test', clientSecret: 'tqs_test', idToken: 'idtoken:ada', audience: 'https://rs.example', dpopKey: key })))
        .toEqual({ name: 'IdJagError', code: 'invalid_response', status: 200, dpopNonce: undefined });
      // A 2xx that is not an object: invalid_response from redeemIdJag too (it handed back the null, string or array).
      for (let i = 0; i < 3; i++) expect(await reason(redeem())).toEqual({ name: 'IdJagError', code: 'invalid_response', status: 200, dpopNonce: undefined });
      expect(ep.seen).toHaveLength(7);
    } finally {
      await ep.close();
    }
  });

  test('the error carries the latest valid DPoP-Nonce: the retry answer\'s, else the first answer\'s', async () => {
    const replies: Reply[] = [
      askNonce('n-1'), { status: 400, body: { error: 'invalid_dpop_proof' } },
      askNonce('n-2'), { status: 400, headers: { 'DPoP-Nonce': 'not a nonce' }, body: { error: 'invalid_dpop_proof' } },
      askNonce('n-3'), { status: 401, headers: { 'DPoP-Nonce': 'n-4' }, body: { error: 'invalid_client' } },
      // requestIdJag: a 200 without an ID-JAG after the retry.
      askNonce('n-5'), { status: 200, body: { token_type: 'N_A' } },
    ];
    const ep = await tokenEndpoint((n) => replies[n - 1] || { status: 500, body: { error: 'unexpected_request' } });
    try {
      const key = createIdJagDpopKey();
      const redeem = () => reason(redeemIdJag({ tokenEndpoint: `${ep.url}/rs/token`, clientId: 'acme-at-rs', assertion: 'jag', dpopKey: key }));
      expect(await redeem()).toEqual({ name: 'IdJagError', code: 'invalid_dpop_proof', status: 400, dpopNonce: 'n-1' });
      expect(await redeem()).toEqual({ name: 'IdJagError', code: 'invalid_dpop_proof', status: 400, dpopNonce: 'n-2' });
      expect(await redeem()).toEqual({ name: 'IdJagError', code: 'invalid_client', status: 401, dpopNonce: 'n-4' });
      expect(await reason(requestIdJag({ tokenEndpoint: `${ep.url}/idp/token`, clientId: 'tqapp_test', clientSecret: 'tqs_test', idToken: 'idtoken:ada', audience: 'https://rs.example', dpopKey: key })))
        .toEqual({ name: 'IdJagError', code: 'invalid_response', status: undefined, dpopNonce: 'n-5' });
      expect(ep.seen.map((s) => s.proof?.payload.nonce)).toEqual([undefined, 'n-1', undefined, 'n-2', undefined, 'n-3', undefined, 'n-5']);
    } finally {
      await ep.close();
    }
  });

  test('no retry, and no nonce on the error, unless DPoP-Nonce is one valid nonce (1*NQCHAR)', async () => {
    // Empty, a space, a double quote, a backslash, a byte above ~, and the header twice with different values (fetch reads "a, b").
    const invalid: Array<string | string[]> = ['', 'n 1', 'n"1', 'n\\1', 'nö', ['n-1', 'n-2']];
    const ep = await tokenEndpoint((n): Reply => (n <= invalid.length
      ? { status: 400, headers: { 'DPoP-Nonce': invalid[n - 1] }, body: { error: 'use_dpop_nonce' } }
      : { status: 401, headers: { 'WWW-Authenticate': 'DPoP error="use_dpop_nonce"', 'DPoP-Nonce': 'n 9' } }));
    try {
      const key = createIdJagDpopKey();
      for (let i = 0; i <= invalid.length; i++) {
        expect(await reason(redeemIdJag({ tokenEndpoint: `${ep.url}/rs/token`, clientId: 'acme-at-rs', assertion: 'jag', dpopKey: key })))
          .toEqual({ name: 'IdJagError', code: i < invalid.length ? 'use_dpop_nonce' : 'server_error', status: i < invalid.length ? 400 : 401, dpopNonce: undefined });
      }
      expect(ep.seen).toHaveLength(invalid.length + 1);
    } finally {
      await ep.close();
    }
    // Every NQCHAR (printable ASCII but space, " and \) is a valid nonce: retried with it.
    const all = Array.from({ length: 0x7e - 0x21 + 1 }, (_, i) => String.fromCharCode(0x21 + i)).filter((c) => c !== '"' && c !== '\\').join('');
    const ok = await tokenEndpoint((n, got) => (got.proof?.payload.nonce === all ? { status: 200, body: { access_token: 'at', token_type: 'DPoP' } } : askNonce(all)));
    try {
      expect(await redeemIdJag({ tokenEndpoint: `${ok.url}/rs/token`, clientId: 'acme-at-rs', assertion: 'jag', dpopKey: createIdJagDpopKey() })).toMatchObject({ token_type: 'DPoP' });
      expect(ok.seen.map((s) => s.proof?.payload.nonce)).toEqual([undefined, all]);
    } finally {
      await ok.close();
    }
  });

  test('a token endpoint that cannot be reached or read is an IdJagError temporarily_unavailable', async () => {
    const gone: Server = createServer();
    await new Promise<void>((r) => gone.listen(0, '127.0.0.1', () => r()));
    const port = (gone.address() as any).port;
    await new Promise<void>((r) => gone.close(() => r()));
    const refused = await redeemIdJag({ tokenEndpoint: `http://127.0.0.1:${port}/rs/token`, clientId: 'acme-at-rs', assertion: 'jag' }).catch((e) => e);
    expect(refused).toBeInstanceOf(IdJagError);
    expect(refused).toMatchObject({ code: 'temporarily_unavailable', status: undefined, dpopNonce: undefined });
    expect(refused.cause).toBeInstanceOf(Error);
    // The retry's connection dropped: the first answer's nonce stays on the error.
    const ep = await tokenEndpoint((n) => (n === 1 ? askNonce('n-1') : null));
    try {
      expect(await reason(redeemIdJag({ tokenEndpoint: `${ep.url}/rs/token`, clientId: 'acme-at-rs', assertion: 'jag', dpopKey: createIdJagDpopKey() })))
        .toEqual({ name: 'IdJagError', code: 'temporarily_unavailable', status: undefined, dpopNonce: 'n-1' });
      expect(ep.seen).toHaveLength(2);
    } finally {
      await ep.close();
    }
  });

  test('a 64 KB WWW-Authenticate or DPoP-Nonce: the normal result or an IdJagError, well under a second', async () => {
    const quoted = `DPoP error_description="${'a'.repeat(65536)}"`;
    const list = `DPoP ${'a,'.repeat(30000)}`;
    const asking = `${quoted}, error="use_dpop_nonce"`; // the DPoP challenge's error after the long parameter
    const longNonce = 'n'.repeat(65536);
    const timed = async (call: () => Promise<unknown>) => {
      const started = performance.now();
      const result = await call().catch((e) => e);
      return { result, ms: performance.now() - started };
    };
    const tokens = { access_token: 'at', token_type: 'Bearer' };
    const jag = { access_token: 'h.p.s', issued_token_type: 'urn:ietf:params:oauth:token-type:id-jag', token_type: 'N_A' };
    // As the server sent them: fetch itself (not this SDK) refuses headers over its limit, 16 KB by default.
    const answers: Reply[] = [];
    const ep = await tokenEndpoint(() => answers.shift() || { status: 500, body: { error: 'unexpected_request' } });
    try {
      for (const challenge of [quoted, list]) {
        for (const withKey of [false, true]) {
          answers.push(withKey ? { status: 401, headers: { 'WWW-Authenticate': challenge, 'DPoP-Nonce': 'n-1' } } : { status: 200, headers: { 'WWW-Authenticate': challenge }, body: tokens });
          const { result, ms } = await timed(() => redeemIdJag({ tokenEndpoint: `${ep.url}/rs/token`, clientId: 'acme-at-rs', assertion: 'jag', ...(withKey && { dpopKey: createIdJagDpopKey() }) }));
          expect(result instanceof IdJagError || (!withKey && JSON.stringify(result) === JSON.stringify(tokens))).toBe(true);
          expect(ms).toBeLessThan(500);
        }
      }
    } finally {
      await ep.close();
    }
    // The same answers handed to the SDK as they are, so these headers reach its parsing.
    const sent: Array<string | undefined> = [];
    const queue: Array<() => Response> = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (_url: unknown, init?: { headers?: Record<string, string> }) => {
      sent.push(init?.headers?.DPoP && readProof(init.headers.DPoP).payload.nonce);
      return (queue.shift() || (() => Response.json({ error: 'unexpected_request' }, { status: 500 })))();
    }) as typeof fetch;
    const answer = (status: number, headers: Record<string, string>, body: unknown = {}) => () => Response.json(body, { status, headers });
    const redeem = (dpopKey?: ReturnType<typeof createIdJagDpopKey>) => timed(() => redeemIdJag({ tokenEndpoint: 'https://auth.example/token', clientId: 'acme', assertion: 'jag', dpopKey }));
    try {
      const key = createIdJagDpopKey();
      for (const challenge of [quoted, list]) {
        // A 200 without a key: the normal result.
        queue.push(answer(200, { 'WWW-Authenticate': challenge }, tokens));
        let r = await redeem();
        expect([r.result, r.ms < 500]).toEqual([tokens, true]);
        queue.push(answer(200, { 'WWW-Authenticate': challenge }, jag));
        r = await timed(() => requestIdJag({ tokenEndpoint: 'https://sso.example/token', clientId: 'tqapp_test', clientSecret: 'tqs_test', idToken: 'idtoken:ada', audience: 'https://rs.example' }));
        expect([r.result, r.ms < 500]).toEqual([{ assertion: 'h.p.s' }, true]);
        // A 401 with a key and a nonce: no DPoP challenge with use_dpop_nonce, so no retry.
        queue.push(answer(401, { 'WWW-Authenticate': challenge, 'DPoP-Nonce': 'n-1' }));
        r = await redeem(key);
        expect([r.result instanceof IdJagError && { code: r.result.code, status: r.result.status, dpopNonce: r.result.dpopNonce }, r.ms < 500])
          .toEqual([{ code: 'server_error', status: 401, dpopNonce: 'n-1' }, true]);
      }
      // A 64 KB challenge that does ask, and a 64 KB valid nonce: one retry that carries it.
      queue.push(answer(401, { 'WWW-Authenticate': asking, 'DPoP-Nonce': longNonce }), answer(200, {}, tokens));
      let r = await redeem(key);
      expect([r.result, r.ms < 500]).toEqual([tokens, true]);
      // A 64 KB nonce that is not valid (a space at its end): no retry, not on the error.
      queue.push(answer(401, { 'WWW-Authenticate': asking, 'DPoP-Nonce': `${'n'.repeat(65535)} x` }));
      r = await redeem(key);
      expect([r.result instanceof IdJagError && { code: r.result.code, dpopNonce: r.result.dpopNonce }, r.ms < 500]).toEqual([{ code: 'server_error', dpopNonce: undefined }, true]);
      expect(sent).toEqual([undefined, undefined, undefined, undefined, undefined, undefined, undefined, longNonce, undefined]);
    } finally {
      globalThis.fetch = realFetch;
    }
  });
});

describe('token endpoint answers: only a 2xx JSON object is a success', () => {
  const request = (url: string, dpopKey?: ReturnType<typeof createIdJagDpopKey>) => requestIdJag({ tokenEndpoint: `${url}/idp/token`, clientId: 'tqapp_test', clientSecret: 'tqs_test', idToken: 'idtoken:ada', audience: 'https://rs.example', dpopKey });
  const redeem = (url: string, dpopKey?: ReturnType<typeof createIdJagDpopKey>) => redeemIdJag({ tokenEndpoint: `${url}/rs/token`, clientId: 'acme-at-rs', assertion: 'jag', dpopKey });
  // The error as fields, with whether fetch's (or the body read's) error is kept as its cause.
  const failure = (p: Promise<unknown>) => p.then(() => 'accepted', (e: IdJagError & { cause?: unknown }) => ({ name: e.name, code: e.code, status: e.status, dpopNonce: e.dpopNonce, cause: e.cause instanceof Error }));
  const unavailable = (dpopNonce?: string) => ({ name: 'IdJagError', code: 'temporarily_unavailable', status: undefined, dpopNonce, cause: true });

  test('a redirect (3xx) is an IdJagError with its status and nonce, never followed', async () => {
    const tokens = { access_token: 'at', token_type: 'Bearer' };
    // Each redirect points to /elsewhere on this server, which would answer tokens if it were followed.
    const moved =(status: number, body: unknown = tokens): Reply => ({ status, headers: { Location: '/elsewhere', 'DPoP-Nonce': 'n-3' }, body });
    let next: Reply[] = [];
    const ep = await tokenEndpoint((n, got) => (got.url === '/elsewhere' ? { status: 200, body: tokens } : next.shift() || { status: 500, body: { error: 'unexpected_request' } }));
    try {
      const key = createIdJagDpopKey();
      for (const status of [301, 302, 303, 307, 308]) {
        next = [moved(status)];
        expect(await reason(redeem(ep.url, key))).toEqual({ name: 'IdJagError', code: 'server_error', status, dpopNonce: 'n-3' });
      }
      // The body's error is the code; requestIdJag the same.
      next = [moved(302, { error: 'moved_here' })];
      expect(await reason(redeem(ep.url))).toEqual({ name: 'IdJagError', code: 'moved_here', status: 302, dpopNonce: 'n-3' });
      next = [moved(307)];
      expect(await reason(request(ep.url, key))).toEqual({ name: 'IdJagError', code: 'server_error', status: 307, dpopNonce: 'n-3' });
      expect(ep.seen.map((s) => s.url)).toEqual([...Array(6).fill('/rs/token'), '/idp/token']);
    } finally {
      await ep.close();
    }
  });

  test('the code is the body\'s error only when it is an RFC 6749 error code of at most 128 characters, else server_error', async () => {
    const cases: Array<[unknown, string]> = [
      ['invalid_grant', 'invalid_grant'], ['with space !#[]~', 'with space !#[]~'], ['a'.repeat(128), 'a'.repeat(128)],
      ['a'.repeat(129), 'server_error'], ['', 'server_error'], ['bad"quote', 'server_error'], ['back\\slash', 'server_error'], ['tab\there', 'server_error'],
      ['new\nline', 'server_error'], ['caf\u00e9', 'server_error'], ['\u0000', 'server_error'], [5, 'server_error'], [true, 'server_error'], [null, 'server_error'],
      [['invalid_grant'], 'server_error'], [{ toString: 1 }, 'server_error'],
    ];
    let next: Reply = { status: 400 };
    const ep = await tokenEndpoint(() => next);
    try {
      for (const [error, code] of cases) {
        next = { status: 400, body: { error } };
        expect([error, await reason(redeem(ep.url))]).toEqual([error, { name: 'IdJagError', code, status: 400, dpopNonce: undefined }]);
      }
      // An error_description that is not a string is not the message (an object with toString: 1 threw a TypeError).
      next = { status: 400, body: { error: { toString: 1 }, error_description: { toString: 1 } } };
      const thrown = await redeem(ep.url).catch((e) => e);
      expect([thrown.name, thrown.code, thrown.message]).toEqual(['IdJagError', 'server_error', `${ep.url}/rs/token answered 400`]);
      next = { status: 400, body: { error: 'invalid_grant', error_description: 'expired' } };
      expect((await redeem(ep.url).catch((e) => e)).message).toBe('expired');
      // Never from WWW-Authenticate, which only decides the retry.
      next = { status: 401, headers: { 'WWW-Authenticate': 'DPoP error="invalid_dpop_proof"', 'DPoP-Nonce': 'n-1' } };
      expect(await reason(redeem(ep.url, createIdJagDpopKey()))).toEqual({ name: 'IdJagError', code: 'server_error', status: 401, dpopNonce: 'n-1' });
      // Every status outside 2xx, the same way.
      for (const status of [404, 418, 500, 503]) {
        next = { status, body: { error: 'invalid_request' } };
        expect(await reason(redeem(ep.url))).toEqual({ name: 'IdJagError', code: 'invalid_request', status, dpopNonce: undefined });
      }
    } finally {
      await ep.close();
    }
  });

  test('a 2xx that is not a JSON object is invalid_response with its status and the latest nonce, from both calls', async () => {
    // JSON null, a string, a number, true, an array, not JSON, an empty body.
    const bodies = ['null', '"at"', '5', 'true', '["at"]', '<html>hi</html>', ''];
    let next: Reply[] = [];
    const ep = await tokenEndpoint(() => next.shift() || { status: 500, body: { error: 'unexpected_request' } });
    try {
      const key = createIdJagDpopKey();
      for (const raw of bodies) {
        for (const [call, status] of [[redeem, 200], [request, 201]] as const) {
          next = [{ status, headers: { 'DPoP-Nonce': 'n-5' }, raw }];
          expect([raw, await reason(call(ep.url, key))]).toEqual([raw, { name: 'IdJagError', code: 'invalid_response', status, dpopNonce: 'n-5' }]);
        }
      }
      // After the nonce retry, the first answer's nonce when the 2xx has none.
      for (const call of [redeem, request]) {
        next = [askNonce('n-1'), { status: 200, raw: 'null' }];
        expect(await reason(call(ep.url, key))).toEqual({ name: 'IdJagError', code: 'invalid_response', status: 200, dpopNonce: 'n-1' });
      }
      // A JSON object is the answer, as before.
      next = [{ status: 200, raw: '{"access_token":"at","token_type":"Bearer"}' }];
      expect(await redeem(ep.url, key)).toEqual({ access_token: 'at', token_type: 'Bearer' });
    } finally {
      await ep.close();
    }
  });

  test('not reached or not read (raw socket): temporarily_unavailable, no status, fetch\'s error as the cause, the latest nonce', async () => {
    // A port nothing listens on.
    const gone = createNetServer();
    await new Promise<void>((r) => gone.listen(0, '127.0.0.1', () => r()));
    const closed = `http://127.0.0.1:${(gone.address() as AddressInfo).port}`;
    await new Promise<void>((r) => gone.close(() => r()));
    expect(await failure(redeem(closed, createIdJagDpopKey()))).toEqual(unavailable());
    expect(await failure(request(closed))).toEqual(unavailable());

    const json = 'Content-Type: application/json';
    const tooLong = `X-Long: ${'a'.repeat(65536)}`;
    const answers: Array<string | null> = [];
    const ep = await rawEndpoint(() => (answers.length ? answers.shift()! : rawAnswer('500 Internal Server Error', [json], '{"error":"unexpected_request"}')));
    try {
      const key = createIdJagDpopKey();
      const cases: Array<[string, Array<string | null>, string | undefined]> = [
        // On the first request: reset, control bytes in a header (fetch refuses them), a 64 KB header line, a body cut short.
        ['reset', [null], undefined],
        ['control byte', [rawAnswer('200 OK', [json, 'X-Odd: a\u0001b'], '{}')], undefined],
        ['NUL byte', [rawAnswer('400 Bad Request', [json, 'DPoP-Nonce: n\u00001'], '{"error":"use_dpop_nonce"}')], undefined],
        ['64 KB header', [rawAnswer('200 OK', [json, tooLong], '{}')], undefined],
        ['200 cut short', [rawAnswer('200 OK', [json, 'DPoP-Nonce: n-7'], '{"access_tok', 100)], 'n-7'],
        ['400 cut short', [rawAnswer('400 Bad Request', [json], '{"error":"inv', 100)], undefined],
        // On the nonce retry: the first answer's nonce, or the retry answer's when it had a valid one.
        ['retry reset', [rawAskNonce(['DPoP-Nonce: n-1']), null], 'n-1'],
        ['retry control byte', [rawAskNonce(['DPoP-Nonce: n-1']), rawAnswer('400 Bad Request', [json, 'DPoP-Nonce: n-2\u007f'], '{}')], 'n-1'],
        ['retry 64 KB header', [rawAskNonce(['DPoP-Nonce: n-1']), rawAnswer('200 OK', [json, 'DPoP-Nonce: n-2', tooLong], '{}')], 'n-1'],
        ['retry cut short', [rawAskNonce(['DPoP-Nonce: n-1']), rawAnswer('200 OK', [json, 'DPoP-Nonce: n-2'], '{"a', 50)], 'n-2'],
        ['retry cut short, nonce invalid', [rawAskNonce(['DPoP-Nonce: n-1']), rawAnswer('200 OK', [json, 'DPoP-Nonce: n 2'], '{"a', 50)], 'n-1'],
      ];
      for (const [name, sent, dpopNonce] of cases) {
        for (const call of [redeem, request]) {
          answers.push(...sent);
          const before = ep.nonces.length;
          expect([name, await failure(call(ep.url, key))]).toEqual([name, unavailable(dpopNonce)]);
          expect([name, ep.nonces.length - before]).toEqual([name, sent.length]);
        }
      }
      // The retry carried the first answer's nonce.
      expect(ep.nonces.filter((n) => n !== undefined).every((n) => n === 'n-1')).toBe(true);
    } finally {
      await ep.close();
    }
  });

  test('DPoP-Nonce sent more than once: one nonce only when every value is the same valid nonce', async () => {
    // [the DPoP-Nonce header lines, the nonce the retry carries or undefined for no retry]
    const cases: Array<[string[], string | undefined]> = [
      [['n-1', 'n-1'], 'n-1'],
      [['n-1', 'n-1', 'n-1'], 'n-1'],
      // Spaces and tabs around a value are not part of it (fetch keeps those after a value).
      [['n-1 ', 'n-1\t'], 'n-1'],
      [['n-1 '], 'n-1'],
      // One line: "n-1,n-1" is one valid nonce; "n-1, n-1" reads as fetch's join of two lines.
      [['n-1,n-1'], 'n-1,n-1'],
      [['n-1, n-1'], 'n-1'],
      [['n-1', 'n-2'], undefined],
      [['n-1', 'n-1', 'n-2'], undefined],
      [['n-1', ''], undefined],
      [['', 'n-1'], undefined],
      [['a b', 'a b'], undefined],
      [['n-1, '], undefined],
    ];
    const answers: string[] = [];
    const ep = await rawEndpoint(() => answers.shift() ?? rawAnswer('400 Bad Request', ['Content-Type: application/json'], '{"error":"invalid_dpop_proof"}'));
    try {
      const key = createIdJagDpopKey();
      for (const [lines, retried] of cases) {
        answers.push(rawAskNonce(lines.map((v) => `DPoP-Nonce: ${v}`)));
        const before = ep.nonces.length;
        const got = await reason(redeem(ep.url, key));
        expect([lines, ep.nonces.slice(before)]).toEqual([lines, retried === undefined ? [undefined] : [undefined, retried]]);
        expect([lines, got]).toEqual([lines, { name: 'IdJagError', code: retried === undefined ? 'use_dpop_nonce' : 'invalid_dpop_proof', status: 400, dpopNonce: retried }]);
      }
      // On the retry's answer: the same value twice is its nonce; different values leave the first answer's.
      answers.push(rawAskNonce(['DPoP-Nonce: n-1']), rawAnswer('400 Bad Request', ['DPoP-Nonce: n-2', 'DPoP-Nonce: n-2'], '{"error":"invalid_dpop_proof"}'));
      expect(await reason(redeem(ep.url, key))).toEqual({ name: 'IdJagError', code: 'invalid_dpop_proof', status: 400, dpopNonce: 'n-2' });
      answers.push(rawAskNonce(['DPoP-Nonce: n-1']), rawAnswer('400 Bad Request', ['DPoP-Nonce: n-2', 'DPoP-Nonce: n-3'], '{"error":"invalid_dpop_proof"}'));
      expect(await reason(redeem(ep.url, key))).toEqual({ name: 'IdJagError', code: 'invalid_dpop_proof', status: 400, dpopNonce: 'n-1' });
      // Without a key, the same rule decides the nonce on the error.
      answers.push(rawAskNonce(['DPoP-Nonce: n-1', 'DPoP-Nonce: n-1']), rawAskNonce(['DPoP-Nonce: n-1', 'DPoP-Nonce: n-2']));
      expect([await reason(redeem(ep.url)), await reason(redeem(ep.url))]).toEqual([
        { name: 'IdJagError', code: 'use_dpop_nonce', status: 400, dpopNonce: 'n-1' },
        { name: 'IdJagError', code: 'use_dpop_nonce', status: 400, dpopNonce: undefined },
      ]);
    } finally {
      await ep.close();
    }
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
