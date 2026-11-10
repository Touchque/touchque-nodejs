// Shared Signals SETs: the cross-SDK vectors (fixtures/security-event-vectors.json),
// discovery through /.well-known/ssf-configuration, and a poll (RFC 8936).
import { describe, test, expect, afterAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { resolve } from 'node:path';
import { SecurityEventVerifier, SecurityEventError, pollSecurityEvents, SECURITY_EVENT_TYPES } from './index';

const V = JSON.parse(readFileSync(resolve(__dirname, '../fixtures/security-event-vectors.json'), 'utf8'));
const pinned = () => new SecurityEventVerifier({ issuer: V.issuer, audience: V.audience, jwks: V.jwks });

describe('SecurityEventVerifier (vectors)', () => {
  for (const v of V.valid as Array<{ name: string; token: string; expect: unknown }>) {
    test(`reads ${v.name}`, async () => {
      expect(await pinned().verify(v.token)).toEqual(v.expect);
    });
  }
  for (const v of V.invalid as Array<{ name: string; token: string; error: string }>) {
    test(`refuses ${v.name}`, async () => {
      const err = await pinned().verify(v.token).catch((e) => e);
      expect(err).toBeInstanceOf(SecurityEventError);
      expect(err.code).toBe(v.error);
    });
  }
  test('the short names TouchQue sends', () => {
    expect(SECURITY_EVENT_TYPES['session-revoked']).toBe('https://schemas.openid.net/secevent/caep/event-type/session-revoked');
  });
});

describe('keys from the transmitter, and a poll', () => {
  let server: Server;
  let polled: { auth?: string; body?: Record<string, unknown> } = {};
  const listen = () => new Promise<string>((r) => {
    server = createServer((req, res) => {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
        if (req.url === '/.well-known/ssf-configuration') return res.end(JSON.stringify({ issuer: base, jwks_uri: `${base}/jwks` }));
        if (req.url === '/jwks') return res.end(JSON.stringify(V.jwks));
        polled = { auth: req.headers.authorization, body: JSON.parse(body || '{}') };
        res.setHeader('Content-Type', 'application/json');
        return res.end(JSON.stringify({ sets: { [V.valid[0].expect.jti]: V.valid[0].token }, moreAvailable: false }));
      });
    }).listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${(server.address() as { port: number }).port}`));
  });
  afterAll(() => server?.close());

  test('discovers the JWKS and checks the issuer the SET names', async () => {
    const base = await listen();
    const verifier = new SecurityEventVerifier({ issuer: base, audience: V.audience });
    // The vectors' issuer is not this one: the signature verifies, the issuer does not.
    expect((await verifier.verify(V.valid[0].token).catch((e) => e)).code).toBe('invalid_issuer');
    const out = await pollSecurityEvents({ url: `${base}/ssf/poll/s1`, token: 'tqssf_x', ack: ['a'], maxEvents: 5 });
    expect(out.sets[V.valid[0].expect.jti]).toBe(V.valid[0].token);
    expect(polled).toEqual({ auth: 'Bearer tqssf_x', body: { ack: ['a'], maxEvents: 5 } });
  });
});
