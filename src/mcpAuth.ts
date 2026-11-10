// src/mcpAuth.ts
// For an MCP server whose authorization server is TouchQue SSO (Organization
// → MCP servers in the dashboard; issuer https://sso.touchque.com/mcp):
//
//   - serves its protected resource metadata (RFC 9728) at
//     /.well-known/oauth-protected-resource (and the path-suffixed variant), so
//     MCP clients find TouchQue and ask for a token for exactly this server;
//   - checks every request's token: signed by TouchQue (its JWKS), this issuer,
//     audience = this server's URL (RFC 8707), not expired, and, for a token
//     bound to a DPoP key, a fresh proof for this very request;
//   - answers 401 with WWW-Authenticate (resource_metadata) without a usable
//     token, and 403 insufficient_scope naming the scope a tool needs, so the
//     client asks the member for more.
//
//   const auth = new McpAuth({ issuer: 'https://sso.touchque.com/mcp', resource: 'https://mcp.acme.com/mcp',
//                              tools: { search_tickets: 'tickets:read', delete_ticket: 'tickets:delete' } });
//   app.use(auth.express());                       // req.touchqueMcp = { sub, email, clientId, scopes, … }
//   // in a tool: auth.requireTool(req.touchqueMcp, 'delete_ticket');

import * as crypto from 'crypto';
import { TouchQueConfigError } from './errors';

export interface McpAuthOptions {
  /** TouchQue SSO's MCP issuer, e.g. https://sso.touchque.com/mcp. */
  issuer: string;
  /** This MCP server's URL, exactly as registered in TouchQue. */
  resource: string;
  /** Tool name → the scope it needs (also listed as scopes_supported). */
  tools?: Record<string, string>;
  /** A human-readable name for the metadata. */
  resourceName?: string;
  /** Seconds of clock skew allowed (default 60). */
  clockSkew?: number;
}

export interface McpAuthClaims {
  /** The member the AI tool acts for. */
  sub: string;
  email?: string;
  /** The AI tool (its client ID metadata document URL). */
  clientId: string;
  scopes: string[];
  orgId?: string;
  expiresAt: number;
  dpopBound: boolean;
  claims: Record<string, unknown>;
}

export interface McpRequest {
  method: string;
  /** The full URL the client called (scheme, host, path). */
  url: string;
  headers: Record<string, string | string[] | undefined>;
}

/** A refused request: send `status` with the `WWW-Authenticate` header. */
export class McpAuthError extends Error {
  constructor(public readonly status: 401 | 403, public readonly code: string, message: string, public readonly wwwAuthenticate: string) {
    super(message);
    this.name = 'McpAuthError';
  }
}

type Jwk = crypto.JsonWebKey & { kid?: string; alg?: string };
const b64urlJson = (part: string) => JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
const header = (headers: McpRequest['headers'], name: string): string | undefined => {
  const v = headers[name] ?? headers[name.toLowerCase()] ?? Object.entries(headers).find(([k]) => k.toLowerCase() === name.toLowerCase())?.[1];
  return Array.isArray(v) ? v[0] : v;
};

function thumbprint(jwk: Jwk): string {
  const members = jwk.kty === 'EC' ? { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y } : jwk.kty === 'RSA' ? { e: jwk.e, kty: jwk.kty, n: jwk.n } : { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
  return crypto.createHash('sha256').update(JSON.stringify(members)).digest('base64url');
}

function verifyJws(input: string, sig: Buffer, alg: string, key: crypto.KeyObject): boolean {
  if (alg === 'RS256') return crypto.verify('sha256', Buffer.from(input), key, sig);
  if (alg === 'ES256') return sig.length === 64 && crypto.verify('sha256', Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' }, sig);
  if (alg === 'EdDSA') return crypto.verify(null, Buffer.from(input), key, sig);
  return false;
}

export class McpAuth {
  private readonly issuer: string;
  private readonly resource: string;
  private readonly tools: Record<string, string>;
  private readonly resourceName?: string;
  private readonly skew: number;
  private keys = new Map<string, crypto.KeyObject>();
  private keysAt = 0;
  private triedAt = 0;
  private readonly seenProofs = new Map<string, number>();

  constructor(options: McpAuthOptions) {
    if (!options?.issuer || !options?.resource) throw new TouchQueConfigError('McpAuth needs issuer (TouchQue SSO\'s MCP issuer) and resource (this server\'s URL)');
    this.issuer = options.issuer.replace(/\/+$/, '');
    this.resource = options.resource;
    this.tools = options.tools || {};
    this.resourceName = options.resourceName;
    this.skew = options.clockSkew ?? 60;
  }

  /** Where this server's protected resource metadata is served (RFC 9728 §3.1: path-suffixed and plain). */
  metadataPaths(): string[] {
    const path = new URL(this.resource).pathname.replace(/\/+$/, '');
    return ['/.well-known/oauth-protected-resource', ...(path ? [`/.well-known/oauth-protected-resource${path}`] : [])];
  }

  metadataUrl(): string {
    const u = new URL(this.resource);
    return `${u.origin}${this.metadataPaths().at(-1)}`;
  }

  /** The RFC 9728 document. */
  protectedResourceMetadata(): Record<string, unknown> {
    return {
      resource: this.resource,
      authorization_servers: [this.issuer],
      bearer_methods_supported: ['header'],
      scopes_supported: [...new Set(Object.values(this.tools))],
      dpop_signing_alg_values_supported: ['ES256', 'EdDSA'],
      ...(this.resourceName && { resource_name: this.resourceName }),
    };
  }

  private challenge(error?: string, description?: string, scope?: string): string {
    const parts = [`resource_metadata="${this.metadataUrl()}"`];
    if (error) parts.push(`error="${error}"`);
    if (description) parts.push(`error_description="${description.replace(/"/g, "'")}"`);
    if (scope) parts.push(`scope="${scope}"`);
    return `Bearer ${parts.join(', ')}`;
  }

  private fail(status: 401 | 403, code: string, message: string, scope?: string): McpAuthError {
    // No token at all: only where to find the metadata (RFC 6750 §3.1).
    const challenge = code === 'missing_token' ? this.challenge() : this.challenge(code, message, scope);
    return new McpAuthError(status, code, message, challenge);
  }

  private async loadKeys(): Promise<void> {
    const issuer = new URL(this.issuer);
    const metaUrl = `${issuer.origin}/.well-known/oauth-authorization-server${issuer.pathname.replace(/\/+$/, '')}`;
    const meta = await fetch(metaUrl).then((r) => (r.ok ? r.json() : Promise.reject(new Error(`metadata ${r.status}`)))) as { issuer?: string; jwks_uri?: string };
    if (String(meta.issuer || '').replace(/\/+$/, '') !== this.issuer || !meta.jwks_uri) throw new Error('the authorization server metadata does not match the issuer');
    const jwks = await fetch(meta.jwks_uri).then((r) => (r.ok ? r.json() : Promise.reject(new Error(`jwks ${r.status}`)))) as { keys?: Jwk[] };
    const keys = new Map<string, crypto.KeyObject>();
    for (const k of jwks.keys || []) if (k.kid) keys.set(k.kid, crypto.createPublicKey({ key: k, format: 'jwk' }));
    this.keys = keys;
    this.keysAt = Date.now();
  }

  private async keyFor(kid: string): Promise<crypto.KeyObject | undefined> {
    if (!this.keysAt || Date.now() - this.keysAt > 600000) await this.loadKeys();
    if (!this.keys.has(kid) && Date.now() - this.triedAt > 60000) {
      this.triedAt = Date.now();
      await this.loadKeys();
    }
    return this.keys.get(kid);
  }

  /** The token of a request, checked; throws McpAuthError (401 or 403). */
  async verifyRequest(req: McpRequest): Promise<McpAuthClaims> {
    const authz = header(req.headers, 'authorization') || '';
    const m = /^(Bearer|DPoP)\s+([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i.exec(authz.trim());
    if (!m) throw this.fail(401, 'missing_token', 'A TouchQue access token is required');
    const [, scheme, token] = m;
    const [h, p, s] = token.split('.');
    let head: Record<string, any>;
    let claims: Record<string, any>;
    try {
      head = b64urlJson(h);
      claims = b64urlJson(p);
    } catch {
      throw this.fail(401, 'invalid_token', 'The token is malformed');
    }
    if (head.typ !== 'at+jwt' || (head.alg !== 'RS256' && head.alg !== 'ES256')) throw this.fail(401, 'invalid_token', 'Not a TouchQue access token');
    let key: crypto.KeyObject | undefined;
    try {
      key = await this.keyFor(String(head.kid || ''));
    } catch {
      throw this.fail(401, 'invalid_token', 'The authorization server\'s keys could not be read');
    }
    if (!key || !verifyJws(`${h}.${p}`, Buffer.from(s, 'base64url'), head.alg, key)) throw this.fail(401, 'invalid_token', 'The token signature does not verify');
    const now = Math.floor(Date.now() / 1000);
    if (String(claims.iss || '').replace(/\/+$/, '') !== this.issuer) throw this.fail(401, 'invalid_token', 'The token is from another issuer');
    const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!aud.includes(this.resource)) throw this.fail(401, 'invalid_token', 'The token is for another server');
    if (typeof claims.exp !== 'number' || claims.exp + this.skew <= now) throw this.fail(401, 'invalid_token', 'The token expired');
    const jkt = claims.cnf?.jkt;
    if (jkt) {
      if (scheme.toLowerCase() !== 'dpop') throw this.fail(401, 'invalid_token', 'This token is bound to a DPoP key: send it as DPoP with a proof');
      this.checkProof(header(req.headers, 'dpop'), req, token, jkt);
    }
    return {
      sub: String(claims.sub), ...(claims.email && { email: String(claims.email) }), clientId: String(claims.client_id || ''),
      scopes: String(claims.scope || '').split(' ').filter(Boolean), ...(claims.org_id && { orgId: String(claims.org_id) }),
      expiresAt: claims.exp, dpopBound: Boolean(jkt), claims,
    };
  }

  private checkProof(proof: string | undefined, req: McpRequest, token: string, jkt: string): void {
    if (!proof) throw this.fail(401, 'invalid_token', 'A DPoP proof is required');
    try {
      const [h, p, s] = proof.split('.');
      const head = b64urlJson(h);
      const claims = b64urlJson(p);
      if (head.typ !== 'dpop+jwt' || !head.jwk || 'd' in head.jwk) throw new Error('typ');
      if (thumbprint(head.jwk) !== jkt) throw new Error('not the bound key');
      if (!verifyJws(`${h}.${p}`, Buffer.from(s, 'base64url'), head.alg, crypto.createPublicKey({ key: head.jwk, format: 'jwk' }))) throw new Error('signature');
      const u = new URL(req.url);
      if (claims.htm !== req.method.toUpperCase() || claims.htu !== `${u.protocol}//${u.host}${u.pathname}`) throw new Error('htm/htu');
      if (Math.abs(claims.iat - Date.now() / 1000) > this.skew) throw new Error('iat');
      if (claims.ath !== crypto.createHash('sha256').update(token).digest('base64url')) throw new Error('ath');
      const now = Date.now();
      for (const [k, until] of this.seenProofs) if (until < now) this.seenProofs.delete(k);
      if (!claims.jti || this.seenProofs.has(claims.jti)) throw new Error('jti used');
      this.seenProofs.set(claims.jti, now + 2 * this.skew * 1000);
    } catch (err) {
      throw this.fail(401, 'invalid_dpop_proof', `DPoP proof: ${(err as Error).message}`);
    }
  }

  /** Throws 403 insufficient_scope unless the token carries `scope`. */
  requireScope(claims: McpAuthClaims, scope: string): void {
    if (!claims.scopes.includes(scope)) throw this.fail(403, 'insufficient_scope', `This needs the ${scope} scope`, scope);
  }

  /** Throws 403 insufficient_scope unless the token carries the scope `tool` needs (from `tools`). */
  requireTool(claims: McpAuthClaims, tool: string): void {
    const scope = this.tools[tool];
    if (!scope) throw this.fail(403, 'insufficient_scope', `No scope is set for the tool ${tool}`);
    this.requireScope(claims, scope);
  }

  /** Express/Connect middleware: serves the metadata, checks the token of every other request (req.touchqueMcp). */
  express() {
    const paths = new Set(this.metadataPaths());
    const origin = new URL(this.resource).origin;
    return async (req: any, res: any, next: (err?: unknown) => void) => {
      if (req.method === 'GET' && paths.has(req.path)) return res.set('Access-Control-Allow-Origin', '*').json(this.protectedResourceMetadata());
      try {
        // htu is checked against resource's origin + the path, so it holds behind a proxy that terminates TLS.
        req.touchqueMcp = await this.verifyRequest({ method: req.method, url: `${origin}${req.originalUrl}`, headers: req.headers });
        return next();
      } catch (err) {
        if (!(err instanceof McpAuthError)) return next(err);
        res.set('WWW-Authenticate', err.wwwAuthenticate);
        return res.status(err.status).json({ error: err.code === 'missing_token' ? 'invalid_token' : err.code, error_description: err.message });
      }
    };
  }
}
