// src/agentCard.ts
// A2A agent card signatures (A2A 1.0 §8.4): before your agent trusts another
// agent's card (its name, URL, skills), check that whoever controls its keys
// signed exactly this card. Each entry of `signatures` is a JWS (RFC 7515)
// over the card in RFC 8785 canonical form without `signatures`; the
// protected header names alg, kid and optionally jku (where the keys are).
//
//   const card = await fetch('https://agent.example/.well-known/agent-card.json').then((r) => r.json());
//   await verifyAgentCard(card, { cardUrl: 'https://agent.example/.well-known/agent-card.json' });
//
// Keys come from `keys` (a JWKS you trust) or from the header's jku, but jku
// is only followed on the card's own host (or a host in trustedJkuHosts):
// a card that points at keys on a host of its choosing proves nothing.
// Signers must leave out fields at their default values (A2A §8.4.1); the
// card is checked as received.

import * as crypto from 'crypto';
import { ALGS, b64urlJson, getJson, keyOf, safeUrl, verifyJws, type Jwk } from './jwsKeys';

export class AgentCardError extends Error {
  /** unsigned | malformed | untrusted_key | invalid_signature | keys_unavailable */
  constructor(public readonly code: string, message: string) {
    super(message);
    this.name = 'AgentCardError';
  }
}

export interface VerifyAgentCardOptions {
  /** Where the card was fetched from: its host is the one jku may point at. */
  cardUrl?: string;
  /** A JWKS (or its keys) you trust for this agent; checked before any jku. */
  keys?: Jwk[] | { keys: Jwk[] };
  /** Other hosts a jku may point at (e.g. the publisher's key host). */
  trustedJkuHosts?: string[];
}

export interface AgentCardVerification {
  kid: string;
  alg: string;
  keySource: 'keys' | 'jku';
}

/** RFC 8785 (JSON Canonicalization Scheme): sorted keys (UTF-16 order), no whitespace, ECMAScript numbers. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new AgentCardError('malformed', 'a number is not finite');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    const o = value as Record<string, unknown>;
    return `{${Object.keys(o).filter((k) => o[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`).join(',')}}`;
  }
  throw new AgentCardError('malformed', `cannot canonicalize ${typeof value}`);
}

function payloadOf(card: Record<string, unknown>): string {
  const { signatures, ...rest } = card;
  return Buffer.from(canonicalJson(rest), 'utf8').toString('base64url');
}

/** Checks the card's signatures; resolves with the one that verified, throws AgentCardError otherwise. */
export async function verifyAgentCard(card: Record<string, unknown> | string, options: VerifyAgentCardOptions = {}): Promise<AgentCardVerification> {
  let c: Record<string, unknown>;
  try {
    c = typeof card === 'string' ? JSON.parse(card) : card;
  } catch {
    throw new AgentCardError('malformed', 'the card is not JSON');
  }
  if (!c || typeof c !== 'object' || Array.isArray(c)) throw new AgentCardError('malformed', 'the card is not a JSON object');
  const sigs = c.signatures;
  if (!Array.isArray(sigs) || !sigs.length) throw new AgentCardError('unsigned', 'the card has no signatures');
  const given = options.keys ? (Array.isArray(options.keys) ? options.keys : options.keys.keys || []) : [];
  const cardHost = options.cardUrl ? safeUrl(options.cardUrl)?.host : undefined;
  const payload = payloadOf(c);
  let last = new AgentCardError('invalid_signature', 'no signature verifies');
  for (const s of sigs as Array<Record<string, unknown>>) {
    if (!s || typeof s.protected !== 'string' || typeof s.signature !== 'string') continue;
    let head: Record<string, unknown>;
    try {
      head = b64urlJson(s.protected);
    } catch {
      continue;
    }
    const alg = String(head.alg);
    if (!ALGS.includes(alg) || typeof head.kid !== 'string' || head.crit !== undefined) continue;
    if (head.typ !== undefined && head.typ !== 'JOSE') continue;
    let jwk = given.find((k) => k.kid === head.kid);
    let source: 'keys' | 'jku' = 'keys';
    if (!jwk && typeof head.jku === 'string') {
      const jku = safeUrl(head.jku);
      const trusted = jku && ((cardHost && jku.host === cardHost) || (options.trustedJkuHosts || []).includes(jku.host));
      if (!trusted) {
        last = new AgentCardError('untrusted_key', `jku ${head.jku} is not on the card's host`);
        continue;
      }
      try {
        const set = await getJson(jku.toString()) as { keys?: Jwk[] };
        jwk = (set.keys || []).find((k) => k.kid === head.kid);
      } catch (err) {
        last = new AgentCardError('keys_unavailable', `the keys at ${head.jku} could not be read: ${(err as Error).message}`);
        continue;
      }
      source = 'jku';
    }
    if (!jwk) {
      if (last.code === 'invalid_signature') last = new AgentCardError('untrusted_key', `no trusted key ${head.kid}`);
      continue;
    }
    let key: crypto.KeyObject;
    try {
      key = keyOf(jwk);
    } catch {
      continue;
    }
    if (verifyJws(`${s.protected}.${payload}`, Buffer.from(s.signature, 'base64url'), alg, key)) return { kid: head.kid, alg, keySource: source };
    last = new AgentCardError('invalid_signature', 'the signature does not match the card');
  }
  throw last;
}

/** Signs a card you publish (A2A 1.0 §8.4): returns it with one more entry in `signatures`. */
export function signAgentCard(card: Record<string, unknown>, privateKey: crypto.KeyObject, options: { kid: string; jku?: string }): Record<string, unknown> {
  const type = privateKey.asymmetricKeyType;
  const alg = type === 'ec' ? 'ES256' : type === 'ed25519' ? 'EdDSA' : type === 'rsa' ? 'RS256' : null;
  if (!alg) throw new AgentCardError('malformed', 'the key must be EC P-256, Ed25519 or RSA');
  const protectedHeader = Buffer.from(JSON.stringify({ alg, typ: 'JOSE', kid: options.kid, ...(options.jku && { jku: options.jku }) })).toString('base64url');
  const input = Buffer.from(`${protectedHeader}.${payloadOf(card)}`);
  const sig = alg === 'ES256' ? crypto.sign('sha256', input, { key: privateKey, dsaEncoding: 'ieee-p1363' })
    : alg === 'EdDSA' ? crypto.sign(null, input, privateKey) : crypto.sign('sha256', input, privateKey);
  const prior = Array.isArray(card.signatures) ? card.signatures : [];
  return { ...card, signatures: [...prior, { protected: protectedHeader, signature: sig.toString('base64url') }] };
}
