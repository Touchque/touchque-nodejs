// src/safeGuard.ts
// Safe Guard approvals, checked without trusting Touchque. The approver's phone decodes the raw
// Safe transaction itself and signs, with a P-256 key only its biometrics unlock, a 105-byte
// approval that TouchqueSafeGuard checks on chain:
//   index (1) | expiresAt (8) | displayDigest (32) | r (32) | s (32)
// over the SHA-256 of the 149-byte message
//   "TQG1" | purpose (1) | chainId (32) | guard (20) | Safe (20) | subject (32) | expiresAt (8) | displayDigest (32)
// where subject is the Safe transaction hash (EIP-712, purpose 1 "approve") or, for a change the
// guard schedules, the governance hash (purpose 2 "schedule"). verifySafeApproval() makes the
// guard's check off chain: both hashes are computed here from the raw fields, so a co-signer (or
// your own server) refuses an approval of anything else, whoever relayed it. It checks the
// purpose you name, `approve` by default: an approval to schedule a change (which leaves out the
// Safe nonce and gas) never passes as one to execute.

import { createHash, createPublicKey, verify as verifySignature, type KeyObject } from 'crypto';
import { TouchqueConfigError } from './errors';

/** A Safe transaction: the fields the owners sign (Safe v1.3+ EIP-712 `SafeTx`). */
export interface SafeTxCall {
  to: string;
  value?: string | number | bigint;
  /** 0x-prefixed hex (default `0x`). */
  data?: string;
  /** 0 call, 1 delegatecall. */
  operation?: 0 | 1;
  safeTxGas?: string | number | bigint;
  baseGas?: string | number | bigint;
  gasPrice?: string | number | bigint;
  gasToken?: string;
  refundReceiver?: string;
  nonce: string | number | bigint;
}

/** Where the transaction runs: what the approval hashes cover. */
export interface SafeTxTarget {
  chainId: string | number | bigint;
  /** The Safe's address. */
  safe: string;
  /** The TouchqueSafeGuard installed on it. */
  guard: string;
  tx: SafeTxCall;
}

/** One row the phone showed, in order. */
export interface SafeDisplayRow {
  label: string;
  value: string;
}

/** Why `verifySafeApproval` refused. */
export type SafeApprovalRefusal =
  | 'approval_malformed'
  | 'public_key_invalid'
  | 'approver_index_mismatch'
  | 'approval_expired'
  | 'rows_differ'
  | 'high_s'
  | 'signature_invalid';

export interface VerifySafeApprovalOptions {
  /**
   * What you will do with the approval: `approve` (the default) to execute the transaction,
   * `schedule` to schedule a governance change. Only that purpose is checked, so an approval to
   * schedule passes only when you name `schedule`.
   */
  purpose?: 'approve' | 'schedule';
  /** The approver's index in the guard: the approval must name it. */
  approverIndex?: number;
  /** The digest of the rows the phone must have shown (from your own decoding). */
  displayDigest?: string;
  /** Or the rows themselves; their digest is compared. */
  rows?: SafeDisplayRow[];
  /** The time to check the expiry against: a Date or Unix seconds (default: now). */
  now?: Date | number;
}

export interface SafeApprovalVerification {
  valid: boolean;
  /** Why it was refused; `null` when valid. */
  reason: SafeApprovalRefusal | null;
  /** What the signature covers: `approve` (execTransaction) or `schedule` (a governance change). */
  purpose: 'approve' | 'schedule' | null;
  approverIndex: number | null;
  /** Unix seconds. */
  expiresAt: number | null;
  /** The digest of the rows the phone showed, as signed. */
  displayDigest: string | null;
  /** Computed here from the raw fields. */
  safeTxHash: string;
  governanceHash: string;
}

const MAGIC = Buffer.from('TQG1', 'ascii');
const PURPOSES = { approve: 1, schedule: 2 } as const;
// The guard (MAX_APPROVAL_TTL) refuses an approval valid for longer than a day.
const MAX_APPROVAL_TTL = 86400n;
// OpenZeppelin P256 (the guard) refuses s above N/2.
const HALF_N = 0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8n;
const MAX_UINT256 = (1n << 256n) - 1n;
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';

// ── Keccak-256 (the Ethereum hash: Keccak padding, not SHA3-256) on 32-bit lane halves ──
const RC = [
  '0000000000000001', '0000000000008082', '800000000000808a', '8000000080008000', '000000000000808b', '0000000080000001',
  '8000000080008081', '8000000000008009', '000000000000008a', '0000000000000088', '0000000080008009', '000000008000000a',
  '000000008000808b', '800000000000008b', '8000000000008089', '8000000000008003', '8000000000008002', '8000000000000080',
  '000000000000800a', '800000008000000a', '8000000080008081', '8000000000008080', '0000000080000001', '8000000080008008',
].map((h) => [parseInt(h.slice(0, 8), 16), parseInt(h.slice(8), 16)]);
// Rotation of lane x + 5y.
const ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];

function keccakF(hi: Uint32Array, lo: Uint32Array): void {
  const cHi = new Uint32Array(5);
  const cLo = new Uint32Array(5);
  const bHi = new Uint32Array(25);
  const bLo = new Uint32Array(25);
  for (let round = 0; round < 24; round++) {
    for (let x = 0; x < 5; x++) {
      cHi[x] = hi[x] ^ hi[x + 5] ^ hi[x + 10] ^ hi[x + 15] ^ hi[x + 20];
      cLo[x] = lo[x] ^ lo[x + 5] ^ lo[x + 10] ^ lo[x + 15] ^ lo[x + 20];
    }
    for (let x = 0; x < 5; x++) {
      const nHi = cHi[(x + 1) % 5];
      const nLo = cLo[(x + 1) % 5];
      const dHi = cHi[(x + 4) % 5] ^ ((nHi << 1) | (nLo >>> 31));
      const dLo = cLo[(x + 4) % 5] ^ ((nLo << 1) | (nHi >>> 31));
      for (let y = 0; y < 25; y += 5) {
        hi[x + y] ^= dHi;
        lo[x + y] ^= dLo;
      }
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        const i = x + 5 * y;
        let h = hi[i];
        let l = lo[i];
        if (ROT[i] >= 32) [h, l] = [l, h];
        const m = ROT[i] % 32;
        if (m) [h, l] = [(h << m) | (l >>> (32 - m)), (l << m) | (h >>> (32 - m))];
        const j = y + 5 * ((2 * x + 3 * y) % 5);
        bHi[j] = h;
        bLo[j] = l;
      }
    }
    for (let y = 0; y < 25; y += 5) {
      for (let x = 0; x < 5; x++) {
        hi[x + y] = bHi[x + y] ^ (~bHi[((x + 1) % 5) + y] & bHi[((x + 2) % 5) + y]);
        lo[x + y] = bLo[x + y] ^ (~bLo[((x + 1) % 5) + y] & bLo[((x + 2) % 5) + y]);
      }
    }
    hi[0] ^= RC[round][0];
    lo[0] ^= RC[round][1];
  }
}

function keccak256(data: Uint8Array): Buffer {
  const rate = 136;
  const padded = new Uint8Array(Math.floor(data.length / rate) * rate + rate);
  padded.set(data);
  padded[data.length] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;
  const hi = new Uint32Array(25);
  const lo = new Uint32Array(25);
  for (let off = 0; off < padded.length; off += rate) {
    for (let k = 0; k < rate / 8; k++) {
      const p = off + 8 * k;
      lo[k] ^= padded[p] | (padded[p + 1] << 8) | (padded[p + 2] << 16) | (padded[p + 3] << 24);
      hi[k] ^= padded[p + 4] | (padded[p + 5] << 8) | (padded[p + 6] << 16) | (padded[p + 7] << 24);
    }
    keccakF(hi, lo);
  }
  const out = Buffer.alloc(32);
  for (let k = 0; k < 4; k++) {
    out.writeUInt32LE(lo[k], 8 * k);
    out.writeUInt32LE(hi[k], 8 * k + 4);
  }
  return out;
}

const typeHash = (s: string) => keccak256(Buffer.from(s, 'ascii'));
const DOMAIN_TYPEHASH = typeHash('EIP712Domain(uint256 chainId,address verifyingContract)');
const SAFE_TX_TYPEHASH = typeHash(
  'SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)',
);
// The type name keeps its original capital Q: the guard contract and the phone hash this exact string.
const GOVERNANCE_TYPEHASH = typeHash('TouchQueGovernance(uint256 chainId,address safe,address to,uint256 value,bytes32 dataHash,uint8 operation)');
const SCHEDULE_SELECTOR = typeHash('schedule(address,bytes32,bytes)').subarray(0, 4);

// ── Field parsing: the partner's own data, so a wrong field throws ──
function uint(value: unknown, field: string, max = MAX_UINT256): bigint {
  let v: bigint | null = null;
  if (typeof value === 'bigint') v = value;
  else if (typeof value === 'number' && Number.isSafeInteger(value)) v = BigInt(value);
  else if (typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value)) v = BigInt(value);
  if (v === null || v < 0n || v > max) throw new TouchqueConfigError(`safeGuard: ${field} must be a non-negative integer (a decimal string for large values).`);
  return v;
}

function address(value: unknown, field: string): Buffer {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(value)) throw new TouchqueConfigError(`safeGuard: ${field} must be an address (0x and 40 hex characters).`);
  return Buffer.from(value.slice(2), 'hex');
}

function hexBytes(value: unknown, field: string, size?: number): Buffer {
  if (typeof value !== 'string' || !/^0x([0-9a-fA-F]{2})*$/.test(value) || (size !== undefined && value.length !== 2 + 2 * size)) {
    throw new TouchqueConfigError(`safeGuard: ${field} must be 0x-prefixed hex${size !== undefined ? ` of ${size} bytes` : ''}.`);
  }
  return Buffer.from(value.slice(2), 'hex');
}

function word(value: bigint): Buffer {
  return Buffer.from(value.toString(16).padStart(64, '0'), 'hex');
}

const wordOf = (b: Buffer) => Buffer.concat([Buffer.alloc(32 - b.length), b]);
const hex = (b: Buffer) => `0x${b.toString('hex')}`;

function parseTarget(target: SafeTxTarget) {
  if (!target || typeof target !== 'object' || !target.tx || typeof target.tx !== 'object') {
    throw new TouchqueConfigError('safeGuard: pass { chainId, safe, guard, tx: { to, value, data, operation, …, nonce } }.');
  }
  const { tx } = target;
  const operation = tx.operation ?? 0;
  if (operation !== 0 && operation !== 1) throw new TouchqueConfigError('safeGuard: tx.operation must be 0 (call) or 1 (delegatecall).');
  return {
    chainId: uint(target.chainId, 'chainId', (1n << 64n) - 1n),
    safe: address(target.safe, 'safe'),
    guard: address(target.guard, 'guard'),
    to: address(tx.to, 'tx.to'),
    value: uint(tx.value ?? 0, 'tx.value'),
    data: hexBytes(tx.data ?? '0x', 'tx.data'),
    operation,
    safeTxGas: uint(tx.safeTxGas ?? 0, 'tx.safeTxGas'),
    baseGas: uint(tx.baseGas ?? 0, 'tx.baseGas'),
    gasPrice: uint(tx.gasPrice ?? 0, 'tx.gasPrice'),
    gasToken: address(tx.gasToken ?? ZERO_ADDRESS, 'tx.gasToken'),
    refundReceiver: address(tx.refundReceiver ?? ZERO_ADDRESS, 'tx.refundReceiver'),
    nonce: uint(tx.nonce, 'tx.nonce'),
  };
}

/** The Safe transaction hash (EIP-712, domain = chainId + the Safe): what the owners sign and an ordinary approval covers. */
export function safeTxHash(target: SafeTxTarget): string {
  const t = parseTarget(target);
  const domain = keccak256(Buffer.concat([DOMAIN_TYPEHASH, word(t.chainId), wordOf(t.safe)]));
  const struct = keccak256(Buffer.concat([
    SAFE_TX_TYPEHASH, wordOf(t.to), word(t.value), keccak256(t.data), word(BigInt(t.operation)), word(t.safeTxGas),
    word(t.baseGas), word(t.gasPrice), wordOf(t.gasToken), wordOf(t.refundReceiver), word(t.nonce),
  ]));
  return hex(keccak256(Buffer.concat([Buffer.from([0x19, 0x01]), domain, struct])));
}

/** What the guard schedules a governance change under: the change itself, without the nonce or gas fields. */
export function safeGovernanceHash(target: SafeTxTarget): string {
  const t = parseTarget(target);
  return hex(keccak256(Buffer.concat([
    GOVERNANCE_TYPEHASH, word(t.chainId), wordOf(t.safe), wordOf(t.to), word(t.value), keccak256(t.data), word(BigInt(t.operation)),
  ])));
}

/** The 149-byte message the phone signs (its SHA-256 is what the guard verifies), as 0x hex. */
export function safeApprovalMessage(fields: {
  purpose: 'approve' | 'schedule';
  chainId: string | number | bigint;
  guard: string;
  safe: string;
  subject: string;
  expiresAt: string | number | bigint;
  displayDigest: string;
}): string {
  const purpose = PURPOSES[fields.purpose];
  if (!purpose) throw new TouchqueConfigError("safeGuard: purpose is 'approve' or 'schedule'.");
  const expires = Buffer.alloc(8);
  expires.writeBigUInt64BE(uint(fields.expiresAt, 'expiresAt', (1n << 64n) - 1n));
  return hex(Buffer.concat([
    MAGIC, Buffer.from([purpose]), word(uint(fields.chainId, 'chainId', (1n << 64n) - 1n)), address(fields.guard, 'guard'),
    address(fields.safe, 'safe'), hexBytes(fields.subject, 'subject', 32), expires, hexBytes(fields.displayDigest, 'displayDigest', 32),
  ]));
}

/** SHA-256 of the rows as "label\x1Fvalue" joined by "\x1E" (UTF-8), as 0x hex: the digest an approval carries. */
export function safeDisplayDigest(rows: SafeDisplayRow[]): string {
  const canonical = rows.map((r) => `${r.label}\u001F${r.value}`).join('\u001E');
  return `0x${createHash('sha256').update(canonical, 'utf8').digest('hex')}`;
}

function publicKeyOf(key: string | { x: string; y: string }): KeyObject | null {
  const xy = typeof key === 'string' ? key.replace(/^0x/, '') : `${String(key?.x ?? '').replace(/^0x/, '')}${String(key?.y ?? '').replace(/^0x/, '')}`;
  if (!/^[0-9a-fA-F]{128}$/.test(xy)) return null;
  try {
    return createPublicKey({
      key: { kty: 'EC', crv: 'P-256', x: Buffer.from(xy.slice(0, 64), 'hex').toString('base64url'), y: Buffer.from(xy.slice(64), 'hex').toString('base64url') },
      format: 'jwk',
    });
  } catch {
    return null;
  }
}

function seconds(now: Date | number | undefined): bigint {
  if (now instanceof Date) return BigInt(Math.floor(now.getTime() / 1000));
  if (typeof now === 'number') return BigInt(Math.floor(now));
  return BigInt(Math.floor(Date.now() / 1000));
}

/**
 * Checks a phone's Safe Guard approval the way TouchqueSafeGuard does, without trusting the server
 * that relayed it: the Safe and governance hashes come from `target`, the key from the guard's
 * approver list on chain (`x || y`, 128 hex characters, or `{ x, y }`). It checks one purpose:
 * `approve` unless you pass `purpose: 'schedule'` for a governance change.
 *
 * Returns a verdict; it throws only when `target` is not a Safe transaction.
 *
 * @example
 * const { safeTx } = await tq.safeGuard.status(requestId);
 * const check = verifySafeApproval(myTx, safeTx.approval, approverKeyFromChain, { approverIndex: 0 });   // to execute
 * if (!check.valid) throw new Error(`approval refused: ${check.reason}`);
 * // A governance change: verifySafeApproval(myTx, safeTx.approval, approverKeyFromChain, { approverIndex: 0, purpose: 'schedule' })
 */
export function verifySafeApproval(
  target: SafeTxTarget,
  approval: string,
  publicKey: string | { x: string; y: string },
  options: VerifySafeApprovalOptions = {},
): SafeApprovalVerification {
  const hashes = { safeTxHash: safeTxHash(target), governanceHash: safeGovernanceHash(target) };
  const refuse = (reason: SafeApprovalRefusal, parsed?: { approverIndex: number; expiresAt: number; displayDigest: string }) => ({
    valid: false, reason, purpose: null, approverIndex: parsed?.approverIndex ?? null, expiresAt: parsed?.expiresAt ?? null,
    displayDigest: parsed?.displayDigest ?? null, ...hashes,
  });
  if (typeof approval !== 'string' || !/^(0x)?[0-9a-fA-F]{210}$/.test(approval)) return refuse('approval_malformed');
  const b = Buffer.from(approval.replace(/^0x/, ''), 'hex');
  const expiresAt = b.readBigUInt64BE(1);
  const parsed = { approverIndex: b[0], expiresAt: Number(expiresAt), displayDigest: hex(b.subarray(9, 41)) };
  const key = publicKeyOf(publicKey);
  if (!key) return refuse('public_key_invalid', parsed);
  if (options.approverIndex !== undefined && options.approverIndex !== parsed.approverIndex) return refuse('approver_index_mismatch', parsed);
  const now = seconds(options.now);
  if (expiresAt < now || expiresAt > now + MAX_APPROVAL_TTL) return refuse('approval_expired', parsed);
  const expected = options.displayDigest ?? (options.rows ? safeDisplayDigest(options.rows) : undefined);
  if (expected !== undefined && expected.toLowerCase().replace(/^(0x)?/, '0x') !== parsed.displayDigest) return refuse('rows_differ', parsed);
  if (BigInt(hex(b.subarray(73, 105))) > HALF_N) return refuse('high_s', parsed);

  const t = parseTarget(target);
  const purpose = options.purpose ?? 'approve';
  const message = safeApprovalMessage({
    purpose, chainId: t.chainId, guard: hex(t.guard), safe: hex(t.safe),
    subject: purpose === 'approve' ? hashes.safeTxHash : hashes.governanceHash, expiresAt, displayDigest: parsed.displayDigest,
  });
  if (verifySignature('sha256', Buffer.from(message.slice(2), 'hex'), { key, dsaEncoding: 'ieee-p1363' }, b.subarray(41, 105))) {
    return { valid: true, reason: null, purpose, ...parsed, ...hashes };
  }
  return refuse('signature_invalid', parsed);
}

function approvalBytes(approvals: string[]): Buffer[] {
  if (!Array.isArray(approvals) || approvals.length === 0 || approvals.length > 255) {
    throw new TouchqueConfigError('safeGuard: pass 1 to 255 approvals.');
  }
  return approvals
    .map((a, i) => hexBytes(typeof a === 'string' && !a.startsWith('0x') ? `0x${a}` : a, `approvals[${i}]`, 105))
    .sort((a, b) => a[0] - b[0]);
}

/**
 * The owners' Safe signatures with the approvals appended (approvals by index | count | "TQG1"):
 * the `signatures` argument of `execTransaction` for an ordinary transaction.
 */
export function withSafeApprovals(ownerSignatures: string, approvals: string[]): string {
  const sorted = approvalBytes(approvals);
  return hex(Buffer.concat([hexBytes(ownerSignatures, 'ownerSignatures'), ...sorted, Buffer.from([sorted.length]), MAGIC]));
}

/** The call data of `guard.schedule(safe, governanceHash, approvals)`, which starts a governance change's waiting time. */
export function safeScheduleCall(safe: string, governanceHash: string, approvals: string[]): string {
  const joined = Buffer.concat(approvalBytes(approvals));
  const padding = Buffer.alloc((32 - (joined.length % 32)) % 32);
  return hex(Buffer.concat([
    SCHEDULE_SELECTOR, wordOf(address(safe, 'safe')), hexBytes(governanceHash, 'governanceHash', 32), word(96n),
    word(BigInt(joined.length)), joined, padding,
  ]));
}
