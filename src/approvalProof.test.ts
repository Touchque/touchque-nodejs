import { describe, test, expect } from 'vitest';
import * as crypto from 'crypto';
import { verifyApprovalProof, detailsDigest, type ApprovalProof } from './approvalProof';

// Same wire format as the iOS app's CryptoKit Secure Enclave key.
function makeDevice() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string; y: string };
  const fromB64Url = (s: string) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  const x963 = Buffer.concat([Buffer.from([0x04]), fromB64Url(jwk.x), fromB64Url(jwk.y)]).toString('base64');
  const proofFor = (message: string): ApprovalProof => ({
    version: 'v2',
    algorithm: 'ECDSA-P256-SHA256',
    message,
    signature: crypto.sign('sha256', Buffer.from(message), { key: privateKey, dsaEncoding: 'der' }).toString('base64'),
    publicKey: x963,
  });
  return { x963, proofFor };
}

const details = { Amount: '1,250.00 USD', Recipient: 'Jane Doe' };
// Pinned: must equal the backend's utils/deviceSecurity.js#detailsDigest and the iOS app's digest.
const DIGEST = '4d09a5ac01b443fffbfe91a648b4f1e9e2737f9908b0c305d3672c7cb8dfaa9d';
const message = `touchque-approve:v2\nreq-1\nWITHDRAW\n47\n${DIGEST}`;

describe('verifyApprovalProof', () => {
  test('detailsDigest matches the backend and iOS reference value, for objects and arrays', () => {
    expect(detailsDigest(details)).toBe(DIGEST);
    expect(detailsDigest([{ label: 'Amount', value: '1,250.00 USD' }, { label: 'Recipient', value: 'Jane Doe' }])).toBe(DIGEST);
    expect(detailsDigest(undefined)).toBe('');
  });

  test('accepts a proof signed over exactly the expected transaction', () => {
    const d = makeDevice();
    expect(verifyApprovalProof(d.proofFor(message), { requestId: 'req-1', type: 'WITHDRAW', challengeCode: '47', details, expectedPublicKey: d.x963 })).toBe(true);
  });

  test('rejects any change to the transaction the partner expects', () => {
    const d = makeDevice();
    const proof = d.proofFor(message);
    const ok = { requestId: 'req-1', type: 'WITHDRAW', challengeCode: '47', details };
    expect(verifyApprovalProof(proof, { ...ok, details: { Amount: '9,999.00 USD', Recipient: 'Jane Doe' } })).toBe(false);
    expect(verifyApprovalProof(proof, { ...ok, details: undefined })).toBe(false);
    expect(verifyApprovalProof(proof, { ...ok, requestId: 'req-2' })).toBe(false);
    expect(verifyApprovalProof(proof, { ...ok, type: 'LOGIN' })).toBe(false);
    expect(verifyApprovalProof(proof, { ...ok, challengeCode: '82' })).toBe(false);
  });

  test('rejects a proof from another key, a forged signature or a pinned-key mismatch', () => {
    const d = makeDevice();
    const attacker = makeDevice();
    const ok = { requestId: 'req-1', type: 'WITHDRAW', challengeCode: '47', details };
    expect(verifyApprovalProof(d.proofFor(message), { ...ok, expectedPublicKey: attacker.x963 })).toBe(false);
    // Attacker signs the right message with their own key: valid signature, wrong device.
    expect(verifyApprovalProof(attacker.proofFor(message), { ...ok, expectedPublicKey: d.x963 })).toBe(false);
    const forged = { ...d.proofFor(message), signature: attacker.proofFor(message).signature };
    expect(verifyApprovalProof(forged, ok)).toBe(false);
  });

  test('never throws on malformed input', () => {
    const ok = { requestId: 'req-1', type: 'WITHDRAW', details };
    expect(verifyApprovalProof(null, ok)).toBe(false);
    expect(verifyApprovalProof(undefined, ok)).toBe(false);
    expect(verifyApprovalProof({ version: 'v2', algorithm: 'ECDSA-P256-SHA256', message: 'x', signature: '!!', publicKey: 'nope' }, ok)).toBe(false);
    expect(verifyApprovalProof({ version: 'v1' } as unknown as ApprovalProof, ok)).toBe(false);
  });
});
