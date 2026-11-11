import { describe, test, expect } from 'vitest';
import vectors from '../fixtures/safe-guard-vectors.json';
import {
  safeTxHash, safeGovernanceHash, safeApprovalMessage, safeDisplayDigest, verifySafeApproval, withSafeApprovals, safeScheduleCall,
  type SafeTxTarget, type VerifySafeApprovalOptions,
} from './safeGuard';
import { TouchqueConfigError } from './errors';

// Shared with every server SDK, derived from the Safe Guard reference vectors: every SDK must agree on every case.
describe('safe-guard-vectors.json', () => {
  for (const v of vectors.vectors) {
    test(v.name, () => {
      const target = v.safeTx as SafeTxTarget;
      expect(safeTxHash(target)).toBe(v.safeTxHash);
      expect(safeGovernanceHash(target)).toBe(v.governanceHash);
      expect(safeApprovalMessage({
        purpose: v.purpose as 'approve' | 'schedule', chainId: target.chainId, guard: target.guard, safe: target.safe,
        subject: v.subject, expiresAt: v.expiresAt, displayDigest: v.displayDigest,
      })).toBe(v.message);
      if (v.rows) expect(safeDisplayDigest(v.rows)).toBe(v.rowsDigest);
      const purpose = v.purpose as 'approve' | 'schedule';
      expect(verifySafeApproval(target, v.approval, vectors.approverKey, { now: vectors.now, approverIndex: v.safeTx.approverIndex, purpose })).toEqual({
        valid: true, reason: null, purpose: v.purpose, approverIndex: v.safeTx.approverIndex, expiresAt: v.expiresAt,
        displayDigest: v.displayDigest, safeTxHash: v.safeTxHash, governanceHash: v.governanceHash,
      });
      // Without a purpose only an ordinary approval passes: a schedule approval is never one to execute.
      expect(verifySafeApproval(target, v.approval, vectors.approverKey, { now: vectors.now }).valid).toBe(purpose === 'approve');
    });
  }

  for (const c of vectors.checks as Array<{ name: string; vector: string; approval: string; options: VerifySafeApprovalOptions; reason: string | null; purpose?: string; key?: string; keyXY?: { x: string; y: string } }>) {
    test(`check: ${c.name}`, () => {
      const v = vectors.vectors.find((x) => x.name === c.vector)!;
      const got = verifySafeApproval(v.safeTx as SafeTxTarget, c.approval, c.keyXY ?? c.key ?? vectors.approverKey, { now: vectors.now, ...c.options });
      expect(got.reason).toBe(c.reason);
      expect(got.valid).toBe(c.reason === null);
      if (c.purpose) expect(got.purpose).toBe(c.purpose);
    });
  }

  test('withSafeApprovals and safeScheduleCall', () => {
    expect(withSafeApprovals(vectors.withApprovals.ownerSignatures, vectors.withApprovals.approvals)).toBe(vectors.withApprovals.expected);
    const s = vectors.scheduleCall;
    expect(safeScheduleCall(s.safe, s.governanceHash, s.approvals)).toBe(s.expected);
  });

  test('a transaction that is not one throws', () => {
    const v = vectors.vectors[0];
    expect(() => safeTxHash({ ...v.safeTx, tx: { ...v.safeTx.tx, to: '0x1234' } } as SafeTxTarget)).toThrow(TouchqueConfigError);
    expect(() => safeTxHash({ ...v.safeTx, tx: { ...v.safeTx.tx, operation: 2 } } as unknown as SafeTxTarget)).toThrow(TouchqueConfigError);
    expect(() => withSafeApprovals('0x', [])).toThrow(TouchqueConfigError);
  });
});
