import { describe, test, expect } from 'vitest';
import vectors from '../fixtures/approval-proof-vectors.json';
import { verifyApprovalProof, detailsDigest, type ApprovalProof } from './approvalProof';

// Shared with the Python, PHP and Go SDKs: every SDK must agree on every case.
describe('approval-proof-vectors.json', () => {
  for (const c of vectors.digest_cases as Array<{ details?: Array<{ label: string; value: string }>; details_object?: Record<string, string>; digest: string }>) {
    test(`detailsDigest ${c.digest || '(empty)'}`, () => {
      expect(detailsDigest(c.details_object ?? c.details)).toBe(c.digest);
    });
  }
  for (const c of vectors.cases) {
    test(c.name, () => {
      expect(verifyApprovalProof(c.proof as ApprovalProof | null, c.options as never)).toBe(c.expected);
    });
  }
});
