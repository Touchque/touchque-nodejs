import { describe, test, expect } from 'vitest';
import vectors from '../fixtures/silent-sign-in-vectors.json';
import { parseRiskCheck } from './resources/Risk';

// Shared with the Python, PHP, Go and web SDKs: every SDK must read every answer the same way.
describe('silent-sign-in-vectors.json riskCheck', () => {
  for (const c of vectors.riskCheck.cases) {
    test(c.name, () => {
      const res = parseRiskCheck(c.response);
      expect(res.prompt).toBe(c.expected.prompt);
      expect(res.reasons.map((r) => r.code)).toEqual(c.expected.reasonCodes);
      expect(res.assurance).toBe(c.expected.assurance);
    });
  }

  test('anything but a JSON object asks', () => {
    for (const raw of [null, undefined, 'false', false, 0, [], { prompt: 0 }, { prompt: null }]) {
      expect(parseRiskCheck(raw)).toEqual({ prompt: true, reasons: [], assurance: 'normal', silentMode: 'enforce' });
    }
  });

  test('reason entries without a string code are dropped; a missing text is empty', () => {
    const res = parseRiskCheck({ prompt: true, reasons: [null, { code: 1 }, { code: 'new_browser' }, 'x', { code: 'risk_signal', text: 'Risk signal: tor_exit_node' }] });
    expect(res.reasons).toEqual([{ code: 'new_browser', text: '' }, { code: 'risk_signal', text: 'Risk signal: tor_exit_node' }]);
  });
});
