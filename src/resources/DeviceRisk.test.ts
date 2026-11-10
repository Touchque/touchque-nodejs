import { describe, test, expect, vi } from 'vitest';
import { DeviceRisk, parseDeviceRiskCheck } from './DeviceRisk';
import { Risk } from './Risk';
import { Login } from './Login';
import { TouchQueConfigError } from '../errors';
import type { HttpClient } from '../core/HttpClient';

const RID = `dre_${'a'.repeat(22)}`;

function fakeHttp() {
  return { post: vi.fn(), get: vi.fn(), delete: vi.fn() } as unknown as HttpClient;
}

describe('DeviceRisk resource', () => {
  test('check() sends the requestId (or the relayed report) and only the given fields', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ report: 'ok', requestId: RID, visitorId: 'tqv_x', confidence: 0.99, signals: [], stepUp: false, wouldStepUp: false, requires: 'none', mode: 'shadow', caseCode: 'K7P-2QX' });
    const r = await new DeviceRisk(http).check({ requestId: RID, event: 'sign_up', externalUsername: 'a@b.com', clientIp: '203.0.113.7' });
    expect(http.post).toHaveBeenCalledWith('/device-risk/check', { requestId: RID, event: 'sign_up', externalUsername: 'a@b.com', clientIp: '203.0.113.7' });
    expect(r).toMatchObject({ report: 'ok', visitorId: 'tqv_x', confidence: 0.99, stepUp: false, mode: 'shadow', caseCode: 'K7P-2QX' });
    await new DeviceRisk(http).check({ deviceRisk: 'REPORT' });
    expect(http.post).toHaveBeenLastCalledWith('/device-risk/check', { deviceRisk: 'REPORT' });
  });

  test('check() relays a full-size report whole (only the requestId field is capped)', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ report: 'ok', signals: [], stepUp: false });
    const report = 'A'.repeat(6144); // deviceRisk.collect() output, base64url
    await new DeviceRisk(http).check({ deviceRisk: report, event: 'sign_up' });
    expect(http.post).toHaveBeenLastCalledWith('/device-risk/check', { deviceRisk: report, event: 'sign_up' });
    await new DeviceRisk(http).check(`${RID}${'x'.repeat(100)}`);
    expect((http.post as any).mock.calls.at(-1)[1].requestId).toHaveLength(64);
  });

  test('getEvent() reads the trusted identification', async () => {
    const http = fakeHttp();
    (http.get as any).mockResolvedValue({ requestId: RID, visitorId: 'tqv_x' });
    expect((await new DeviceRisk(http).getEvent(RID)).visitorId).toBe('tqv_x');
    expect(http.get).toHaveBeenCalledWith(`/device-risk/events/${RID}`);
    await expect(new DeviceRisk(http).getEvent('../users')).rejects.toBeInstanceOf(TouchQueConfigError);
  });

  test('searchEvents() sends the filters it was given and hands back the opaque cursor', async () => {
    const http = fakeHttp();
    (http.get as any).mockResolvedValue({ events: [{ requestId: RID, visitorId: 'tqv_x' }], nextCursor: 'abc', from: 'f', to: 't' });
    const page = await new DeviceRisk(http).searchEvents({ from: new Date('2026-11-01T00:00:00Z'), signal: 'device_tampered', stepUp: true, ip: '203.0.113.0/24', account: '', cursor: 'prev', limit: 50 });
    expect(http.get).toHaveBeenCalledWith('/device-risk/events', { from: '2026-11-01T00:00:00.000Z', signal: 'device_tampered', stepUp: true, ip: '203.0.113.0/24', cursor: 'prev', limit: 50 });
    expect(page).toEqual({ events: [{ requestId: RID, visitorId: 'tqv_x' }], nextCursor: 'abc', from: 'f', to: 't' });
    (http.get as any).mockResolvedValue({ events: [], nextCursor: null });
    expect((await new DeviceRisk(http).searchEvents()).nextCursor).toBeNull();
    expect(http.get).toHaveBeenLastCalledWith('/device-risk/events', {});
    await expect(new DeviceRisk(http).searchEvents({ limit: 101 })).rejects.toBeInstanceOf(TouchQueConfigError);
  });

  test('one line with the form field: missing, empty or made up is sent as it is and answered, never thrown', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ report: 'missing', requestId: null, visitorId: null, signals: [{ code: 'device_identification_missing', text: 't', strength: 'number_match', enforced: false }], stepUp: false, wouldStepUp: true, requires: 'none', mode: 'shadow' });
    const tq = new DeviceRisk(http);
    const r = await tq.check(undefined);
    expect(http.post).toHaveBeenLastCalledWith('/device-risk/check', {});
    expect(r).toMatchObject({ report: 'missing', visitorId: null, stepUp: false, wouldStepUp: true });
    expect(r.signals[0].code).toBe('device_identification_missing');
    await tq.check('', { event: 'sign_up', externalUsername: 'a@b.com' });
    expect(http.post).toHaveBeenLastCalledWith('/device-risk/check', { event: 'sign_up', externalUsername: 'a@b.com' });
    await tq.check(null);
    expect(http.post).toHaveBeenLastCalledWith('/device-risk/check', {});
    await tq.check(['x'] as never);
    expect(http.post).toHaveBeenLastCalledWith('/device-risk/check', {});
    await tq.check('nope', { clientIp: '203.0.113.7' });
    expect(http.post).toHaveBeenLastCalledWith('/device-risk/check', { requestId: 'nope', clientIp: '203.0.113.7' });
    await tq.check(RID, { event: 'password_reset' });
    expect(http.post).toHaveBeenLastCalledWith('/device-risk/check', { requestId: RID, event: 'password_reset' });
    expect(parseDeviceRiskCheck({ report: 'expired' }).report).toBe('expired');
    expect(parseDeviceRiskCheck({ report: 'whatever' }).report).toBe('invalid');
  });

  test('a wrong event is a clear error before any request (a bug in your code, not the page)', async () => {
    const http = fakeHttp();
    await expect(new DeviceRisk(http).check({ deviceRisk: 'r', event: 'tracking' as never })).rejects.toBeInstanceOf(TouchQueConfigError);
    await expect(new DeviceRisk(http).check(RID, { event: 'tracking' as never })).rejects.toBeInstanceOf(TouchQueConfigError);
    expect(http.post).not.toHaveBeenCalled();
  });

  test('the answer fails toward asking: a malformed stepUp asks, junk signals are dropped', () => {
    expect(parseDeviceRiskCheck({}).stepUp).toBe(true);
    expect(parseDeviceRiskCheck({ stepUp: false }).stepUp).toBe(false);
    const r = parseDeviceRiskCheck({ report: 'ok', signals: [{ code: 'device_tampered', text: 't', strength: 'number_match', enforced: false }, null, { text: 'no code' }], mode: 'enforce', requires: 'passkey' });
    expect(r.signals).toEqual([{ code: 'device_tampered', text: 't', strength: 'number_match', enforced: false }]);
    expect(r).toMatchObject({ mode: 'enforce', requires: 'passkey', report: 'ok', network: null, velocity: null, bot: null });
  });

  test('engine: \'unavailable\' comes through (an outage, not risk); a normal answer has engine null', () => {
    const down = parseDeviceRiskCheck({ report: 'ok', signals: [], stepUp: true, wouldStepUp: true, requires: 'number_match', mode: 'enforce', engine: 'unavailable' });
    expect(down).toMatchObject({ engine: 'unavailable', stepUp: true, requires: 'number_match', mode: 'enforce' });
    const normal = parseDeviceRiskCheck({ report: 'ok', signals: [], stepUp: false, wouldStepUp: false, requires: 'none', mode: 'shadow' });
    expect(normal.engine).toBeNull();
    expect(normal.stepUp).toBe(false);
    expect(parseDeviceRiskCheck({ engine: 42 }).engine).toBeNull();
  });

  test('the address, the visitor\'s counts and one answer to "a bot?" come through', () => {
    const network = { countryCode: 'TR', city: 'İzmir', asn: 34984, asnOrg: 'Superonline', type: 'isp', tor: false, hosting: false, timezoneMismatch: false };
    const r = parseDeviceRiskCheck({ report: 'ok', network, velocity: { accounts24h: 1, identifications1h: 2 }, bot: { result: 'suspected', reasons: ['pointer_synthetic'] } });
    expect(r.network).toEqual(network);
    expect(r.velocity).toMatchObject({ identifications1h: 2 });
    expect(r.bot).toEqual({ result: 'suspected', reasons: ['pointer_synthetic'] });
  });

  test('login.request and risk.check pass deviceRiskRequestId (and deviceRisk) through untouched', async () => {
    const http = fakeHttp();
    (http.post as any).mockResolvedValue({ prompt: true, reasons: [], requestId: 'r1', status: 'PENDING' });
    await new Risk(http).check({ externalUsername: 'a@b.com', deviceRiskRequestId: RID });
    expect(http.post).toHaveBeenLastCalledWith('/risk/check', { externalUsername: 'a@b.com', deviceRiskRequestId: RID });
    await new Login(http).request({ externalUsername: 'a@b.com', type: 'LOGIN', deviceRiskRequestId: RID, deviceRisk: 'REPORT' } as never).catch(() => null);
    expect((http.post as any).mock.calls.at(-1)[1]).toMatchObject({ deviceRiskRequestId: RID, deviceRisk: 'REPORT' });
  });
});
