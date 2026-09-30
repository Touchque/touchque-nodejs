// src/testing/fakeApi.ts (tests only — not exported from the package)
// A small in-memory TouchQue API with the same contract as the real one for the
// endpoints the step-up flow uses. Tests drive the "phone" with approve()/reject().

import express from 'express';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { TouchQue } from '../index';

export interface FakeRequest {
  id: string; user: string; type: string; referenceId: string | null;
  details: Array<{ label: string; value: string }> | null;
  status: 'PENDING' | 'CONFIRMED' | 'REJECTED' | 'EXPIRED';
  challengeCode?: string; requiresPasskey?: boolean; consumed: boolean; confirmedVia?: string;
}

export interface FakeApi {
  client: TouchQue;
  requests: FakeRequest[];
  linked: Set<string>;
  pendingSecrets: Set<string>;
  actions: Map<string, { critical: boolean; active: boolean }>;
  calls: Array<{ method: string; path: string; body: any }>;
  /** Behaviour switches */
  opts: { numberMatch?: boolean; passkeyOnly?: boolean; frozen?: boolean; rateLimited?: boolean; blocked?: string; offlineCode?: string; totpCode?: string };
  approve(id?: string, via?: string): void;
  reject(id?: string): void;
  close(): Promise<void>;
}

const toPairs = (d: any) => (!d ? null : Array.isArray(d) ? d : Object.entries(d).map(([label, value]) => ({ label, value: String(value) })));

export async function startFakeApi(): Promise<FakeApi> {
  const app = express();
  app.use(express.json());
  const api = {
    requests: [] as FakeRequest[],
    linked: new Set<string>(),
    pendingSecrets: new Set<string>(),
    actions: new Map([['LOGIN', { critical: false, active: true }], ['SEND_MONEY', { critical: true, active: true }]]),
    calls: [] as Array<{ method: string; path: string; body: any }>,
    opts: {} as FakeApi['opts'],
    challenges: new Map<string, { user: string; type: string; used: boolean; requestId?: string }>(),
  };
  let seq = 0;
  app.use((req, res, next) => {
    api.calls.push({ method: req.method, path: req.path, body: req.body });
    if (!req.get('x-api-key') || !req.get('x-signature') || !req.get('x-nonce')) return res.status(401).json({ error: 'unsigned' });
    next();
  });

  app.post('/login/request', (req, res) => {
    const { externalUsername: user, type, referenceId = null, details } = req.body;
    if (!api.linked.has(user)) return res.status(404).json({ code: 'device_not_linked', error: 'No linked device found for this user' });
    if (api.opts.frozen) return res.status(423).json({ code: 'frozen', error: 'frozen', retryAfter: 900 });
    if (api.opts.rateLimited) return res.status(429).json({ code: 'rate_limited', error: 'too_many_login_requests', retryAfter: 60 });
    const action = api.actions.get(type);
    if (!action) return res.status(400).json({ code: 'unknown_action', error: `Invalid action type: ${type}` });
    if (api.opts.blocked) return res.status(403).json({ code: 'blocked', reason: api.opts.blocked, error: 'blocked' });
    const r: FakeRequest = {
      id: `00000000-0000-4000-8000-${String(++seq).padStart(12, '0')}`, user, type, referenceId, details: toPairs(details),
      status: 'PENDING', consumed: false,
      challengeCode: api.opts.passkeyOnly ? undefined : (api.opts.numberMatch || action.critical ? '47' : undefined),
      requiresPasskey: api.opts.passkeyOnly || undefined,
    };
    api.requests.push(r);
    res.json({ message: 'Request sent', requestId: r.id, challengeCode: r.challengeCode, expiresAt: new Date(Date.now() + 30000).toISOString(), requiresPasskey: r.requiresPasskey });
  });

  app.get('/login/status/:id', (req, res) => {
    const r = api.requests.find((x) => x.id === req.params.id);
    if (!r) return res.status(404).json({ code: 'not_found' });
    res.json({
      status: r.status, externalUsername: r.user, type: r.type, referenceId: r.referenceId, details: r.details, consumed: r.consumed,
      requiresPasskey: r.requiresPasskey, confirmedVia: r.confirmedVia || null,
      assurance: r.status === 'CONFIRMED' ? { phishingResistant: r.confirmedVia === 'WEBAUTHN', method: r.confirmedVia === 'WEBAUTHN' ? 'passkey' : 'push' } : null,
    });
  });

  app.post('/login/:id/consume', (req, res) => {
    const r = api.requests.find((x) => x.id === req.params.id);
    if (!r) return res.status(404).json({ code: 'not_found' });
    if (r.status !== 'CONFIRMED') return res.status(409).json({ code: r.status === 'REJECTED' ? 'rejected' : r.status === 'EXPIRED' ? 'expired' : 'not_approved' });
    if (r.consumed) return res.status(409).json({ code: 'already_used' });
    r.consumed = true;
    res.json({
      consumed: true, requestId: r.id, externalUsername: r.user, type: r.type, referenceId: r.referenceId, details: r.details,
      confirmedVia: r.confirmedVia, assurance: { phishingResistant: r.confirmedVia === 'WEBAUTHN', method: r.confirmedVia === 'WEBAUTHN' ? 'passkey' : 'push' }, approvalProof: null,
    });
  });

  app.post('/auth/generate-secret', (req, res) => {
    const user = req.body.externalUsername;
    if (api.linked.has(user)) return res.status(409).json({ error: 'already linked' });
    if (api.pendingSecrets.has(user)) return res.status(409).json({ error: 'Secret already generated' });
    api.pendingSecrets.add(user);
    res.json({ secret: 'S', qrCodeDataUrl: `data:image/png;base64,QR-${user}`, externalUsername: user, expiresAt: 'soon', ttlMs: 300000, recoveryCodes: ['r1'] });
  });
  app.post('/auth/secret/reset', (req, res) => {
    const user = req.body.externalUsername;
    api.linked.delete(user);
    api.pendingSecrets.add(user);
    res.json({ success: true, secret: 'S2', qrCodeDataUrl: `data:image/png;base64,QR2-${user}`, externalUsername: user, recoveryCodes: ['r2'] });
  });
  app.get('/users/:u', (req, res) => {
    const u = req.params.u;
    if (!api.linked.has(u) && !api.pendingSecrets.has(u)) return res.status(404).json({ error: 'not found' });
    res.json({ externalUsername: u, deviceId: api.linked.has(u) ? 'dev-1' : null, used: api.linked.has(u), frozen: false });
  });

  // Like the real API: a QR that follows a push is tied to it. A request the phone REJECTED kills the QR
  // (none is issued, a code is refused), and a push with number matching makes the QR show the same number.
  app.post('/offline/challenge', (req, res) => {
    const linked = req.body.requestId ? api.requests.find((x) => x.id === req.body.requestId) : undefined;
    if (req.body.requestId && !linked) return res.status(404).json({ error: 'request_not_found' });
    if (linked?.status === 'REJECTED') return res.status(409).json({ error: 'request_rejected' });
    const id = `ch-${++seq}`;
    api.challenges.set(id, { user: req.body.externalUsername, type: req.body.type, used: false, requestId: linked?.id });
    const challengeCode = linked?.challengeCode || (req.body.requireNumberMatch === true ? '47' : undefined);
    res.json({ challengeId: id, qr: 'TQ2.x', qrDataUrl: 'data:image/png;base64,OFFLINE', expiresAt: 'soon', expiresInSeconds: 120, totpAvailable: true, ...(challengeCode && { challengeCode }) });
  });
  app.post('/offline/verify', (req, res) => {
    const ch = api.challenges.get(req.body.challengeId);
    if (!ch) return res.status(404).json({ approved: false, reason: 'unknown_challenge' });
    if (ch.used) return res.status(410).json({ approved: false, reason: 'used' });
    if (ch.requestId && api.requests.find((x) => x.id === ch.requestId)?.status === 'REJECTED') return res.status(410).json({ approved: false, reason: 'request_rejected' });
    if (req.body.code !== (api.opts.offlineCode || 'ABCD123')) return res.status(401).json({ approved: false, reason: 'invalid_code', attemptsLeft: 4 });
    ch.used = true;
    res.json({ approved: true, challengeId: req.body.challengeId, externalUsername: ch.user, type: ch.type });
  });
  app.post('/offline/totp/verify', (req, res) => {
    if (req.body.requestId && api.requests.find((x) => x.id === req.body.requestId)?.status === 'REJECTED') return res.status(410).json({ approved: false, reason: 'request_rejected' });
    if (req.body.code !== (api.opts.totpCode || '123456')) return res.status(401).json({ approved: false, reason: 'invalid_code' });
    res.json({ approved: true, externalUsername: req.body.externalUsername });
  });

  const server: Server = await new Promise((resolve) => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  const { port } = server.address() as AddressInfo;
  const client = new TouchQue({ apiKey: 'tq_test_key', apiSecret: 'test_secret', baseUrl: `http://127.0.0.1:${port}` });
  const pick = (id?: string) => (id ? api.requests.find((r) => r.id === id) : api.requests[api.requests.length - 1])!;

  return Object.assign(api, {
    client,
    approve(id?: string, via = 'DEVICE') { const r = pick(id); r.status = 'CONFIRMED'; r.confirmedVia = via; },
    reject(id?: string) { pick(id).status = 'REJECTED'; },
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  });
}
