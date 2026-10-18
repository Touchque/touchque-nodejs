// src/testing/fakeApi.ts (tests only — not exported from the package)
// A small in-memory TouchQue API with the same contract as the real one for the
// endpoints the step-up flow uses. Tests drive the "phone" with approve()/reject().

import express from 'express';
import * as crypto from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { TouchQue } from '../index';

export interface FakeRequest {
  id: string; user: string; type: string; referenceId: string | null;
  details: Array<{ label: string; value: string }> | null;
  status: 'PENDING' | 'CONFIRMED' | 'REJECTED' | 'EXPIRED';
  challengeCode?: string; requiresPasskey?: boolean; consumed: boolean; confirmedVia?: string;
  provisional?: boolean; reconfirmedAt?: string; revokedAt?: string; revokeReason?: 'UNDO' | 'COACHED';
  browserProof?: string;
}

/** A browser made known by an approved request that carried `browserProof`. */
export interface FakeBrowser {
  user: string; thumbprint: string; label: string; createdAt: string;
  lastMfaAt: string; lastMfaMethod: string; lastSeenAt: string; lastSilentAt: string | null;
}

export interface FakeApi {
  client: TouchQue;
  requests: FakeRequest[];
  linked: Set<string>;
  pendingSecrets: Set<string>;
  actions: Map<string, { critical: boolean; active: boolean }>;
  calls: Array<{ method: string; path: string; body: any }>;
  /** Silent sign-ins: browsers made known by approvals (GET /risk/browsers). */
  browsers: FakeBrowser[];
  /** The body of the last POST /risk/check, or null. */
  lastCheck: any;
  /**
   * Behaviour switches. `silent`: POST /risk/check answers prompt:false for an
   * everyday action (a critical one still asks, as does an unlinked user).
   */
  opts: { numberMatch?: boolean; passkeyOnly?: boolean; telemetry?: boolean; canary?: boolean; silent?: boolean; frozen?: boolean; rateLimited?: boolean; blocked?: string; offlineCode?: string; totpCode?: string };
  approve(id?: string, via?: string, extra?: { provisional?: boolean }): void;
  reject(id?: string): void;
  /** Vishing Shield: the phone tap moved the request to a passkey (still PENDING). */
  escalate(id?: string): void;
  revoke(id?: string, reason?: 'UNDO' | 'COACHED'): void;
  reconfirm(id?: string): void;
  close(): Promise<void>;
}

const toPairs = (d: any) => (!d ? null : Array.isArray(d) ? d : Object.entries(d).map(([label, value]) => ({ label, value: String(value) })));
const b64u = (buf: Buffer) => buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// RFC 7638 thumbprint of the proof's key, like the API (object or base64url JSON
// string). The fake does not check the signature; an unreadable proof gets a
// stable stand-in so tests can still tell browsers apart.
function browserThumbprint(proof: unknown): string {
  try {
    const p = typeof proof === 'string' ? JSON.parse(Buffer.from(proof, 'base64url').toString('utf8')) : proof;
    const { crv, kty, x, y } = (p as { jwk: Record<string, unknown> }).jwk;
    if (typeof x !== 'string' || typeof y !== 'string') throw new Error('no key');
    return b64u(crypto.createHash('sha256').update(JSON.stringify({ crv, kty, x, y })).digest());
  } catch {
    return b64u(crypto.createHash('sha256').update(typeof proof === 'string' ? proof : JSON.stringify(proof)).digest());
  }
}
// The engine's English texts for the reason codes the fake answers with.
const REASON_TEXT: Record<string, string> = {
  known_browser: 'This browser proved its device-bound key',
  recent_approval: 'Approved on the phone in this browser 3 h ago',
  same_phone: 'The same phone approved this browser',
  familiar_network: 'Country and network seen in earlier approved sign-ins',
  no_risk_signal: 'No risk signal',
  no_browser_key: 'No device-bound browser key was presented',
  new_browser: 'This browser has not been approved on the phone for this account',
  critical_action: 'The action is critical',
  phone_not_linked: 'No phone is linked to this account',
};
const reasons = (...codes: string[]) => codes.map((code) => ({ code, text: REASON_TEXT[code] }));

export async function startFakeApi(): Promise<FakeApi> {
  const app = express();
  app.use(express.json());
  const api = {
    requests: [] as FakeRequest[],
    linked: new Set<string>(),
    pendingSecrets: new Set<string>(),
    actions: new Map([['LOGIN', { critical: false, active: true }], ['SEND_MONEY', { critical: true, active: true }], ['PASSKEY_ENROLL', { critical: true, active: true }]]),
    calls: [] as Array<{ method: string; path: string; body: any }>,
    opts: {} as FakeApi['opts'],
    challenges: new Map<string, { user: string; type: string; used: boolean; requestId?: string }>(),
    browsers: [] as FakeBrowser[],
    lastCheck: null as any,
  };
  // Like the API: only a real second factor makes a browser known (a confirmed push that is not provisional, a passkey).
  const rememberBrowser = (r: FakeRequest) => {
    if (!r.browserProof || r.status !== 'CONFIRMED' || r.provisional) return;
    const thumbprint = browserThumbprint(r.browserProof);
    const now = new Date().toISOString();
    const lastMfaMethod = r.confirmedVia === 'WEBAUTHN' ? 'passkey' : 'push';
    const known = api.browsers.find((x) => x.user === r.user && x.thumbprint === thumbprint);
    if (known) Object.assign(known, { lastMfaAt: now, lastMfaMethod, lastSeenAt: now });
    else api.browsers.push({ user: r.user, thumbprint, label: 'Browser', createdAt: now, lastMfaAt: now, lastMfaMethod, lastSeenAt: now, lastSilentAt: null });
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
    if (action.critical && api.requests.some((x) => x.user === user && x.status === 'CONFIRMED' && x.provisional && !x.reconfirmedAt && !x.revokedAt)) {
      return res.status(403).json({ code: 'blocked', reason: 'provisional', error: 'blocked' });
    }
    const r: FakeRequest = {
      id: `00000000-0000-4000-8000-${String(++seq).padStart(12, '0')}`, user, type, referenceId, details: toPairs(details),
      status: 'PENDING', consumed: false,
      challengeCode: api.opts.passkeyOnly ? undefined : (api.opts.numberMatch || action.critical ? '47' : undefined),
      requiresPasskey: api.opts.passkeyOnly || undefined,
      browserProof: req.body.browserProof || undefined,
    };
    api.requests.push(r);
    res.json({
      message: 'Request sent', requestId: r.id, challengeCode: r.challengeCode, expiresAt: new Date(Date.now() + 30000).toISOString(), requiresPasskey: r.requiresPasskey,
      ...(api.opts.telemetry && { telemetryToken: 'tt_test' }),
      ...(api.opts.canary && { canary: { url: `http://127.0.0.1:1/c/canary-${r.id}.gif` } }),
    });
  });
  const shieldFields = (r: FakeRequest) => ({
    provisional: Boolean(r.provisional), reconfirmedAt: r.reconfirmedAt || null, revoked: Boolean(r.revokedAt), revokeReason: r.revokeReason || null,
  });

  app.get('/login/status/:id', (req, res) => {
    const r = api.requests.find((x) => x.id === req.params.id);
    if (!r) return res.status(404).json({ code: 'not_found' });
    res.json({
      status: r.status, externalUsername: r.user, type: r.type, referenceId: r.referenceId, details: r.details, consumed: r.consumed,
      requiresPasskey: r.requiresPasskey, confirmedVia: r.confirmedVia || null,
      assurance: r.status === 'CONFIRMED' ? { phishingResistant: r.confirmedVia === 'WEBAUTHN', method: r.confirmedVia === 'WEBAUTHN' ? 'passkey' : 'push' } : null,
      ...shieldFields(r),
    });
  });

  app.post('/login/:id/consume', (req, res) => {
    const r = api.requests.find((x) => x.id === req.params.id);
    if (!r) return res.status(404).json({ code: 'not_found' });
    if (r.status !== 'CONFIRMED') return res.status(409).json({ code: r.status === 'REJECTED' ? 'rejected' : r.status === 'EXPIRED' ? 'expired' : 'not_approved' });
    if (r.consumed) return res.status(409).json({ code: 'already_used' });
    if (r.revokedAt) return res.status(409).json({ code: 'revoked' });
    r.consumed = true;
    res.json({
      consumed: true, requestId: r.id, externalUsername: r.user, type: r.type, referenceId: r.referenceId, details: r.details,
      confirmedVia: r.confirmedVia, assurance: { phishingResistant: r.confirmedVia === 'WEBAUTHN', method: r.confirmedVia === 'WEBAUTHN' ? 'passkey' : 'push' }, approvalProof: null,
      ...shieldFields(r),
    });
  });

  // Silent sign-ins. Sends nothing to the phone; never 404 for an unknown user (that would reveal who has 2FA).
  app.post('/risk/check', (req, res) => {
    const b = req.body || {};
    api.lastCheck = b;
    if (typeof b.externalUsername !== 'string' || !b.externalUsername) return res.status(400).json({ code: 'invalid_request', error: 'externalUsername is required' });
    if (api.opts.rateLimited) return res.status(429).json({ code: 'rate_limited', error: 'too_many_login_requests', retryAfter: 60 });
    const ask = (assurance: string, ...codes: string[]) => res.json({ prompt: true, reasons: reasons(...codes), assurance, silentMode: 'enforce' });
    if (!api.linked.has(b.externalUsername)) return ask('normal', 'phone_not_linked');
    if (api.actions.get(b.type || 'LOGIN')?.critical) return ask('normal', 'critical_action');
    if (api.opts.silent) {
      return res.json({
        prompt: false, reasons: reasons('known_browser', 'recent_approval', 'same_phone', 'familiar_network', 'no_risk_signal'), assurance: 'high', silentMode: 'enforce',
      });
    }
    return ask('normal', b.browserProof ? 'new_browser' : 'no_browser_key');
  });
  const browserView = ({ user, ...rest }: FakeBrowser) => rest;
  app.get('/risk/browsers', (req, res) => {
    const user = typeof req.query.externalUsername === 'string' ? req.query.externalUsername : '';
    if (!user) return res.status(400).json({ code: 'invalid_request', error: 'externalUsername is required' });
    res.json({ browsers: api.browsers.filter((x) => x.user === user).map(browserView) });
  });
  app.post('/risk/browsers/forget', (req, res) => {
    const b = req.body || {};
    if (typeof b.externalUsername !== 'string' || !b.externalUsername) return res.status(400).json({ code: 'invalid_request', error: 'externalUsername is required' });
    const gone = (x: FakeBrowser) => x.user === b.externalUsername && (!b.thumbprint || x.thumbprint === b.thumbprint);
    const forgotten = api.browsers.filter(gone).length;
    api.browsers = api.browsers.filter((x) => !gone(x));
    res.json({ forgotten });
  });

  // Like the API: a user with a linked phone needs an approved PASSKEY_ENROLL first, used once.
  const usedEnrollApprovals = new Set<string>();
  app.post('/webauthn/register/options', (req, res) => {
    const { externalUsername: user, approvalRequestId } = req.body;
    if (api.linked.has(user)) {
      if (!approvalRequestId) return res.status(403).json({ code: 'enrollment_approval_required', error: 'enrollment_approval_required', action: 'PASSKEY_ENROLL' });
      const r = api.requests.find((x) => x.id === approvalRequestId);
      if (!r || r.user !== user || r.type !== 'PASSKEY_ENROLL' || r.status !== 'CONFIRMED') return res.status(403).json({ code: 'enrollment_approval_invalid', error: 'enrollment_approval_invalid' });
      if (usedEnrollApprovals.has(r.id)) return res.status(403).json({ code: 'enrollment_approval_used', error: 'enrollment_approval_used' });
      usedEnrollApprovals.add(r.id);
    }
    res.json({ challenge: 'reg-challenge', rp: { id: 'example.com', name: 'Example' }, user: { name: user } });
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
    if (linked?.requiresPasskey) return res.status(403).json({ error: 'passkey_required', reason: 'passkey_required' });
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
    if (ch.requestId && api.requests.find((x) => x.id === ch.requestId)?.requiresPasskey) return res.status(403).json({ approved: false, reason: 'passkey_required' });
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
    approve(id?: string, via = 'DEVICE', extra: { provisional?: boolean } = {}) {
      const r = pick(id); r.status = 'CONFIRMED'; r.confirmedVia = via; r.provisional = Boolean(extra.provisional);
      rememberBrowser(r);
    },
    reject(id?: string) { pick(id).status = 'REJECTED'; },
    escalate(id?: string) { const r = pick(id); r.requiresPasskey = true; r.challengeCode = undefined; },
    revoke(id?: string, reason: 'UNDO' | 'COACHED' = 'COACHED') { const r = pick(id); r.revokedAt = new Date().toISOString(); r.revokeReason = reason; },
    reconfirm(id?: string) { pick(id).reconfirmedAt = new Date().toISOString(); },
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  });
}
