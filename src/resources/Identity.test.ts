// tq.identity (Touchque Login Management API): each call sends the method,
// path and body the API expects, signed like every partner call.
import { describe, test, expect, beforeAll, afterAll, afterEach } from 'vitest';
import { createServer, type Server } from 'node:http';
import * as crypto from 'node:crypto';
import { Touchque, TouchqueAPIError, MemoryWebhookReplayCache, TouchqueWebhookReplayError, TouchqueWebhookSignatureError, type IdentityCustomDomainsOverview } from '../index';

const seen: Array<{ method: string; url: string; body: unknown; signed: boolean }> = [];
/** The next answers, in order: a status and a JSON body (none for 204). Empty: the default answers. */
const answers: Array<{ status: number; body?: unknown }> = [];
let server: Server;
let tq: Touchque;

beforeAll(async () => {
  server = createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => {
      seen.push({ method: req.method!, url: req.url!, body: raw ? JSON.parse(raw) : null, signed: Boolean(req.headers['x-signature']) });
      const next = answers.shift();
      if (next) {
        res.writeHead(next.status, next.body === undefined ? {} : { 'Content-Type': 'application/json' });
        res.end(next.body === undefined ? undefined : JSON.stringify(next.body));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      const domains = req.method === 'GET' && req.url === '/identity/custom-domains';
      res.end(JSON.stringify(req.url!.startsWith('/identity/roles') ? { roles: [] }
        : domains ? { domains: [{ id: 'dom_1', domain: 'login.acme.test', status: 'pending' }] } : { status: 'done' }));
    });
  });
  await new Promise<void>((ok) => server.listen(0, '127.0.0.1', ok));
  const port = (server.address() as { port: number }).port;
  tq = new Touchque({ apiKey: 'tq_test_key', apiSecret: 'test_secret', baseUrl: `http://127.0.0.1:${port}` });
});
afterAll(() => { server.close(); });
afterEach(() => { answers.length = 0; });

/** The rejection of `call`, which must be a TouchqueAPIError. */
async function refusal(call: Promise<unknown>): Promise<TouchqueAPIError> {
  const err = await call.then(() => null, (e: unknown) => e);
  expect(err).toBeInstanceOf(TouchqueAPIError);
  return err as TouchqueAPIError;
}

describe('tq.identity', () => {
  test('users, roles, organizations, jobs and the tenant', async () => {
    await tq.identity.users.list({ q: 'ayse', limit: 10 });
    await tq.identity.users.create({ email: 'a@x.com', passwordHash: '$2b$10$abc' });
    await tq.identity.users.update('usr_1', { appMetadata: { plan: null } });
    await tq.identity.users.block('usr_1', { reason: 'fraud' });
    await tq.identity.users.delete('usr_1');
    await tq.identity.users.resetMfa('usr_1');
    await tq.identity.users.passwordReset('usr_1', { sendEmail: false });
    await tq.identity.users.addRoles('usr_1', ['rol_1'], { organizationId: 'org_1' });
    await tq.identity.users.removeRole('usr_1', 'rol_1', { organizationId: 'org_1' });
    await tq.identity.imports.start({ users: [{ email: 'b@x.com' }], upsert: true });
    await tq.identity.organizations.invite('org_1', { email: 'c@x.com', clientId: 'cli', roleIds: ['rol_1'] });
    await tq.identity.roles.list();
    await tq.identity.updateTenant({ slug: 'acme', displayName: 'Acme' });
    const job = await tq.identity.exports.wait('job_1', { intervalMs: 1 });
    expect(job.status).toBe('done');
    await tq.identity.setDelivery('email', { provider: 'postmark', from: 'login@acme.test', serverToken: 'pm' });
    await tq.identity.testDelivery('sms', '+905321234567');
    await tq.identity.setAttackProtection({ bot: { provider: 'turnstile', siteKey: 'k', secret: 's', mode: 'risky' } });
    await tq.identity.setApproverAppName('Acme Pay');
    await tq.identity.setCustomDomainOnly(true);
    await tq.identity.checkDomainCertificate('dom_1');
    expect(seen.map((r) => `${r.method} ${r.url}`)).toEqual([
      'GET /identity/users?limit=10&q=ayse',
      'POST /identity/users',
      'PATCH /identity/users/usr_1',
      'POST /identity/users/usr_1/block',
      'DELETE /identity/users/usr_1',
      'DELETE /identity/users/usr_1/mfa',
      'POST /identity/users/usr_1/password-reset',
      'POST /identity/users/usr_1/roles',
      'DELETE /identity/users/usr_1/roles/rol_1?organizationId=org_1',
      'POST /identity/users-imports',
      'POST /identity/organizations/org_1/invitations',
      'GET /identity/roles',
      'PUT /identity/tenant',
      'GET /identity/users-exports/job_1',
      'PUT /identity/delivery/email',
      'POST /identity/delivery/sms/test',
      'PUT /identity/attack-protection',
      'PUT /identity/tenant',
      'PUT /identity/tenant',
      'POST /identity/custom-domains/dom_1/check-certificate',
    ]);
    expect(seen[17].body).toEqual({ branding: { approverAppName: 'Acme Pay' } });
    expect(seen[18].body).toEqual({ customDomainOnly: true });
    expect(seen[1].body).toEqual({ email: 'a@x.com', passwordHash: '$2b$10$abc' });
    expect(seen[2].body).toEqual({ appMetadata: { plan: null } });
    expect(seen[7].body).toEqual({ roleIds: ['rol_1'], organizationId: 'org_1' });
    expect(seen.every((r) => r.signed)).toBe(true);
  });

  test('custom domains: get reads the list (there is no GET by id), verify checks the TXT record', async () => {
    seen.length = 0;
    expect(await tq.identity.customDomains.get('dom_1')).toMatchObject({ id: 'dom_1', domain: 'login.acme.test' });
    await expect(tq.identity.customDomains.get('dom_2')).rejects.toMatchObject({ status: 404, data: { error: 'not_found' } });
    await tq.identity.customDomains.verify('dom_1');
    expect(seen.map((r) => `${r.method} ${r.url}`)).toEqual([
      'GET /identity/custom-domains',
      'GET /identity/custom-domains',
      'POST /identity/custom-domains/dom_1/verify',
    ]);
  });
});

describe('tq.identity passkey domain', () => {
  test('the passkey domain', async () => {
    const from = seen.length;
    await tq.identity.setPasskeyDomain('acme.com');
    await tq.identity.setPasskeyDomain(null);
    expect(seen.slice(from).map(({ method, url, body }) => ({ method, url, body }))).toEqual([
      { method: 'PUT', url: '/identity/tenant', body: { passkeyDomain: 'acme.com' } },
      { method: 'PUT', url: '/identity/tenant', body: { passkeyDomain: null } },
    ]);
  });

  test('the domain goes as given ("" too: the API reads it as none) and the tenant comes back', async () => {
    const from = seen.length;
    answers.push({ status: 200, body: { slug: 'acme', passkeyDomain: 'acme.com', customDomainOnly: false } });
    expect(await tq.identity.setPasskeyDomain('Acme.COM')).toEqual({ slug: 'acme', passkeyDomain: 'acme.com', customDomainOnly: false });
    await tq.identity.setPasskeyDomain('');
    expect(seen.slice(from).map(({ url, body }) => ({ url, body }))).toEqual([
      { url: '/identity/tenant', body: { passkeyDomain: 'Acme.COM' } },
      { url: '/identity/tenant', body: { passkeyDomain: '' } },
    ]);
  });

  test('a refusal keeps its code (data.error), field and count', async () => {
    answers.push({ status: 409, body: { error: 'passkeys_exist', field: 'passkeyDomain', count: 3, message: '3 customer passkeys belong to the current setting and would stop working' } });
    const kept = await refusal(tq.identity.setPasskeyDomain('acme.com'));
    expect(kept).toMatchObject({ status: 409, code: undefined, message: '3 customer passkeys belong to the current setting and would stop working' });
    expect(kept.data).toMatchObject({ error: 'passkeys_exist', field: 'passkeyDomain', count: 3 });

    answers.push({ status: 409, body: { error: 'not_your_domain', field: 'passkeyDomain', message: 'example.org must be one of your verified custom domains, or a domain above one that your organization verified (Organization → Domains)' } });
    expect((await refusal(tq.identity.setPasskeyDomain('example.org'))).data).toMatchObject({ error: 'not_your_domain', field: 'passkeyDomain', count: undefined });

    answers.push({ status: 400, body: { error: 'invalid_request', field: 'passkeyDomain', message: 'passkeyDomain must be a domain like example.com, or null' } });
    expect((await refusal(tq.identity.setPasskeyDomain('not a domain'))).data).toMatchObject({ error: 'invalid_request', field: 'passkeyDomain' });

    answers.push({ status: 409, body: { error: 'organization_unavailable', field: 'passkeyDomain', message: 'Your organization’s verified domains could not be read; try again' } });
    expect((await refusal(tq.identity.setPasskeyDomain('acme.com'))).data).toMatchObject({ error: 'organization_unavailable', field: 'passkeyDomain' });

    // Before Touchque Login is set up for the workspace the PUT would set it up, which needs a slug.
    answers.push({ status: 400, body: { error: 'invalid_request', field: 'slug', message: 'slug must be 3–63 lowercase letters, digits or hyphens' } });
    const notSetUp = await refusal(tq.identity.setPasskeyDomain('acme.com'));
    expect(notSetUp).toMatchObject({ status: 400, message: 'slug must be 3–63 lowercase letters, digits or hyphens' });
    expect(notSetUp.data).toMatchObject({ error: 'invalid_request', field: 'slug' });
  });
});

describe('tq.identity custom domains', () => {
  const dns = { points: 'here', cloudflareProxy: false, caaBlocks: false, problems: [] };
  const domain = { id: 'dom_1', domain: 'login.acme.com', status: 'verified', dns, autoCheckUntil: '2026-11-20T09:00:00.000Z' };
  const answer = { domains: [domain], verifiedDomains: ['acme.com'], slugPasskeys: 2 };

  test('overview() is the answer whole; list() is its alias: the array of domains, carrying the other two fields', async () => {
    const from = seen.length;
    answers.push({ status: 200, body: answer }, { status: 200, body: answer });
    const overview: IdentityCustomDomainsOverview = await tq.identity.customDomains.overview();
    expect(overview).toEqual(answer);
    const list = await tq.identity.customDomains.list();
    expect(Array.isArray(list)).toBe(true);
    expect([...list]).toEqual(overview.domains);
    expect([list.verifiedDomains, list.slugPasskeys]).toEqual([overview.verifiedDomains, overview.slugPasskeys]);

    // verifiedDomains null: your organization's domains could not be read.
    answers.push({ status: 200, body: { domains: [], verifiedDomains: null, slugPasskeys: 0 } });
    expect(await tq.identity.customDomains.overview()).toEqual({ domains: [], verifiedDomains: null, slugPasskeys: 0 });
    expect(seen.slice(from).map(({ method, url, signed }) => `${method} ${url} ${signed}`)).toEqual(Array(3).fill('GET /identity/custom-domains true'));
  });

  test("get(id) finds the domain in the list; with none it throws the API's own 404 not_found", async () => {
    answers.push({ status: 200, body: answer });
    expect(await tq.identity.customDomains.get('dom_1')).toEqual(domain);

    answers.push({ status: 200, body: answer });
    const missing = await refusal(tq.identity.customDomains.get('dom_2'));
    expect(missing).toMatchObject({ name: 'TouchqueAPIError', status: 404, code: undefined, message: 'No custom domain with this id' });
    expect(missing.data).toEqual({ error: 'not_found', message: 'No custom domain with this id' });

    // The same shape as a 404 the API sends for a domain it does not have.
    answers.push({ status: 404, body: { error: 'not_found', message: 'No custom domain with this id' } });
    const real = await refusal(tq.identity.customDomains.delete('dom_2'));
    const shape = (e: TouchqueAPIError) => ({ type: Object.getPrototypeOf(e), name: e.name, status: e.status, code: e.code, caseCode: e.caseCode, message: e.message, data: e.data });
    expect(shape(missing)).toEqual(shape(real));
  });

  test('verify(id) POSTs {} to /verify, the id path-encoded, and answers the domain', async () => {
    const from = seen.length;
    answers.push({ status: 200, body: domain });
    expect(await tq.identity.customDomains.verify('dom_1')).toEqual(domain);
    await tq.identity.customDomains.verify('dom/2 é?x');
    expect(seen.slice(from).map(({ method, url, body, signed }) => ({ method, url, body, signed }))).toEqual([
      { method: 'POST', url: '/identity/custom-domains/dom_1/verify', body: {}, signed: true },
      { method: 'POST', url: '/identity/custom-domains/dom%2F2%20%C3%A9%3Fx/verify', body: {}, signed: true },
    ]);
  });
});

describe('tq.identity user store', () => {
  test('get, set, test and remove', async () => {
    const from = seen.length;
    await tq.identity.getUserStore();
    await tq.identity.setUserStore({ url: 'https://api.acme.test/touchque/user-store', enabled: true });
    await tq.identity.testUserStore();
    await tq.identity.testUserStore('https://api.acme.test/other');
    await tq.identity.removeUserStore();
    expect(seen.slice(from).map(({ method, url, body, signed }) => ({ method, url, body, signed }))).toEqual([
      { method: 'GET', url: '/identity/user-store', body: null, signed: true },
      { method: 'PUT', url: '/identity/user-store', body: { url: 'https://api.acme.test/touchque/user-store', enabled: true }, signed: true },
      { method: 'POST', url: '/identity/user-store/test', body: {}, signed: true },
      { method: 'POST', url: '/identity/user-store/test', body: { url: 'https://api.acme.test/other' }, signed: true },
      { method: 'DELETE', url: '/identity/user-store', body: null, signed: true },
    ]);
  });

  test('testUserStore: left out, null or "" tests the endpoint set ({}); any other string is the address to test', async () => {
    const from = seen.length;
    await tq.identity.testUserStore();
    await tq.identity.testUserStore(undefined);
    await tq.identity.testUserStore(null);
    await tq.identity.testUserStore('');
    await tq.identity.testUserStore('https://api.acme.test/other');
    expect(seen.slice(from).map(({ method, url, body }) => ({ method, url, body }))).toEqual([
      ...Array(4).fill({ method: 'POST', url: '/identity/user-store/test', body: {} }),
      { method: 'POST', url: '/identity/user-store/test', body: { url: 'https://api.acme.test/other' } },
    ]);
  });

  test('a field left out is not sent (the API keeps its value)', async () => {
    const from = seen.length;
    await tq.identity.setUserStore({ enabled: false });
    await tq.identity.setUserStore({ url: 'https://api.acme.test/touchque/user-store?v=2' });
    await tq.identity.setUserStore({ url: undefined, enabled: true });
    expect(seen.slice(from).map(({ body }) => body)).toEqual([
      { enabled: false },
      { url: 'https://api.acme.test/touchque/user-store?v=2' },
      { enabled: true },
    ]);
  });

  test('answers come back whole', async () => {
    const view = {
      url: 'https://api.acme.test/touchque/user-store', enabled: true, active: true, movedIn: 1,
      lastCall: { at: '2026-11-17T09:00:00.000Z', event: 'user_store.verify_password', ok: true, status: 200, ms: 84, error: null },
      paused: false, updatedAt: '2026-11-17T08:00:00.000Z',
      signing: "Signed like Touchque webhooks: HMAC-SHA256 with your API secret (x-signature); check it with your SDK's webhook verify.",
    };
    answers.push({ status: 200, body: view }, { status: 201, body: view });
    const store = await tq.identity.getUserStore();
    expect(store).toEqual(view);
    expect(store.lastCall?.ok).toBe(true);
    expect(await tq.identity.setUserStore({ url: view.url })).toEqual(view);

    // A failing endpoint is ok: false with the reason, not an exception.
    answers.push({ status: 200, body: { ok: false, error: 'answered 500', ms: 12 } });
    expect(await tq.identity.testUserStore()).toEqual({ ok: false, error: 'answered 500', ms: 12 });

    // Accounts moved in carry your id.
    answers.push({ status: 200, body: { id: 'usr_9', email: 'moved@acme.test', externalId: 'shop-42', fromUserStore: true } });
    const user = await tq.identity.users.get('usr_9');
    expect([user.externalId, user.fromUserStore]).toEqual(['shop-42', true]);
  });

  test('remove is idempotent (204 resolves); a 404 is not_enabled and throws', async () => {
    answers.push({ status: 204 });
    await expect(tq.identity.removeUserStore()).resolves.toBeFalsy();

    answers.push({ status: 404, body: { error: 'not_enabled', message: 'PUT /identity/tenant first' } });
    const err = await refusal(tq.identity.removeUserStore());
    expect(err).toMatchObject({ status: 404, message: 'PUT /identity/tenant first' });
    expect(err.data.error).toBe('not_enabled');
  });

  test('refusals keep their code (data.error) and field', async () => {
    answers.push({ status: 409, body: { error: 'passwords_off', field: 'enabled', message: 'Moving users in checks their passwords: turn passwords on first' } });
    expect((await refusal(tq.identity.setUserStore({ enabled: true }))).data).toMatchObject({ error: 'passwords_off', field: 'enabled' });

    answers.push({ status: 400, body: { error: 'invalid_request', field: 'url', message: 'url must use https' } });
    const bad = await refusal(tq.identity.testUserStore('http://api.acme.example/x'));
    expect(bad).toMatchObject({ status: 400, message: 'url must use https' });
    expect(bad.data).toMatchObject({ error: 'invalid_request', field: 'url' });
  });

  // What Touchque POSTs to the user store: the payload signed with the workspace's
  // API secret over its top-level keys sorted, the signature in x-signature and in the body.
  function userStoreRequest(fields: Record<string, unknown>) {
    const payload: Record<string, unknown> = { event: 'user_store.verify_password', tenant: 'acme', ...fields, timestamp: new Date().toISOString(), jti: crypto.randomUUID() };
    const canonical = JSON.stringify(Object.fromEntries(Object.keys(payload).sort().map((k) => [k, payload[k]])));
    const signature = crypto.createHmac('sha256', 'test_secret').update(canonical).digest('hex');
    return { rawBody: JSON.stringify({ ...payload, signature }), signature };
  }

  test("Touchque's requests to the user store pass tq.webhook.verify", () => {
    const replayCache = new MemoryWebhookReplayCache();
    const ask = userStoreRequest({ email: 'jane@acme.test', password: 'Old-Shop-Pass-2019!' });
    expect(tq.webhook.verify({ ...ask, replayCache })).toMatchObject({ event: 'user_store.verify_password', tenant: 'acme', email: 'jane@acme.test', password: 'Old-Shop-Pass-2019!' });
    expect(() => tq.webhook.verify({ ...ask, replayCache })).toThrow(TouchqueWebhookReplayError);
    expect(() => tq.webhook.verify({ rawBody: ask.rawBody.replace('Old-Shop-Pass-2019!', 'Guess-123!'), signature: ask.signature })).toThrow(TouchqueWebhookSignatureError);

    // Whatever the customer typed verifies: quotes, backslashes, emoji, line separators, control characters and
    // unpaired surrogates (JSON.stringify writes them as \ud800 on both sides). The password handed back has U+FFFD
    // for each unpaired surrogate, so it can be encoded as UTF-8.
    for (const [password, handedBack] of [
      ['pässwörd 🔑 "q" \\ /', 'pässwörd 🔑 "q" \\ /'],
      ['café \u2028line\u2029 <b>&', 'café \u2028line\u2029 <b>&'],
      ['tab\there\u2028\u0000\u0001', 'tab\there\u2028\u0000\u0001'],
      ['a\ud800b\udc00', 'a\uFFFDb\uFFFD'],
      ['\ud800\u{10000}', '\uFFFD\u{10000}'],
    ]) {
      const typed = userStoreRequest({ email: 'jane@acme.test', password });
      expect(tq.webhook.verify(typed).password).toBe(handedBack);
      expect(tq.webhook.verify({ rawBody: typed.rawBody }).password).toBe(handedBack);
      expect(Buffer.from(handedBack, 'utf8').toString('utf8')).toBe(handedBack);
    }

    // The body's own signature is enough; the lookup and the test ping carry no password.
    expect(tq.webhook.verify({ rawBody: userStoreRequest({ event: 'user_store.get_user', email: 'jane@acme.test' }).rawBody })).toMatchObject({ event: 'user_store.get_user', email: 'jane@acme.test' });
    expect(tq.webhook.verify({ rawBody: userStoreRequest({ event: 'user_store.ping' }).rawBody }).event).toBe('user_store.ping');
  });
});
