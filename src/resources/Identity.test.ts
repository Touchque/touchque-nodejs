// tq.identity (Touchque Login Management API): each call sends the method,
// path and body the API expects, signed like every partner call.
import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server } from 'node:http';
import { Touchque } from '../index';

const seen: Array<{ method: string; url: string; body: unknown; signed: boolean }> = [];
let server: Server;
let tq: Touchque;

beforeAll(async () => {
  server = createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => {
      seen.push({ method: req.method!, url: req.url!, body: raw ? JSON.parse(raw) : null, signed: Boolean(req.headers['x-signature']) });
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
    await expect(tq.identity.customDomains.get('dom_2')).rejects.toMatchObject({ status: 404, code: 'not_found' });
    await tq.identity.customDomains.verify('dom_1');
    expect(seen.map((r) => `${r.method} ${r.url}`)).toEqual([
      'GET /identity/custom-domains',
      'GET /identity/custom-domains',
      'POST /identity/custom-domains/dom_1/verify',
    ]);
  });
});
