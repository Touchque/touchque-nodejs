// TouchQue Actions in the Node SDK: every management call sends exactly what
// the shared vectors (fixtures/actions-api-vectors.json) say, against the
// shared fake API (testing/fake-touchque-api.mjs), signed like the real API.
import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import { spawn, type ChildProcess } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { TouchQue, TouchQueConfigError, handlerToCode, type LoginRequestEvent, type LoginRequestApi } from '../index';

const vectors = JSON.parse(readFileSync(resolve(__dirname, '../../fixtures/actions-api-vectors.json'), 'utf8'));
let fake: ChildProcess;
let base = '';
let tq: TouchQue;

beforeAll(async () => {
  fake = spawn(process.execPath, [resolve(__dirname, '../../testing/fake-touchque-api.mjs')], { stdio: ['ignore', 'pipe', 'inherit'] });
  const port = await new Promise<number>((res, rej) => {
    fake.once('error', rej);
    fake.stdout!.once('data', (chunk) => res(JSON.parse(String(chunk).split('\n')[0]).port));
  });
  base = `http://127.0.0.1:${port}`;
  tq = new TouchQue({ apiKey: 'tq_test_key', apiSecret: 'test_secret', baseUrl: base });
});
afterAll(() => { fake?.kill(); });

const lastCall = async () => {
  const calls = await (await fetch(`${base}/__test/calls`)).json() as Array<{ method: string; path: string; url: string; body: Record<string, unknown> }>;
  return calls[calls.length - 1];
};

// Vector name → the Node call.
const run: Record<string, (a: any) => Promise<unknown>> = {
  deploy: (a) => tq.actions.deploy(a.slug, { trigger: a.trigger, code: a.code, secrets: a.secrets, name: a.name }),
  deployTemplate: (a) => tq.actions.deploy(a.slug, { trigger: a.trigger, template: a.template, onFailure: a.onFailure }),
  deployLoosening: (a) => tq.actions.deploy(a.slug, { trigger: a.trigger, code: a.code, capabilities: a.capabilities, allowedHosts: a.allowedHosts }),
  list: () => tq.actions.list(),
  get: (a) => tq.actions.get(a.slug),
  version: (a) => tq.actions.version(a.slug, a.number),
  update: (a) => tq.actions.update(a.slug, { enabled: a.enabled }),
  rollback: (a) => tq.actions.rollback(a.slug, a.version),
  rollbackPrevious: (a) => tq.actions.rollback(a.slug),
  test: (a) => tq.actions.test({ trigger: a.trigger, code: a.code, eventId: a.eventId }),
  testDeployed: (a) => tq.actions.test({ slug: a.slug, event: a.event }),
  dryRun: (a) => tq.actions.dryRun({ trigger: a.trigger, code: a.code, replaces: a.replaces, limit: a.limit }),
  events: (a) => tq.actions.events({ trigger: a.trigger, limit: a.limit }),
  logs: (a) => tq.actions.logs(a.slug, { limit: a.limit }),
  metrics: (a) => tq.actions.metrics(a.slug, { window: a.window }),
  triggers: () => tq.actions.triggers(),
  templates: () => tq.actions.templates(),
  renderTemplate: (a) => tq.actions.renderTemplate(a.id, a.trigger, a.params),
  setSecret: (a) => tq.actions.secrets.set(a.name, a.value),
  listSecrets: () => tq.actions.secrets.list(),
  deleteSecret: (a) => tq.actions.secrets.delete(a.name),
  delete: (a) => tq.actions.delete(a.slug),
};

describe('actions API vectors', () => {
  test.each(vectors.calls.map((v: any) => [v.name, v]))('%s', async (_name, v: any) => {
    const result: any = await run[v.name](v.args);
    const call = await lastCall();
    expect(call.method).toBe(v.request.method);
    expect(call.path).toBe(v.request.path);
    const query = Object.fromEntries(new URL(call.url, 'http://x').searchParams);
    expect(query).toEqual(v.request.query || {});
    if (v.request.method !== 'GET' && v.request.method !== 'DELETE') expect(call.body).toEqual(v.request.body || {});
    if (v.expect) {
      for (const [path, want] of Object.entries(v.expect)) {
        expect(path.split('.').reduce((o: any, k) => o?.[k], result)).toEqual(want);
      }
    }
  });

  test('context is passed through on login.request and risk.check', async () => {
    await fetch(`${base}/__test/link`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ user: 'ctx@example.com' }) });
    await tq.login.request(vectors.context.loginRequest.args);
    expect((await lastCall()).body).toEqual(vectors.context.loginRequest.body);
    await tq.risk.check(vectors.context.riskCheck.args);
    expect((await lastCall()).body).toEqual(vectors.context.riskCheck.body);
  });
});

describe('actions helpers', () => {
  test('a typed function deploys as onExecute', async () => {
    const handler = async (event: LoginRequestEvent, api: LoginRequestApi) => {
      if ((event.context?.roles as string[] | undefined)?.includes('admin')) api.requirePasskey('Admins approve with a passkey');
    };
    const res = await tq.actions.deploy('admins-passkey', { trigger: 'login.request', handler });
    expect(res.deployed).toBe(true);
    const body = (await lastCall()).body as { code: string };
    expect(body.code.startsWith('exports.onExecute = async (event, api) =>')).toBe(true);
    expect(handlerToCode(function onExecute() { /* nothing */ })).toMatch(/^exports\.onExecute = function onExecute\(\)/);
    expect(handlerToCode({ async onExecute(_e: unknown, _a: unknown) { /* method shorthand */ } }.onExecute)).toMatch(/^exports\.onExecute = async function onExecute\(/);
  });

  test('a version that loosens security reports that it waits for the phone; approval makes it live', async () => {
    const res = await tq.actions.deploy('silent-office', { trigger: 'risk.check', code: 'exports.onExecute = (e, api) => api.allowSilent("office");', capabilities: ['allow_silent'] });
    expect(res).toMatchObject({ deployed: false, version: { status: 'pending_approval' }, approval: { required: true, capabilities: ['allow_silent'] } });
    await fetch(`${base}/__test/approve-version`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ slug: 'silent-office', number: 1 }) });
    expect((await tq.actions.get('silent-office')).action.activeVersion).toBe(1);
  });

  test('bad input is refused before any request', async () => {
    await expect(tq.actions.deploy('Bad Slug', { trigger: 'login.request', code: 'x' })).rejects.toThrow(TouchQueConfigError);
    await expect(tq.actions.deploy('no-code', { trigger: 'login.request' })).rejects.toThrow(/needs code, handler or template/);
    await expect(tq.actions.secrets.set('lowercase', 'v')).rejects.toThrow(TouchQueConfigError);
    await expect(tq.actions.deploy('both', { trigger: 'login.request', code: 'x', handler: () => undefined })).rejects.toThrow(/not both/);
  });

  test('action types moved to tq.actionTypes', async () => {
    await tq.actionTypes.define('EXPORT_DATA', { name: 'Export data', critical: true });
    expect(await lastCall()).toMatchObject({ method: 'POST', path: '/action-types', body: { type: 'EXPORT_DATA', name: 'Export data', critical: true } });
  });
});
