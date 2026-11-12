# @touchque/node

The official Node.js server SDK for [Touchque](https://touchque.com) — biometric push 2FA,
passkeys, and offline approval codes, added to any backend with one line per route.

[![npm version](https://img.shields.io/npm/v/@touchque/node.svg)](https://www.npmjs.com/package/@touchque/node)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

📘 Full docs: **[support.touchque.com](https://support.touchque.com)**

## Install

```bash
npm install @touchque/node
```

## Setup

Get an API key and secret from your [Touchque Dashboard](https://dashboard.touchque.com),
then set them as environment variables:

```bash
TQ_API_KEY=tq_auth_your_key
TQ_API_SECRET=your_api_secret
```

The client picks these up automatically — `new Touchque()` with no arguments.

## Quick start (Express)

```typescript
import express from 'express';
import { requireTouchque } from '@touchque/node';
import { transfers } from './transfers'; // your own records

const app = express();
app.use(express.json());

app.post('/transfer',
  requireTouchque('SEND_MONEY', {
    // Who approves. Default: req.user.email || req.user.id || req.user.username, from your auth.
    user: (req) => req.user?.email,
    // What the phone shows and the approval is bound to. Build it from your own records,
    // not from what the browser sent: here the transfer the user prepared before.
    details: async (req) => {
      const t = await transfers.draft(req.user.id, req.body.transferId);
      return { Amount: `${t.amount} EUR`, To: t.iban };
    },
  }),
  async (req, res) => {
    // Only reached once the user approved on their phone.
    await transfers.send(req.user.id, req.body.transferId);
    res.json({ ok: true, assurance: req.touchque.assurance });
  }
);

app.listen(3000);
```

That's the whole integration for one route. What actually happens:

1. The first request comes in with no pending approval → the middleware calls
   Touchque, sends a push to the user's phone, and answers **`202 { touchque, token }`**
   instead of running your handler.
2. Your frontend shows `touchque` in its own UI — a matching number for the
   user to tap on their phone, or a QR code the first time they link the app —
   then sends the *same request* again with header `X-Touchque-Token: <token>`
   (see [`@touchque/web`](https://www.npmjs.com/package/@touchque/web), which does this loop for you).
   While the first-time QR is up, polls answer `{ state: 'enroll', expiresAt }` without `enroll`:
   keep showing the QR you have. About 15 s before it expires, a poll brings a new QR
   (`enroll.qrCodeDataUrl`) with new recovery codes; the old QR and the old codes stop working.
   Pages on `@touchque/web` need 2.1.0.
3. Once the user approves, that retried request reaches your handler exactly
   once, with `req.touchque` populated (`assurance`, `approvalProof`, …).

No hosted page, no redirect, no new domain — you keep your own UI end to end.

## Action types

`'SEND_MONEY'` above is an action type: one kind of approval, with the title the phone shows and
whether it is critical. Define each one once, in the dashboard (**Developers → Action types**)
or from code:

```typescript
await tq.actionTypes.define('SEND_MONEY', { name: 'Send money', critical: true });
```

The guard refuses what is not ready. A name that is not defined is a setup error
(`TouchqueConfigError`, "Unknown action …"): the guard answers 500 with `reason: 'misconfigured'`. A type
turned off in the dashboard answers 403 with `reason: 'action_disabled'`, which stops that kind of
approval at once, without a deploy.

## The three primitives, if you don't use a framework adapter

```typescript
import { Touchque } from '@touchque/node';

const tq = new Touchque(); // from TQ_API_KEY / TQ_API_SECRET

const step = await tq.start('SEND_MONEY', {
  user: 'jane@acme.com',
  details: { Amount: '250 EUR', To: 'DE89...' },
});
// step.state: 'waiting' (show step.number) | 'enroll' (show step.enroll.qrCodeDataUrl;
//             with enroll: false, reason 'enrollment_off' and no QR) | 'approved' | 'rejected'
//             | 'expired' | 'passkey_required' | 'frozen' | 'blocked'

const latest = await tq.check(step.requestId!); // with the request's current expiresAt

// Once approved, consume it exactly once, right before doing the protected thing:
const approval = await tq.complete(step.requestId!, {
  user: 'jane@acme.com',
  action: 'SEND_MONEY',
  details: { Amount: '250 EUR', To: 'DE89...' },
});
```

`complete()` verifies the approval was actually issued for this user, action
and transaction — it will not let an approval for a different amount or
recipient be replayed against this call, and consuming it twice fails on the
second call.

## Framework adapters

- **Express**: `requireTouchque(action, options?)` — shown above.
- **Next.js / Fetch API route handlers**: `withTouchque(action, options?)`. It sends no end-user
  address unless you say where it comes from: `ip: ipFromVercel` (Vercel), `ip: ipFromCloudflare`
  (only when your origin accepts Cloudflare traffic only), `trustedProxyHops: 1` (one proxy of yours
  in front), or your own function. Never the leftmost `X-Forwarded-For` hop: the client controls it.
  Without an address the risk checks that need one (Tor, location, travel) are skipped.
- **`touchqueRouter`**: mounts every relay route a frontend needs
  (`POST /login`, enrollment, passkey ceremonies, offline codes) so you don't
  hand-write them. `POST /passkey/authenticate/options` with no `email` answers options for any passkey of
  your site, which `@touchque/web`'s passkey autofill (`passkeys.autofill()`) uses; the passkey the user picks
  names the account (`tq.webauthn.primaryOptions()` with no `externalUsername` does the same).

```typescript
import { touchqueRouter } from '@touchque/node';

app.use(touchqueRouter(tq, {
  getUserId: (req) => req.session.user?.email,
  // The user who already passed your password step. Binds POST /login and the
  // offline routes to them; the offline routes stay off (403) without it.
  getLoginUser: (req) => req.session.passwordVerifiedUser,
}));
```

- **`touchqueRelay`** (Next.js App Router, Hono, Remix, SvelteKit, Bun, Deno, Workers): the same routes and checks
  as `touchqueRouter`, as one handler that takes a `Request` and returns a `Response`; no express needed. Set
  `getLoginUser` exactly as for the router (the offline routes stay off without it). Fetch has no socket address, so
  say where the end user's address comes from (`ip` or `trustedProxyHops`, as for `withTouchque`); without one the
  per-IP limits are skipped and only the per-username ones apply. `basePath` (default `/touchque`) is where it is
  mounted; another path answers 404.

```typescript
// app/touchque/[...path]/route.ts
import { Touchque, touchqueRelay, ipFromVercel } from '@touchque/node';

const relay = touchqueRelay(new Touchque(), {
  getUserId: async () => (await auth())?.user?.email,
  getLoginUser: async () => (await passwordStep())?.email,
  ip: ipFromVercel,
  // `headers` go out on the success response (or use Next's cookies().set()).
  onAuthenticated: async (req, info, headers) => {
    headers.append('Set-Cookie', await sessionCookie(info.externalUsername));
  },
});
export { relay as GET, relay as POST, relay as DELETE };
```

Both relays rate limit with `FixedWindowLimiter`, which is exported for your own routes (`withTouchque`, a
hand-written relay). `hit(key, limit)` counts one request and returns the seconds to wait once `key` is over `limit`
in the window (0 until then); it is in memory, per process.

```typescript
import { FixedWindowLimiter, withTouchque, ipFromVercel } from '@touchque/node';

const limiter = new FixedWindowLimiter();   // { windowMs: 60000, perIp: 20, perUser: 5 }
const transfer = withTouchque('SEND_MONEY', handler, { user, ip: ipFromVercel });

export async function POST(req: Request) {
  const wait = limiter.hit(`ip|transfer|${ipFromVercel(req)}`, limiter.perIp);
  if (wait) return Response.json({ error: 'RATE_LIMITED', retryAfter: wait }, { status: 429, headers: { 'Retry-After': String(wait) } });
  return transfer(req);
}
```

### Your own error shape: `errorBody`

Refusals answer `{ touchque, token }` by default; 401, 500 and 503 carry `{ touchque, error: { code, message } }`
instead. `requireTouchque`, `withTouchque` and `guardResponse` take `errorBody` to answer in your app's own shape:

```typescript
app.post('/transfer', requireTouchque('SEND_MONEY', {
  errorBody: (r) => ({ message: r.message, code: r.code }),
}), handler);
// 403 {"message":"The approval was rejected.","code":"rejected","touchque":{"state":"rejected",…}}
```

- It is called for every answer with status 400 or more: 401, 403, 408, 423, 429, 500 and 503. Never for a
  202 step, never on approval.
- It gets a `GuardRefusal`: `status`; `code` (`error.code` when the guard set one, else the step's `reason`,
  else its `state`); `message` (`error.message` when set, else "The approval was rejected.", "The approval
  expired. Try again.", "Too many rejected approvals. Try again later.", "Too many attempts. Try again later."
  or "The approval was refused."); and `touchque`, a copy of the step as it would be sent.
- What you return is judged by its JSON, as it will be sent. When it encodes to a JSON object (a plain
  object, a class instance, an object with `toJSON()`, or a `Map`, read as its entries), it is sent with
  `touchque` set to the step: the SDK's key wins, so `@touchque/web` still sees the state. No `token` is added.
  Anything else (a string, number, array or `null`) is sent as it is, and `undefined` keeps the default body.
  It may be `async`.
- The status and headers stay the same: JSON, `Cache-Control: no-store`, `Retry-After`.
- If it throws, or returns something JSON cannot encode (a `BigInt`, a cycle), the default body is sent and
  your client's logger gets `[Touchque] errorBody failed: …` (with `guardResponse`, the `logger` you pass).

### Refusal headers

Every guard answer with status 400 or more, from `requireTouchque`, `withTouchque`, `guardResponse`,
`touchqueRouter` and `touchqueRelay`, says what happened in headers too: `X-Touchque-State` (`rejected`, `blocked`, …) and, when
the step has a reason, `X-Touchque-Reason`. `@touchque/web` 2.1.0 reads them when the body is your own
shape without `touchque` (an `errorBody` that returns a string), so the page shows the refusal and never
"Approved". When the page is on another origin, list them in your CORS `Access-Control-Expose-Headers`.

### No API key

The adapters, and `runGuard(null, …)` in your own handler, never throw for a missing `TQ_API_KEY` /
`TQ_API_SECRET`, at startup or on a request. Without `client`, they build the client on a request and keep it
once built. Until then a guarded route answers **500** with `Cache-Control: no-store`, and the protected
handler or action never runs:

```json
{"touchque":{"state":"blocked","reason":"misconfigured"},"error":{"code":"misconfigured","message":"Two-factor approval is not configured correctly."}}
```

A request with no signed-in user still gets the usual 401 `unauthenticated`. Settings that cannot work (a key
that does not start with `tq_`, a plaintext `http://` `TQ_API_URL` other than localhost) answer the same 500.
`@touchque/web` shows "Approvals are not set up correctly on this site." Nothing is logged: the SDK writes
nothing on its own, and without a client it has no logger.

- To fail fast instead, call `getDefaultClient()` at startup: it builds the default client and throws a
  `TouchqueConfigError` that names the problem.
- To have a logger on these paths, set the default client yourself:
  `setDefaultClient(new Touchque({ logger: console }))` (your pino or winston works too). The adapters and
  `runGuard(null, …)` then use it. `new Touchque()` throws without the keys, as `getDefaultClient()` does: set
  it only when they are present, or catch the `TouchqueConfigError` to keep the 500 answer.
  `setDefaultClient(null)` forgets it, and the next request builds one from the environment again.

## Guard inside your handler

When the approval belongs in the middle of your handler, after your own checks (the balance, who owns the
record), call `runGuard` there instead of using a middleware. It is what the adapters run:

```typescript
import { runGuard, guardResponse, GUARD_HEADERS } from '@touchque/node';

app.post('/transfer', async (req, res) => {
  // Your checks first: a transfer you would refuse never reaches the phone.
  const t = await transfers.draft(req.user.id, req.body.transferId);
  if (!t) return res.status(404).json({ error: 'not_found' });
  if (t.amount > await accounts.balance(req.user.id)) return res.status(422).json({ error: 'insufficient_funds' });

  // null: the default client, built from TQ_API_KEY / TQ_API_SECRET on a request and kept.
  const result = await runGuard(null, {
    user: req.user.email,
    action: 'SEND_MONEY',
    details: { Amount: `${t.amount} EUR`, To: t.iban },   // from your records, bound to the approval
    referenceId: t.id,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    token: req.get(GUARD_HEADERS.token),
    offline: req.get(GUARD_HEADERS.offline) === '1',
    code: req.get(GUARD_HEADERS.code),
    codeType: req.get(GUARD_HEADERS.codeType),
  });
  if (!result.approved) {
    // The 202 step or the refusal, exactly as requireTouchque would send it.
    const { status, headers, body } = await guardResponse(result);
    return res.status(status).set(headers).json(body);
  }
  // Approved, and the approval is used up: do the protected thing now, once.
  await transfers.send(t.id);
  res.json({ ok: true, assurance: result.approved.assurance });
});
```

`runGuard(client, input)` never throws for a Touchque problem. Pass `null` for the default client, the one the
adapters use: it is built from `TQ_API_KEY` / `TQ_API_SECRET` on a request and kept once built, so a missing
key answers 500 `misconfigured` (401 without a `user`) instead of stopping your app at startup. Or pass your
own `Touchque`. It returns either `{ approved, status: 200 }` or `{ status, body }`. To fail fast, call
`getDefaultClient()` at startup (it throws a `TouchqueConfigError` that names the problem). The null path
logs nothing; for a logger, set `setDefaultClient(new Touchque({ logger: console }))` at startup. Like
`getDefaultClient()`, `new Touchque()` throws without the keys: set it only when they are present, or catch the
`TouchqueConfigError` to keep the 500 answer.

`guardResponse(result, { errorBody?, logger? })` turns a result that is not approved into
`{ status, headers, body }`: what `requireTouchque` and `withTouchque` send, as they use it too.
`Cache-Control: no-store`; `Retry-After` on 423 and 429; `X-Touchque-State` and `X-Touchque-Reason` on 400
or more; your `errorBody` shape. Send `body` with your framework's JSON (in a Fetch handler,
`Response.json(body, { status, headers })`).

The contract, the same in every Touchque server SDK:

- **202** `{ touchque: step, token }`: show the step (a number to pick on the phone, the first-time QR, the
  offline QR). The page sends the same request again with `X-Touchque-Token: <token>` every ~1.5 s until it
  is approved or refused; `@touchque/web`'s `touchqueFetch` does this loop. Every answer while the push or
  passkey waits (`waiting`, `passkey_required`) carries the request's current `expiresAt`, so a page can stop
  once it has passed. It can move later: a push tapped during a call moves to a passkey with 180 s more.
- While the first-time QR is up, polls answer `{ state: 'enroll', expiresAt }` without `enroll`: keep
  showing the QR you have. About 15 s before it expires, a poll brings a new QR (`enroll.qrCodeDataUrl`) with
  new recovery codes; the old QR and the old codes stop working. Pages on `@touchque/web` need 2.1.0.
- Pass `enroll: false` when `user` is not proven by your own sign-in (a typed username before the password
  step). A user with no phone then gets 202 `{ state: 'enroll', reason: 'enrollment_off' }`: a final answer
  with no QR. Stop polling and ask them to link the Touchque app first (`@touchque/web` 2.2.0 does).
- A 202 state other than `waiting` or `enroll` without a reason (`passkey_required`, `offline`, `enroll` with
  a `reason`) needs `@touchque/web`, or your own UI following this contract.
- **200** with `approved` (`requestId`, `assurance`, `approvalProof`, …): approved once for this user,
  action, details and `referenceId`. The same token never approves twice.
- **401** `unauthenticated` (no `user`), **403** `rejected` or `blocked` (see `reason`), **408** `expired`,
  **423** `frozen` and **429** `rate_limited` (both with `retryAfter`), **500** `misconfigured` (an action
  type that is not defined, or no API key), **503** `unavailable` (Touchque could not be reached).

`beforeStart` in the input is plumbing for relays with a rate limit (`touchqueRouter` and `touchqueRelay` pass
one): `runGuard` calls it when a poll on the first-time QR is about to start something (the push once the phone
is linked, or a new QR), so the relay can charge that like a new attempt. A handler that guards one route
does not need it.

## Passkeys (phishing-resistant)

Push approval and offline codes stop password reuse and push fatigue, but a
real-time phishing proxy can still relay them. A passkey can't be phished: the
browser signs your site's real origin and Touchque refuses any other
(NIST SP 800-63B-4 §3.2.5).

1. Set your passkey domain in the Dashboard (Developers → App user policy).
2. Let users register one via `tq.webauthn` (server) + `@touchque/web`'s
   `passkeys.register()` (browser).
3. Optionally require it for critical actions or every sign-in — Touchque then
   skips the push and your route resolves `passkey_required` instead.
4. Check `assurance.phishingResistant` before treating a session as high-assurance.

## Offline approval (no internet on the phone)

```typescript
const ch = await tq.offline.challenge({
  externalUsername: 'jane@acme.com',
  type: 'WITHDRAW',
  details: { Amount: '1,250.00 USD', Recipient: 'Jane Doe' },
});
// show ch.qrDataUrl — the phone scans it offline and shows a 7-character code

const { approved } = await tq.offline.verify({ challengeId: ch.challengeId, code });
```

**A QR that follows a push.** Pass the push's `requestId` when the offline QR is the fallback for a
push the user already started (`requireTouchque` / `touchqueRouter` do this for you):

```typescript
const ch = await tq.offline.challenge({ externalUsername, type: 'LOGIN', requestId: step.requestId });
// ch.challengeCode is the number to print under the QR when number matching applies.
```

- If the user **rejects the push on the phone, the offline QR dies with it**: no new QR is issued for that
  sign-in (`409 request_rejected`), a code for a QR already on screen is refused (`reason: 'request_rejected'`)
  and so is the time-based code (`verifyTotp({ …, requestId })`). Treat it as a final "no".
- With number matching, the page prints `ch.challengeCode` under the QR; the phone shows it among two decoys
  after scanning and the user taps the one that matches. The phone is never told which is right — a wrong tap
  produces a code that fails verification.

## Webhooks

```typescript
import { MemoryWebhookReplayCache, WebhookEvents, WebhookReasons } from '@touchque/node';
const replayCache = new MemoryWebhookReplayCache();

app.post('/webhooks/touchque', express.raw({ type: 'application/json' }), (req, res) => {
  try {
    const payload = tq.webhook.verify({
      rawBody: req.body.toString(),
      signature: req.headers['x-signature'] as string,
      replayCache,
    });
    if (payload.event === WebhookEvents.APPROVAL_REVOKED) endSessionsBuiltOn(payload.requestId); // see below
    else if (payload.status === 'REJECTED' && payload.reason === WebhookReasons.USER_REPORTED_COACHED) lockAccount(payload.externalUsername);
    res.sendStatus(200);
  } catch {
    res.sendStatus(403); // not from Touchque
  }
});
```

Login results carry `status` (`SUCCESS` | `REJECTED`) and, when rejected, a `reason` (`WebhookReasons`):
`user_rejected`, `user_reported_fraud`, `user_reported_coached` (the user said someone on the phone told
them to approve), `risk_reversed`, `risk_step_up`, `approval_signature_invalid`, `device_integrity_failed`,
`vishing_suspected` and `phishing_origin` (see Vishing Shield). Treat a reason you do not know as a rejection.
Event webhooks carry `event` (`WebhookEvents`): `DEVICE_LINKED`, `DEVICE_UNLINKED`, `PASSKEY_REGISTERED`,
`PASSKEY_DELETED`, `APPROVAL_RECONFIRMED`, `APPROVAL_REVOKED`. Ignore events you do not know.
Touchque also sends `MOBILE_PUSH` (Mobile SDK: send the push with your own keys, `mobilePushFromWebhook`), the
Never Locked Out events `RECOVERY_STARTED`, `RECOVERY_DEVICE_BOUND`, `RECOVERY_COOLING`, `RECOVERY_COMPLETED`,
`RECOVERY_VETOED`, `RECOVERY_EXPIRED`, `RECOVERY_FAILED` (with `recoveryId`), and the help-desk events
`ASSIST_OPENED`, `ASSIST_ENDED`, `ASSIST_CHECK_PASSED`, `ASSIST_CHECK_FAILED`, `ASSIST_UNFROZEN`,
`ASSIST_CLAIM_CONFIRMED`, `ASSIST_CLAIM_UNVERIFIED` (page someone on the last two failures: someone may be
pretending to be IT). All are in `WebhookEvents`.

## Vishing Shield (someone on the phone guiding the user)

The phone tells Touchque, signed with its hardware key, whether a call was active (or just ended), the screen
was shared or the phone remote-controlled when the user tapped Approve. Depending on the server's mode:

- **Passkey instead.** A user with a passkey finishes in the browser: the request stays open and turns into
  `passkey_required` mid-flight. The step-up flow (`start` / `check`, the guard, `touchqueRouter`) and
  `@touchque/web` handle it; the blocking `login.waitForApproval` / `login.verify` / `tq.protect` throw
  `TouchquePasskeyRequiredError` with `reason: 'step_up'`. No offline or recovery code can finish such a request.
- **Refused.** A critical action without a passkey is rejected (`reason: 'vishing_suspected'`).
- **Provisional.** Anything else is approved with `provisional: true` (on the `Approval`, `GET /login/status`,
  consume and the SUCCESS webhook). Let the user in, but treat the session as limited: Touchque refuses the
  user's critical actions (`blocked` / `provisional`) until the phone re-confirms after the call
  (`APPROVAL_RECONFIRMED`). `APPROVAL_REVOKED` (`reason: 'COACHED' | 'UNDO'`) means end the session; an approval
  revoked before you consumed it can no longer be consumed (409 `revoked`).

**Mirror Alarm.** Every waiting step carries `canary.url` once. `@touchque/web` loads it on the page showing the
sign-in and sends a beacon to it, so a real-time phishing proxy in front of your site shows up as itself: the
approval is refused (`reason: 'phishing_origin'`) and the phone warns the user. Allow the canary host in your
Content-Security-Policy (`img-src` and `connect-src`).

## Touchque Actions (your code in the approval pipeline)

Alerts, step-ups and refusals by country, local time, role or amount, passkeys
for admins — from a template or a few lines of JavaScript, replayed against your
real recent sign-ins before they go live. Full guide: [support.touchque.com/actions](https://support.touchque.com/actions).

```ts
import type { LoginRequestEvent, LoginRequestApi } from '@touchque/node';

// A no-code template
await tq.actions.deploy('night-alert', {
  trigger: 'approval.decided',
  template: { id: 'alert', params: { channel: 'slack', when: { countries: ['TR'], hours: { from: 0, to: 6 } } } },
});

// Your own typed function (self-contained: it is sent as source text)
await tq.actions.deploy('admins-use-passkeys', {
  trigger: 'login.request',
  handler: async (event: LoginRequestEvent, api: LoginRequestApi) => {
    if ((event.context?.roles as string[] | undefined)?.includes('admin')) api.requirePasskey('Admins approve with a passkey');
  },
});

// Before deploying: how many of the last 500 real decisions would it change?
const report = await tq.actions.dryRun({ trigger: 'login.request', handler: myDraft });
// report.transitions → { 'push→passkey': 12 }
```

Give Actions what only your server knows with `context` (never shown on the phone):
`requireTouchque('SEND_MONEY', { context: (req) => ({ roles: req.user.roles, amount: req.body.amount }) })`.
Loosening calls (`skipNumberMatch`, `overrideBlock`, `allowSilent`) need a capability an
admin approves on their phone. Action types moved to `tq.actionTypes` in 4.0.

## AI agents (an identity per agent, never your API key)

Register each agent with its **public** key; the private key stays where the agent runs. The agent then signs in
with its own key and gets a 10-minute token bound to that key (DPoP), so a leaked token is useless on its own.

```ts
import { Touchque, TouchqueAgent, generateAgentKey } from '@touchque/node';

// Once, from your server (needs an API key with the agents:write scope):
const { privateJwk, publicJwk } = generateAgentKey();           // or generate it where the agent runs
const agent = await tq.agents.create({
  name: 'Invoice bot',
  allowedTypes: ['PAY_INVOICE'],         // the only approvals it may ask for
  publicKey: publicJwk,
  ownerEmail: 'ada@acme.com',            // accountable person; the agent stops if they leave
  platform: 'openai-agents',
});
// Store agent.id and privateJwk in the agent's secret store (TQ_AGENT_ID, TQ_AGENT_KEY).

// In the agent:
const me = await new TouchqueAgent().me();   // reads TQ_AGENT_ID / TQ_AGENT_KEY
```

Stop an agent at once with `tq.agents.suspend(id)` or every agent with `tq.agents.setKillSwitch(true)`; its
tokens stop working immediately.

### The agent asks, the person approves on the phone, your server executes once

```ts
// In the agent: structured details, never free text; Touchque draws the phone's rows.
const ask = await agent.requestApproval({
  user: 'jane@example.com', type: 'PAY_INVOICE', reason: 'October rent',
  authorizationDetails: [{ type: 'payment_initiation', instructedAmount: { currency: 'TRY', amount: '500.00' },
    creditorName: 'Jane Doe', creditorAccount: { iban: 'TR33 0006 1005 1978 6457 8413 26' } }],
});
reply(`Type ${ask.challengeCode} in the Touchque app to approve.`);
const { approvalToken } = await agent.waitForApproval(ask.approvalId);

// In your executor, right before paying: used once, and only for what you are about to do.
const approval = await tq.agents.redeemApproval(approvalToken, {
  user: 'jane@example.com', type: 'PAY_INVOICE',
  authorizationDetails: { type: 'payment_initiation', instructedAmount: { currency: 'TRY', amount: '500.00' }, creditorAccount: { iban } },
});
```

### In your agent framework

A policy says who approves which tool calls and what their phone shows; the tool
runs only after the person approved, and `currentApproval()` holds the approval
token inside it. The wrapped function keeps its arguments, so it drops into
LangChain's `tool()`, the Vercel AI SDK's `execute`, LlamaIndex's `FunctionTool`
and the OpenAI Agents SDK's `tool({ execute })`.

```ts
import { withTouchqueApproval, currentApproval, approveInterruptionsWithTouchque, touchqueCanUseTool, guardMcpClient } from '@touchque/node';

const policy = {
  agent, user: 'jane@example.com', type: 'PAY_INVOICE',
  details: ({ iban, amount }) => [{ type: 'payment_initiation', instructedAmount: { currency: 'TRY', amount }, creditorAccount: { iban } }],
  onChallenge: (s) => reply(`Type ${s.challengeCode} in the Touchque app to approve.`),
};
const payInvoice = tool(withTouchqueApproval(async ({ iban, amount }) => bank.pay(iban, amount, currentApproval().approvalToken), policy), { name: 'pay_invoice', schema });

// OpenAI Agents SDK (tools with needsApproval): ask the phone for each interruption, then resume.
const state = await approveInterruptionsWithTouchque(result, { pay_invoice: policy });
// Claude Agent SDK: query({ prompt, options: { canUseTool: touchqueCanUseTool({ pay_invoice: policy }) } })
// Any MCP client: the token reaches the server in _meta['touchque/approvalToken'].
const guarded = guardMcpClient(mcpClient, { pay_invoice: policy });
```
 Agents also stop when their review date passes (`update(id, { reviewInDays })`
renews it) and when their owner leaves the organization.

### Cross App Access (ID-JAG) and A2A agent cards

An organization's identity provider (Touchque SSO) can let one of its apps reach another service for a member with no consent screen (Cross App Access, ID-JAG, an open IETF draft): the app trades the member's ID token for an ID-JAG, then the ID-JAG for an access token at the other service. If you run an authorization server, the verifier checks an ID-JAG (issuer, single audience, your client, expiry, `typ`) and uses it once. Before your agent trusts another agent's A2A card, check its signatures (A2A 1.0 §8.4: JWS over the RFC 8785 canonical card); keys named by `jku` are only fetched from the card's own host or hosts you trust.

```ts
import { requestIdJag, redeemIdJag, IdJagVerifier, verifyAgentCard } from '@touchque/node';

const { assertion } = await requestIdJag({ issuer: 'https://sso.touchque.com', clientId, clientSecret, idToken, audience: 'https://auth.files.example' });
const tokens = await redeemIdJag({ tokenEndpoint: 'https://auth.files.example/token', clientId: 'acme', clientSecret: filesSecret, assertion });

// Your own authorization server (jwt-bearer grant):
const idJag = new IdJagVerifier({ issuer: 'https://sso.touchque.com', audience: 'https://auth.files.example' });
const claims = await idJag.verify(form.assertion, { clientId: authenticatedClientId });

await verifyAgentCard(card, { cardUrl: 'https://agent.example/.well-known/agent-card.json' });
```

## Shared Signals (security events from Touchque SSO)

Touchque SSO sends Security Event Tokens (OpenID Shared Signals Framework 1.0, RFC 8417) for an organization's
members to the receivers its admin adds (Organization > Continuous access) when something happens after sign-in:
CAEP `session-revoked`, `credential-change`, `device-compliance-change`; RISC `account-disabled`,
`credential-compromise`. Your app ends the person's sessions or asks them to sign in again. The verifier reads the
transmitter's keys from its `/.well-known/ssf-configuration` and checks the signature (RS256), `typ`, issuer,
audience and that the SET carries exactly one event.

```typescript
import express from 'express';
import { SecurityEventVerifier, SecurityEventError, pollSecurityEvents } from '@touchque/node';

const verifier = new SecurityEventVerifier({ issuer: 'https://sso.touchque.com', audience: 'https://app.example.com' });

// Push delivery (RFC 8935): the SET is the request body.
app.post('/ssf', express.text({ type: 'application/secevent+jwt' }), async (req, res) => {
  try {
    const event = await verifier.verify(req.body);
    if (event.name === 'session-revoked') await endSessionsOf(event.subject.email);
    res.status(202).end();
  } catch (err) {
    if (!(err instanceof SecurityEventError)) throw err;
    res.status(err.code === 'temporarily_unavailable' ? 503 : 400).json({ err: err.code, description: err.message });
  }
});

// Poll delivery (RFC 8936): the stream's poll endpoint and token; each poll acknowledges what you handled.
let ack: string[] = [];
const { sets, moreAvailable } = await pollSecurityEvents({ url: pollUrl, token: streamToken, ack }); // poll again at once while moreAvailable
ack = [];
for (const [jti, set] of Object.entries(sets)) {
  await handle(await verifier.verify(set));
  ack.push(jti);   // sent with the next poll
}
```

`verify` returns `{ jti, issuer, audience, issuedAt, txn, subject, type, name, claims }`; `txn` is the case code of
Touchque's decision ("Why?"). A refusal is a `SecurityEventError` whose `code` is the RFC 8935 error to answer with
(`invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience`), or `temporarily_unavailable` when the keys
could not be read (answer 503: the transmitter tries again). A SET does not expire: keep the jtis you handled and skip
a repeat. `SECURITY_EVENT_TYPES` maps the short names to the event type URIs.

## Silent sign-ins (stop asking when nothing is new)

A user who approved on their phone in this browser a little while ago, from the same phone, network and country,
with no risk signal since, does not need another push. Touchque's risk engine decides; your server only skips the
push when it says so.

1. In the browser, `@touchque/web` 2.0.0 with `createTouchqueWeb({ browserKey: true })` keeps a non-extractable
   key for your site and sends a fresh, signed proof of it in the `X-Touchque-Browser` header.
2. On the server, turn on `silentSignIn`:

```typescript
app.post('/login/2fa',
  requireTouchque('LOGIN', { user: (req) => req.session.passwordOkUser, silentSignIn: true }),
  (req, res) => {
    // req.touchque.assurance.method is 'silent' when no push was needed.
    res.json({ ok: true });
  });

app.use('/touchque', touchqueRouter(tq, {
  getUserId: (req) => req.session.user?.email,
  getLoginUser: (req) => req.session.passwordOkUser,
  silentSignIn: true, // or { maxAgeSeconds: 8 * 3600 } for your own limit
}));
```

`withTouchque` takes the same option. With it on, a new attempt that carries the header first calls
`tq.risk.check`. Only an answer of exactly `prompt: false` approves it at once, with nothing sent to the phone:
the approval has `assurance: { method: 'silent', phishingResistant: false }`, `confirmedVia: 'SILENT'`,
`requestId: 'silent'` and `reasons` (`known_browser`, `recent_approval`, `same_phone`, `familiar_network`,
`no_risk_signal`); `touchqueRouter` calls `onAuthenticated` with `via: 'silent'`. Anything else, and any error in the
check, starts the usual push with the proof attached, so its approval makes the browser known. Polling with the
token never checks again.

Touchque only lets a sign-in through silently when all of this holds: the browser proved its key and was approved
on the phone (a confirmed push, not one approved during a call, or a passkey) within your `maxAgeSeconds` and at most
7 days ago, by the phone that is linked now; the country and the network were seen in the user's earlier approved
sign-ins; the risk engine allows it with no risk signal; and the action is an everyday one. A critical action always
asks. In `shadow` mode (`silentMode`) it always asks and the reasons say what would have happened.

Without the adapters:

```typescript
const browserProof = req.get('x-touchque-browser');
const risk = await tq.risk.check({ externalUsername: user, type: 'LOGIN', clientIp: req.ip, browserProof });
if (risk.prompt === false) return openSession(user); // risk.reasons say why
const step = await tq.start('LOGIN', { user, ip: req.ip, browserProof }); // the approval makes the browser known

const { browsers } = await tq.risk.browsers({ externalUsername: user });      // for an "approved browsers" list
await tq.risk.forgetBrowsers({ externalUsername: user });                    // all; or { thumbprint } for one
```

Forget a user's browsers after a password reset or a "sign out everywhere". `risk.check` reads the answer fail-closed:
`prompt` is `false` only when Touchque answered the boolean `false`.

## Never Locked Out (lost, dead or new phone)

A user whose phone is gone moves to a new phone without a help desk. Colleagues they named beforehand vouch on their own
phones, each typing a number the user reads them on a call; then a cooling-off (default 60 minutes) lets the old phone, any
voucher or an admin stop it. The risk engine can refuse it or ask for more vouchers, and for 24 hours afterwards critical
actions are refused. It is an option: offer it next to passkeys and the old phone's transfer, never as the only way.

```ts
// Settings page, after an approval on the user's phone:
await tq.recovery.setVouchers({ externalUsername: user, vouchers: ['bo@acme.com', 'cy@acme.com'] });

// "I lost my phone", after the password:
const r = await tq.recovery.start({ externalUsername: user, clientIp: req.ip, displayName: 'Ada', fallbackVouchers: admins });
showQr(r.bindUri);                     // the Touchque app on the new phone scans it
const now = await tq.recovery.status(r.recoveryId);
now.vouchers.forEach((v) => show(v.externalUsername, v.code)); // read each code to that colleague
// now.status: AWAITING_DEVICE → VOUCHING → COOLING → COMPLETED (or VETOED / EXPIRED / FAILED)

// An admin who does not believe it:
await tq.recovery.veto(r.recoveryId, { by: 'admin@acme.com' });
```

Every step is a hash-chained receipt (`receipts`); a voucher's step carries the signature of their phone's hardware key.

## "Why?": case codes instead of guesswork

Every approval decision names a short case code (`K7P-2QX`: 6 characters, no I, O, 0 or 1). A user who was asked to
match a number, needed a passkey or was refused reads it out to your support team, and the team opens the whole
decision by it in the Touchque dashboard (Logs → Look up a case): what went in, each check's verdict (the access rule
that matched, the risk signals that were acted on and the ones only measured), and the single change that would have
let it through. No screenshots, no log digging. The code opens nothing on its own: only your workspace sees its
decisions.

```ts
const step = await tq.start('WITHDRAW', { user, ip: req.ip });
// step.caseCode → 'K7P-2QX'; step.reasons → [{ code: 'critical_action', text: 'The action is marked critical' }]
try {
  await tq.login.request({ externalUsername: user, type: 'LOGIN' });
} catch (err) {
  if (err instanceof TouchqueAPIError && err.caseCode) show(`Tell your support team: ${err.caseCode}`);
}
```

`caseCode` is on `LoginRequestResponse`, `RiskCheckResult`, `TouchqueAPIError` and every step (the guard keeps it
while it waits); `reasons` says why number matching or a passkey is needed, from a fixed list, never a score.

## Blocking `verify()` and number matching

`login.verify()` sends the request and waits for the phone in one call. With number matching (your option, a
workspace policy, a critical action or the risk engine can turn it on) the phone asks the user to pick a number,
and the call returns only after they have. Pass `onChallenge`: it runs once, right after the request is created and
before the wait. **Show `challengeCode` to the user now; the phone asks for it.**

```typescript
await tq.login.verify({
  externalUsername: user, type: 'SEND_MONEY',
  onChallenge: ({ challengeCode, caseCode }) => {
    if (challengeCode) socket.emit('touchque', { text: `Pick ${challengeCode} on your phone`, caseCode });
  },
});
```

It gets `{ requestId, challengeCode?, expiresAt, reasons?, caseCode? }`. It is not called when only a passkey can
approve (`verify()` throws `TouchquePasskeyRequiredError` first). An error it throws, or a promise it returns that
rejects, is logged and ignored: `verify()` keeps waiting. `tq.protect()` takes the same `onChallenge`. In a web
request, where the page hears nothing until you answer, use the router or `tq.start()`: their first answer already
carries the number.

## Verifying the device proof (no need to trust Touchque)

When the phone holds a hardware key, every approval carries `approvalProof`: the
phone's own signature over the request id, action, number-match code and the
exact details it showed. Check it yourself and pin the device key:

```typescript
import { verifyApprovalProof } from '@touchque/node';

const ok = verifyApprovalProof(event.approvalProof, {
  requestId, type: 'WITHDRAW', details, challengeCode,
  expectedPublicKey: user.touchqueDeviceKey, // stored from their first verified approval
});
```

Without `expectedPublicKey` it returns `false` unless you pass
`allowUnpinnedKey: true` (trust on first use — store `proof.publicKey`, then pin it).

## Reporting fraud

Learned later that an approved request was fraud (a chargeback, an account
takeover)? Report it — it is the strongest signal Touchque's risk engine learns
from, and it stays in your audit log:

```typescript
await tq.login.reportFraud(requestId, { reason: 'chargeback', note: 'Disputed by card holder' });
// reason: 'chargeback' | 'account_takeover' | 'social_engineering' | 'other'
```

## Pairing a browser by QR code

Your page shows a QR code, the person scans it with the Touchque app, and the phone that scanned is the one asked to approve, with number matching. Your page sends the thumbprint of its browser key (`@touchque/web` `browserKey.thumbprint()`); the nonce in the QR never leaves your server (Touchque keeps its hash).

```ts
const p = await tq.qrPairings.create({ keyThumbprint, clientIp: req.ip, userAgent: req.get('user-agent') });
// show p.uri (touchque://pair-browser?…) as a QR code; poll:
const now = await tq.qrPairings.get(p.pairingId);   // waiting → scanned → confirmed
if (now.state === 'confirmed') await tq.login.request({ externalUsername: now.externalUsername!, type: 'LOGIN', qrPairing: p.pairingId });
// or: await tq.qrPairings.refuse(p.pairingId, { reason: 'device_not_approved', message: 'Ask IT to approve this computer.' });
```

`get` says `scanned` / `confirmed` once a phone holding one of your users' accounts read it (with `proximity`: same network, same country), `reported` when the person said someone told them to scan it (their 2FA freezes). `refuse` tells the phone why your own checks said no.

## A code typed back on the phone

When a sign-in needs a code another service sent the person (a text message, WhatsApp, e-mail), ask them to type it on the phone instead. The phone encrypts it to a one-time key you made for this request: Touchque only ever holds the ciphertext. Such a request lives 5 minutes.

```ts
const key = newCodeReplyKey();   // keep key.privateKey for this request
const sent = await tq.login.request({ externalUsername: user, type: 'LOGIN', reply: { kind: 'code', key: key.publicKey, channel: 'sms', target: '+**********26' } });
const status = await tq.login.status(sent.requestId);   // once CONFIRMED
const code = status.reply ? openCodeReply(key.privateKey, sent.requestId, status.reply.ct) : null;
```

## Safe Guard (Safe transactions approved on the phone)

TouchqueSafeGuard is a transaction guard for a Safe: a transaction runs only with approvals signed by the P-256 keys on its approvers' phones. You send the raw transaction; the phone decodes it itself, shows its own rows and signs what it computed with a key only its biometrics unlock. Delegatecalls, changes to the Safe and proxy upgrades are governance: scheduled, time-locked and vetoable. A phone without that key yet gets `409 crypto_key_missing`.

```ts
const sent = await tq.safeGuard.request({
  externalUsername: 'treasurer@acme.com',
  type: 'safe_payment',   // an action type from your dashboard
  safeTx: {
    chainId: 1, safe, guard, tx: { to, value: '0', data, operation: 0, nonce: 42 },
    config: { threshold: 2, govThreshold: 3, govDelay: 172800, exitDelay: 259200 },
    batchTargets: [multiSendCallOnly],
    approverIndex: 0,     // this approver's index in the guard
  },
});
const done = await tq.safeGuard.waitForApproval({ requestId: sent.requestId });   // 5 minutes at most
const approval = done.safeTx!.approval!;

// Check it yourself: your own transaction, the approver's key from the guard on chain, and the
// purpose you will use it for (the signature must cover it, so one is never taken for the other).
const purpose = done.safeTx!.purpose;   // 'approve' (execTransaction) or 'schedule' (a governance change)
const check = verifySafeApproval({ chainId: 1, safe, guard, tx }, approval, approverKey, { approverIndex: 0, purpose });
if (!check.valid) throw new Error(`approval refused: ${check.reason}`);
if (purpose === 'approve') {
  const signatures = withSafeApprovals(ownerSignatures, [approval]);   // execTransaction(…, signatures)
} else {
  const data = safeScheduleCall(safe, check.governanceHash, [approval]);   // a call to the guard; runs after govDelay
}
```

`verifySafeApproval` makes the guard's check off chain, so a co-signer or your own server never has to trust Touchque: it computes the Safe transaction hash (EIP-712) and the governance hash from the raw fields, rebuilds the 149-byte message the phone signed and checks the P-256 signature for one purpose: `approve` unless you pass `purpose: 'schedule'`, so an approval to schedule a governance change (which leaves out the Safe nonce and gas) never passes as one to execute. It refuses a high `s`, an approval that expired or is valid for more than a day, another approver index, and, when you pass `rows` or `displayDigest` from your own decoding, rows the phone did not show. `reason` is `approval_malformed`, `public_key_invalid`, `approver_index_mismatch`, `approval_expired`, `rows_differ`, `high_s` or `signature_invalid`. `safeTxHash`, `safeGovernanceHash`, `safeApprovalMessage` and `safeDisplayDigest` are exported too.

## Touchque Login (hosted sign-in)

Sign-up and sign-in pages for your own customers, on your brand, over OpenID Connect: at
`https://<slug>.login.touchque.com` or your own domain. In the dashboard, add **Touchque Login** under
**Organization → Modules**, then follow the guide under **Touchque Login → Setup**: you choose your sign-in
address and add your first app. More apps are under **Touchque Login → Setup → Apps** (**Add app**), each
with its **Callback URLs**. The full guide (Next.js, single-page apps, the Management API):
[support.touchque.com/touchque-login](https://support.touchque.com/touchque-login).

`HostedLogin` is the OpenID Connect client. Every sign-in uses PKCE (S256), `state` and `nonce`, and the ID
token is checked against your tenant's keys: signature, issuer, audience, expiry, nonce and `at_hash`.

```typescript
import { HostedLogin, HostedLoginError } from '@touchque/node';

const login = new HostedLogin({
  domain: 'acme.login.touchque.com',                // or your own domain
  clientId: process.env.TQ_LOGIN_CLIENT_ID!,
  clientSecret: process.env.TQ_LOGIN_CLIENT_SECRET,  // apps with a server; single-page and native apps leave it out
  redirectUri: 'https://app.acme.com/callback',      // registered on the application
  scope: 'openid profile email offline_access',      // offline_access: a refresh token too
});

// 1. Send the browser to `url`. Keep state, nonce and codeVerifier for the callback
//    (in your session or a short-lived HttpOnly cookie).
const { url, state, nonce, codeVerifier } = login.authorizationUrl({ screenHint: 'signup' });

// 2. On the callback: checks state, exchanges the code with the PKCE verifier, verifies the ID token.
try {
  const tokens = await login.handleCallback(req.originalUrl, { state, nonce, codeVerifier });
  tokens.claims?.sub;    // who signed in; also email, email_verified, name, org_id, amr…
  tokens.accessToken;    // expiresAt is in Unix seconds
  tokens.refreshToken;   // with offline_access; login.refresh() rotates it: keep the new one
} catch (err) {
  if (!(err instanceof HostedLoginError)) throw err;
  // err.code: state_mismatch, access_denied, invalid_grant…
}
```

- `new HostedLogin(config)`: `domain` and `clientId` are required. `domain` is your sign-in domain or the full
  issuer URL, and must be `https://` (`http://` only on localhost). Also `clientSecret`, `redirectUri`, `scope`
  (default `openid profile email`), `audience` (an access token for your API) and `clockToleranceSec`
  (default 60).
- `fetch`: the function `HostedLogin` calls Touchque with (default: the global `fetch` of Node.js 18+). Pass
  your own to go through a proxy, add a timeout, or test without the network.
- `authorizationUrl(options?)` returns `{ url, state, nonce, codeVerifier }`. Options: `screenHint: 'signup'`
  (the sign-up page), `loginHint` (fills in the email), `prompt`, `uiLocales` (`tr`, `en`…), `maxAge`,
  `connection` (straight to Google, Apple or an enterprise connection), `organization`, `invitation`,
  `acrValues`, `audience`, `scope`, `redirectUri`, `responseMode` and `extraParams`.
- `handleCallback(input, { state, nonce, codeVerifier, redirectUri?, maxAge? })` returns a `TokenSet`. `input`
  is the callback URL (a string or a `URL`), its `URLSearchParams`, or the posted fields with
  `responseMode: 'form_post'`.
- `TokenSet`: `accessToken`, `tokenType`, `expiresAt`, `scope`, `idToken`, `refreshToken`, and `claims`: the
  verified ID token's claims (`IdTokenClaims`: `sub`, `email`, `email_verified`, `name`, `given_name`,
  `family_name`, `picture`, `locale`, `org_id`, `org_name`, `amr`, `acr`, `auth_time`, `sid` and your own).
- `HostedLoginError` is a `TouchqueError` with `code`, `description` and `status` (the HTTP status when
  Touchque answered). `code` is the OAuth error from the page or the token endpoint (`access_denied`,
  `invalid_grant`, `login_required`…), or one of the SDK's own checks: `config`, `state_mismatch`,
  `issuer_mismatch`, `nonce_mismatch`, `invalid_token`, `invalid_request`, `jwks_unavailable`,
  `insufficient_scope` (status 403).
- Also on the client: `refresh(refreshToken)`, `logoutUrl({ idTokenHint, postLogoutRedirectUri })`,
  `revoke(token)`, `userinfo(accessToken)`, `verifyAccessToken(token, { audience, requiredScopes })` for your
  API, `clientCredentials({ audience })` (machine to machine), `exchangeToken` (RFC 8693),
  `getConnectionToken` (the provider's token from the token vault), `askUser` and `waitForUser` (the person
  approves on the phone, CIBA), `myAccountToken`, `myAccount` and `accountUrl()`.

With Express, three helpers do the routes and keep the session in an encrypted cookie (no store needed):

```typescript
import { hostedLoginRoutes, requireSignIn, requireAccessToken } from '@touchque/node';

app.use(hostedLoginRoutes({ login, secret: process.env.SESSION_SECRET! }));   // /login, /callback, /logout
app.get('/account', requireSignIn(), (req, res) => res.json(req.touchqueSession!.user));
app.get('/api/orders', requireAccessToken(login, { audience: 'https://api.acme.com', scopes: ['read:orders'] }), handler);
```

`secret` is at least 32 random characters. `requireSignIn()` refreshes the access token shortly before it
expires (with `offline_access`) and sends a signed-out browser to `/login?returnTo=…`; `{ api: true }` answers
401 JSON instead. In Next.js (App Router), `createTouchqueLogin({ domain, clientId, clientSecret, secret,
appUrl })` gives the route handlers and `getSession()`, and `touchqueMiddleware` from
`@touchque/node/next/middleware` protects pages on the Edge.

## Testing your routes

`@touchque/node/testing` has `FakeTouchque`: a `Touchque` client that answers in memory, with no network, no
API keys and no dependency of its own. The real guard runs, so your routes answer what they answer in
production, and your test plays the phone:

```typescript
// transfer.test.ts
import { test, expect, beforeEach, afterEach } from 'vitest'; // in Jest these are globals: leave this line out
import express from 'express';
import request from 'supertest';
import { requireTouchque } from '@touchque/node';
import { FakeTouchque } from '@touchque/node/testing';

const app = express(); // your app: its guards are given no `client`
app.use(express.json());
app.use((req, _res, next) => { (req as any).user = { email: 'jane@acme.com' }; next(); }); // your sign-in
app.post('/transfer',
  requireTouchque('SEND_MONEY', { details: (req) => ({ Amount: `${req.body.amount} EUR` }) }),
  (_req, res) => res.json({ ok: true }));

let tq: FakeTouchque;
beforeEach(() => { tq = new FakeTouchque().install(); }); // the default client until uninstall()
afterEach(() => tq.uninstall());

test('a transfer waits for the approval on the phone', async () => {
  const first = await request(app).post('/transfer').send({ amount: 5 });
  expect(first.status).toBe(202);
  expect(first.body.touchque.state).toBe('waiting');

  tq.approve(); // the person approves on the phone
  const done = await request(app).post('/transfer').set('X-Touchque-Token', first.body.token).send({ amount: 5 });
  expect(done.status).toBe(200);
  expect(tq.requests.at(-1)?.details).toEqual([{ label: 'Amount', value: '5 EUR' }]);
});
```

- `install()` makes it the default client: the one routes without `client` and `runGuard(null, …)` use.
  `uninstall()` puts back the one it replaced. A route given `client` uses that one: pass the fake there instead.
- `tq.approve()`, `tq.reject()`, `tq.expire()`: the latest request, or one by its id (`tq.approve(requestId)`;
  `tq.approve(requestId, 'WEBAUTHN')` approves with a passkey).
- `new FakeTouchque({ autoApprove: true })` (or `tq.autoApprove = true`): every request is approved as it is
  made. The first request still answers 202; the next one runs the route.
- Every user has a phone linked. `tq.unlink(user)` shows them the first-time QR instead
  (`new FakeTouchque({ linked: false })`: nobody has one); `tq.link(user)` is the phone scanning it.
  `tq.secretTtlMs` is how long a QR works (5 minutes).
- `new FakeTouchque({ numberMatch: true })`: pushes ask for the number `47`.
- `tq.requests` (`id`, `user`, `type`, `details`, `referenceId`, `status`, `expiresAt`, …) and `tq.calls`
  (`method`, `path`, `body`): what your app asked Touchque, in order. Each request's `expiresAt` is 30 s after it
  was made, and its status answer and every poll carry it (set a later one to extend it). The fake never expires a
  request by time: call `tq.expire()`.
- Offline approval: the code is `tq.offlineCode` (`ABCD123`), the time-based code `tq.totpCode` (`123456`).
  `{ logger }` gets the SDK's own log lines, as on a real client. Calls outside the step-up (recovery,
  agents …) throw `TouchqueAPIError` 404.
- Load it the way your app loads `@touchque/node` (both `import`, or both `require`), so the fake and your
  guards come from the same build.

## Errors

All SDK errors extend `TouchqueError`: `TouchqueAPIError`, `TouchqueNetworkError`,
`TouchqueRejectedError`, `TouchqueTimeoutError`, `TouchqueWebhookSignatureError`,
`TouchqueConfigError`, `TouchquePasskeyRequiredError`.

A feature your organization cannot use here answers 403 as a `TouchqueFeatureError` (still a `TouchqueAPIError`) with `feature` (`device_risk`, `ai_agents`…) and `reason`: `TouchqueFeatureNotInPlanError`, `TouchqueFeatureReadOnlyError` or `TouchqueFeatureOffError` — not in its plan (an owner or admin adds it in the Touchque dashboard), being turned off (reads work for 14 days, changes are refused) or switched off on this Touchque deployment.

## Security

- Every API request is signed HMAC-SHA256 (method, path+query, timestamp, nonce, body hash).
- The `X-Touchque-Token` a frontend echoes back is itself signed and bound to
  one user + action + transaction digest — it can't be replayed for a
  different amount, recipient or user.
- An approval is consumed exactly once, server-side.
- Your API secret never leaves your server.

See [SECURITY.md](https://github.com/Touchque/touchque-nodejs/blob/main/SECURITY.md) to report a vulnerability.

## Requirements

- Node.js 18+
- A [Touchque Dashboard](https://dashboard.touchque.com) account

## Logging

The SDK writes nothing to the console on its own. To see its own problems (a misconfigured guard, a failed `onChallenge` or `errorBody`, a relay mounted without `getLoginUser`), pass a logger: `new Touchque({ logger: console })`, or pino or winston (anything with `warn` and `error`); `debug: true` uses `console`. Lines carry an error's class, code and message, never a request or a user. A guard with no API key has no client and so no logger: see [No API key](#no-api-key).

## License

MIT © [Touchque](https://touchque.com)
