# @touchque/node

The official Node.js server SDK for [TouchQue](https://touchque.com) — biometric push 2FA,
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

Get an API key and secret from your [TouchQue Dashboard](https://dashboard.touchque.com),
then set them as environment variables:

```bash
TQ_API_KEY=tq_auth_your_key
TQ_API_SECRET=your_api_secret
```

The client picks these up automatically — `new TouchQue()` with no arguments.

## Quick start (Express)

```typescript
import express from 'express';
import { requireTouchQue } from '@touchque/node';

const app = express();
app.use(express.json());

app.post('/transfer',
  requireTouchQue('SEND_MONEY', {
    details: (req) => ({ Amount: `${req.body.amount} EUR`, To: req.body.iban }),
  }),
  (req, res) => {
    // Only reached once the user approved on their phone.
    res.json({ ok: true, assurance: req.touchque.assurance });
  }
);

app.listen(3000);
```

That's the whole integration for one route. What actually happens:

1. The first request comes in with no pending approval → the middleware calls
   TouchQue, sends a push to the user's phone, and answers **`202 { touchque, token }`**
   instead of running your handler.
2. Your frontend shows `touchque` in its own UI — a matching number for the
   user to tap on their phone, or a QR code the first time they link the app —
   then sends the *same request* again with header `X-TouchQue-Token: <token>`
   (see [`@touchque/web`](https://www.npmjs.com/package/@touchque/web), which does this loop for you).
3. Once the user approves, that retried request reaches your handler exactly
   once, with `req.touchque` populated (`assurance`, `approvalProof`, …).

No hosted page, no redirect, no new domain — you keep your own UI end to end.

## The three primitives, if you don't use a framework adapter

```typescript
import { TouchQue } from '@touchque/node';

const tq = new TouchQue(); // from TQ_API_KEY / TQ_API_SECRET

const step = await tq.start('SEND_MONEY', {
  user: 'jane@acme.com',
  details: { Amount: '250 EUR', To: 'DE89...' },
});
// step.state: 'waiting' (show step.number) | 'enroll' (show step.enroll.qrCodeDataUrl)
//             | 'approved' | 'rejected' | 'expired' | 'passkey_required' | 'frozen' | 'blocked'

const latest = await tq.check(step.id);

// Once approved, consume it exactly once, right before doing the protected thing:
const approval = await tq.complete(step.id, {
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

- **Express**: `requireTouchQue(action, options?)` — shown above.
- **Next.js / Fetch API route handlers**: `withTouchQue(action, options?)`. It sends no end-user
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
  say where the end user's address comes from (`ip` or `trustedProxyHops`, as for `withTouchQue`); without one the
  per-IP limits are skipped and only the per-username ones apply. `basePath` (default `/touchque`) is where it is
  mounted; another path answers 404.

```typescript
// app/touchque/[...path]/route.ts
import { TouchQue, touchqueRelay, ipFromVercel } from '@touchque/node';

const relay = touchqueRelay(new TouchQue(), {
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

Both relays rate limit with `FixedWindowLimiter`, which is exported for your own routes (`withTouchQue`, a
hand-written relay). `hit(key, limit)` counts one request and returns the seconds to wait once `key` is over `limit`
in the window (0 until then); it is in memory, per process.

```typescript
import { FixedWindowLimiter, withTouchQue, ipFromVercel } from '@touchque/node';

const limiter = new FixedWindowLimiter();   // { windowMs: 60000, perIp: 20, perUser: 5 }
const transfer = withTouchQue('SEND_MONEY', handler, { user, ip: ipFromVercel });

export async function POST(req: Request) {
  const wait = limiter.hit(`ip|transfer|${ipFromVercel(req)}`, limiter.perIp);
  if (wait) return Response.json({ error: 'RATE_LIMITED', retryAfter: wait }, { status: 429, headers: { 'Retry-After': String(wait) } });
  return transfer(req);
}
```

## Passkeys (phishing-resistant)

Push approval and offline codes stop password reuse and push fatigue, but a
real-time phishing proxy can still relay them. A passkey can't be phished: the
browser signs your site's real origin and TouchQue refuses any other
(NIST SP 800-63B-4 §3.2.5).

1. Set your passkey domain in the Dashboard (Security Policy → Passkeys).
2. Let users register one via `tq.webauthn` (server) + `@touchque/web`'s
   `passkeys.register()` (browser).
3. Optionally require it for critical actions or every sign-in — TouchQue then
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
push the user already started (`requireTouchQue` / `touchqueRouter` do this for you):

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
    res.sendStatus(403); // not from TouchQue
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

The phone tells TouchQue, signed with its hardware key, whether a call was active (or just ended), the screen
was shared or the phone remote-controlled when the user tapped Approve. Depending on the server's mode:

- **Passkey instead.** A user with a passkey finishes in the browser: the request stays open and turns into
  `passkey_required` mid-flight. The step-up flow (`start` / `check`, the guard, `touchqueRouter`) and
  `@touchque/web` handle it; the blocking `login.waitForApproval` / `login.verify` / `tq.protect` throw
  `TouchQuePasskeyRequiredError` with `reason: 'step_up'`. No offline or recovery code can finish such a request.
- **Refused.** A critical action without a passkey is rejected (`reason: 'vishing_suspected'`).
- **Provisional.** Anything else is approved with `provisional: true` (on the `Approval`, `GET /login/status`,
  consume and the SUCCESS webhook). Let the user in, but treat the session as limited: TouchQue refuses the
  user's critical actions (`blocked` / `provisional`) until the phone re-confirms after the call
  (`APPROVAL_RECONFIRMED`). `APPROVAL_REVOKED` (`reason: 'COACHED' | 'UNDO'`) means end the session; an approval
  revoked before you consumed it can no longer be consumed (409 `revoked`).

**Mirror Alarm.** Every waiting step carries `canary.url` once. `@touchque/web` loads it on the page showing the
sign-in and sends a beacon to it, so a real-time phishing proxy in front of your site shows up as itself: the
approval is refused (`reason: 'phishing_origin'`) and the phone warns the user. Allow the canary host in your
Content-Security-Policy (`img-src` and `connect-src`).

## TouchQue Actions (your code in the approval pipeline)

Alerts, step-ups and refusals by country, local time, role or amount, passkeys
for admins — from a template or a few lines of JavaScript, replayed against your
real recent sign-ins before they go live. Full guide: [Actions](https://support.touchque.com/actions).

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
`requireTouchQue('SEND_MONEY', { context: (req) => ({ roles: req.user.roles, amount: req.body.amount }) })`.
Loosening calls (`skipNumberMatch`, `overrideBlock`, `allowSilent`) need a capability an
admin approves on their phone. Action types moved to `tq.actionTypes` in 4.0.

## AI agents (an identity per agent, never your API key)

Register each agent with its **public** key; the private key stays where the agent runs. The agent then signs in
with its own key and gets a 10-minute token bound to that key (DPoP), so a leaked token is useless on its own.

```ts
import { TouchQue, TouchQueAgent, generateAgentKey } from '@touchque/node';

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
const me = await new TouchQueAgent().me();   // reads TQ_AGENT_ID / TQ_AGENT_KEY
```

Stop an agent at once with `tq.agents.suspend(id)` or every agent with `tq.agents.setKillSwitch(true)`; its
tokens stop working immediately.

### The agent asks, the person approves on the phone, your server executes once

```ts
// In the agent: structured details, never free text; TouchQue draws the phone's rows.
const ask = await agent.requestApproval({
  user: 'jane@example.com', type: 'PAY_INVOICE', reason: 'October rent',
  authorizationDetails: [{ type: 'payment_initiation', instructedAmount: { currency: 'TRY', amount: '500.00' },
    creditorName: 'Jane Doe', creditorAccount: { iban: 'TR33 0006 1005 1978 6457 8413 26' } }],
});
reply(`Type ${ask.challengeCode} in the TouchQue app to approve.`);
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
import { withTouchQueApproval, currentApproval, approveInterruptionsWithTouchQue, touchqueCanUseTool, guardMcpClient } from '@touchque/node';

const policy = {
  agent, user: 'jane@example.com', type: 'PAY_INVOICE',
  details: ({ iban, amount }) => [{ type: 'payment_initiation', instructedAmount: { currency: 'TRY', amount }, creditorAccount: { iban } }],
  onChallenge: (s) => reply(`Type ${s.challengeCode} in the TouchQue app to approve.`),
};
const payInvoice = tool(withTouchQueApproval(async ({ iban, amount }) => bank.pay(iban, amount, currentApproval().approvalToken), policy), { name: 'pay_invoice', schema });

// OpenAI Agents SDK (tools with needsApproval): ask the phone for each interruption, then resume.
const state = await approveInterruptionsWithTouchQue(result, { pay_invoice: policy });
// Claude Agent SDK: query({ prompt, options: { canUseTool: touchqueCanUseTool({ pay_invoice: policy }) } })
// Any MCP client: the token reaches the server in _meta['touchque/approvalToken'].
const guarded = guardMcpClient(mcpClient, { pay_invoice: policy });
```
 Agents also stop when their review date passes (`update(id, { reviewInDays })`
renews it) and when their owner leaves the organization.

### Cross App Access (ID-JAG) and A2A agent cards

An organization's identity provider (TouchQue SSO) can let one of its apps reach another service for a member with no consent screen (Cross App Access, ID-JAG, an open IETF draft): the app trades the member's ID token for an ID-JAG, then the ID-JAG for an access token at the other service. If you run an authorization server, the verifier checks an ID-JAG (issuer, single audience, your client, expiry, `typ`) and uses it once. Before your agent trusts another agent's A2A card, check its signatures (A2A 1.0 §8.4: JWS over the RFC 8785 canonical card); keys named by `jku` are only fetched from the card's own host or hosts you trust.

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
with no risk signal since, does not need another push. TouchQue's risk engine decides; your server only skips the
push when it says so.

1. In the browser, `@touchque/web` 1.4.0 with `createTouchQueWeb({ browserKey: true })` keeps a non-extractable
   key for your site and sends a fresh, signed proof of it in the `X-TouchQue-Browser` header.
2. On the server, turn on `silentSignIn`:

```typescript
app.post('/login/2fa',
  requireTouchQue('LOGIN', { user: (req) => req.session.passwordOkUser, silentSignIn: true }),
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

`withTouchQue` takes the same option. With it on, a new attempt that carries the header first calls
`tq.risk.check`. Only an answer of exactly `prompt: false` approves it at once, with nothing sent to the phone:
the approval has `assurance: { method: 'silent', phishingResistant: false }`, `confirmedVia: 'SILENT'`,
`requestId: 'silent'` and `reasons` (`known_browser`, `recent_approval`, `same_phone`, `familiar_network`,
`no_risk_signal`); `touchqueRouter` calls `onAuthenticated` with `via: 'silent'`. Anything else, and any error in the
check, starts the usual push with the proof attached, so its approval makes the browser known. Polling with the
token never checks again.

TouchQue only lets a sign-in through silently when all of this holds: the browser proved its key and was approved
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
`prompt` is `false` only when TouchQue answered the boolean `false`.

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
showQr(r.bindUri);                     // the TouchQue app on the new phone scans it
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
decision by it in the TouchQue dashboard (Logs → Look up a case): what went in, each check's verdict (the access rule
that matched, the risk signals that were acted on and the ones only measured), and the single change that would have
let it through. No screenshots, no log digging. The code opens nothing on its own: only your workspace sees its
decisions.

```ts
const step = await tq.start('WITHDRAW', { user, ip: req.ip });
// step.caseCode → 'K7P-2QX'; step.reasons → [{ code: 'critical_action', text: 'The action is marked critical' }]
try {
  await tq.login.request({ externalUsername: user, type: 'LOGIN' });
} catch (err) {
  if (err instanceof TouchQueAPIError && err.caseCode) show(`Tell your support team: ${err.caseCode}`);
}
```

`caseCode` is on `LoginRequestResponse`, `RiskCheckResult`, `TouchQueAPIError` and every step (the guard keeps it
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
approve (`verify()` throws `TouchQuePasskeyRequiredError` first). An error it throws, or a promise it returns that
rejects, is logged and ignored: `verify()` keeps waiting. `tq.protect()` takes the same `onChallenge`. In a web
request, where the page hears nothing until you answer, use the router or `tq.start()`: their first answer already
carries the number.

## Verifying the device proof (no need to trust TouchQue)

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
takeover)? Report it — it is the strongest signal TouchQue's risk engine learns
from, and it stays in your audit log:

```typescript
await tq.login.reportFraud(requestId, { reason: 'chargeback', note: 'Disputed by card holder' });
// reason: 'chargeback' | 'account_takeover' | 'social_engineering' | 'other'
```

## Pairing a browser by QR code

Your page shows a QR code, the person scans it with the TouchQue app, and the phone that scanned is the one asked to approve, with number matching. Your page sends the thumbprint of its browser key (`@touchque/web` `browserKey.thumbprint()`); the nonce in the QR never leaves your server (TouchQue keeps its hash).

```ts
const p = await tq.qrPairings.create({ keyThumbprint, clientIp: req.ip, userAgent: req.get('user-agent') });
// show p.uri (touchque://pair-browser?…) as a QR code; poll:
const now = await tq.qrPairings.get(p.pairingId);   // waiting → scanned → confirmed
if (now.state === 'confirmed') await tq.login.request({ externalUsername: now.externalUsername!, type: 'LOGIN', qrPairing: p.pairingId });
// or: await tq.qrPairings.refuse(p.pairingId, { reason: 'device_not_approved', message: 'Ask IT to approve this computer.' });
```

`get` says `scanned` / `confirmed` once a phone holding one of your users' accounts read it (with `proximity`: same network, same country), `reported` when the person said someone told them to scan it (their 2FA freezes). `refuse` tells the phone why your own checks said no.

## A code typed back on the phone

When a sign-in needs a code another service sent the person (a text message, WhatsApp, e-mail), ask them to type it on the phone instead. The phone encrypts it to a one-time key you made for this request: TouchQue only ever holds the ciphertext. Such a request lives 5 minutes.

```ts
const key = newCodeReplyKey();   // keep key.privateKey for this request
const sent = await tq.login.request({ externalUsername: user, type: 'LOGIN', reply: { kind: 'code', key: key.publicKey, channel: 'sms', target: '+**********26' } });
const status = await tq.login.status(sent.requestId);   // once CONFIRMED
const code = status.reply ? openCodeReply(key.privateKey, sent.requestId, status.reply.ct) : null;
```

## Safe Guard (Safe transactions approved on the phone)

TouchQueSafeGuard is a transaction guard for a Safe: a transaction runs only with approvals signed by the P-256 keys on its approvers' phones. You send the raw transaction; the phone decodes it itself, shows its own rows and signs what it computed with a key only its biometrics unlock. Delegatecalls, changes to the Safe and proxy upgrades are governance: scheduled, time-locked and vetoable. A phone without that key yet gets `409 crypto_key_missing`.

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

`verifySafeApproval` makes the guard's check off chain, so a co-signer or your own server never has to trust TouchQue: it computes the Safe transaction hash (EIP-712) and the governance hash from the raw fields, rebuilds the 149-byte message the phone signed and checks the P-256 signature for one purpose: `approve` unless you pass `purpose: 'schedule'`, so an approval to schedule a governance change (which leaves out the Safe nonce and gas) never passes as one to execute. It refuses a high `s`, an approval that expired or is valid for more than a day, another approver index, and, when you pass `rows` or `displayDigest` from your own decoding, rows the phone did not show. `reason` is `approval_malformed`, `public_key_invalid`, `approver_index_mismatch`, `approval_expired`, `rows_differ`, `high_s` or `signature_invalid`. `safeTxHash`, `safeGovernanceHash`, `safeApprovalMessage` and `safeDisplayDigest` are exported too.

## Errors

All SDK errors extend `TouchQueError`: `TouchQueAPIError`, `TouchQueNetworkError`,
`TouchQueRejectedError`, `TouchQueTimeoutError`, `TouchQueWebhookSignatureError`,
`TouchQueConfigError`, `TouchQuePasskeyRequiredError`.

A feature your organization cannot use here answers 403 as a `TouchQueFeatureError` (still a `TouchQueAPIError`) with `feature` (`device_risk`, `ai_agents`…) and `reason`: `TouchQueFeatureNotInPlanError`, `TouchQueFeatureReadOnlyError` or `TouchQueFeatureOffError` — not in its plan (an owner or admin adds it in the TouchQue dashboard), being turned off (reads work for 14 days, changes are refused) or switched off on this TouchQue deployment.

## Security

- Every API request is signed HMAC-SHA256 (method, path+query, timestamp, nonce, body hash).
- The `X-TouchQue-Token` a frontend echoes back is itself signed and bound to
  one user + action + transaction digest — it can't be replayed for a
  different amount, recipient or user.
- An approval is consumed exactly once, server-side.
- Your API secret never leaves your server.

See [SECURITY.md](./SECURITY.md) to report a vulnerability.

## Requirements

- Node.js 18+
- A [TouchQue Dashboard](https://dashboard.touchque.com) account

## Logging

The SDK writes nothing to the console on its own. To see its own problems (a misconfigured guard, a failed `onChallenge`, a relay mounted without `getLoginUser`), pass a logger: `new TouchQue({ logger: console })`, or pino or winston (anything with `warn` and `error`); `debug: true` uses `console`. Lines carry an error's class, code and message, never a request or a user.

## License

MIT © [TouchQue](https://touchque.com)

## TouchQue Login (hosted sign-in)

Sign-up and sign-in pages for your own customers, on your brand, with OpenID Connect. See [Touchque Login](https://support.touchque.com/touchque-login) for this SDK's client and a quickstart.
