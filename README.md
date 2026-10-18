# @touchque/node

The official Node.js server SDK for [TouchQue](https://touchque.com) — biometric push 2FA,
passkeys, and offline approval codes, added to any backend with one line per route.

[![npm version](https://img.shields.io/npm/v/@touchque/node.svg)](https://www.npmjs.com/package/@touchque/node)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

📘 Full docs: **[authenticator.touchque.com/docs](https://authenticator.touchque.com/docs)**

## Install

```bash
npm install @touchque/node
```

## Setup

Get an API key and secret from your [TouchQue Dashboard](https://authenticator.touchque.com),
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
  hand-write them.

```typescript
import { touchqueRouter } from '@touchque/node';

app.use(touchqueRouter(tq, {
  getUserId: (req) => req.session.user?.email,
  // The user who already passed your password step. Binds POST /login and the
  // offline routes to them; the offline routes stay off (403) without it.
  getLoginUser: (req) => req.session.passwordVerifiedUser,
}));
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

## Errors

All SDK errors extend `TouchQueError`: `TouchQueAPIError`, `TouchQueNetworkError`,
`TouchQueRejectedError`, `TouchQueTimeoutError`, `TouchQueWebhookSignatureError`,
`TouchQueConfigError`, `TouchQuePasskeyRequiredError`.

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
- A [TouchQue Dashboard](https://authenticator.touchque.com) account

## License

MIT © [TouchQue](https://touchque.com)
