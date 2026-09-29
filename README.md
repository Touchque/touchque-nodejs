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
- **Next.js / Fetch API route handlers**: `withTouchQue(action, options?)`.
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
  user: 'jane@acme.com',
  type: 'WITHDRAW',
  details: { Amount: '1,250.00 USD', Recipient: 'Jane Doe' },
});
// show ch.qrDataUrl — the phone scans it offline and shows a 7-character code

const { approved } = await tq.offline.verify({ challengeId: ch.challengeId, code });
```

## Webhooks

```typescript
app.post('/webhooks/touchque', express.raw({ type: 'application/json' }), (req, res) => {
  try {
    const event = tq.webhook.verify({
      rawBody: req.body.toString(),
      signature: req.headers['x-touchque-signature'] as string,
    });
    // handle event.event: 'login.confirmed' | 'login.rejected' | …
    res.sendStatus(200);
  } catch {
    res.sendStatus(403); // not from TouchQue
  }
});
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
