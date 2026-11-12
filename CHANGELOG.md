# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [5.2.0] — 2026-11-13

### Added
- **`runGuard(null, input)`: the guard inside your handler with the default client.** `null` or `undefined` means the client built from `TQ_API_KEY` / `TQ_API_SECRET` on a request and kept once built, the one the adapters use (`getDefaultClient()`); a failed build is tried again on the next request. Until it can be built, `runGuard` answers 401 `unauthenticated` without a `user`, else 500 `misconfigured`, and never throws; nothing is logged, as there is no client to log through. So a handler no longer needs a client built at startup, which threw without the keys. To fail fast instead, call `getDefaultClient()` at startup: it throws a `TouchqueConfigError` that names the problem.
- **`setDefaultClient(client?)`: replace or forget the default client.** `setDefaultClient(new Touchque({ logger: console }))` gives the adapters and `runGuard(null, …)` a client with your logger; `null` or `undefined` forgets it, so the next `getDefaultClient()` builds one from the environment again. Returns the client it replaced. `FakeTouchque.install()` / `uninstall()` use it.
- **`guardResponse(result, { errorBody?, logger? })`: the HTTP answer for a guard result that is not approved.** It returns `{ status, headers, body }` exactly as `requireTouchque` and `withTouchque` send it, and they use it too, so the two paths cannot drift: `Cache-Control: no-store`, `Retry-After` on 423 and 429, `X-Touchque-State` / `X-Touchque-Reason` on 400 or more, and `errorBody` with the 5.1 rules (400 or more only, judged by its JSON, a copy of the step, a failing callback sends the default body). `logger` gets `[Touchque] errorBody failed: …`; without it nothing is logged. `body` is a JSON value: send it with your framework's JSON. An approved result throws a `TypeError`: run the protected action instead. `GuardResponse` and `GuardResponseOptions` types. `touchqueRouter` and `touchqueRelay` send their guard answers through it as well (what they send is unchanged).
- **`@touchque/node/testing`: `FakeTouchque`, a fake client for your app's tests**, the counterpart of Python's `touchque.testing.FakeTouchque`. It is a real `Touchque` whose API calls are answered in memory: no network, no API keys, no express or any other dependency. The real guard runs, so routes answer what they answer in production. `link(user)` / `unlink(user)` / `isLinked(user)` (every user has a phone unless `{ linked: false }`); `approve(requestId?, via?)`, `reject(requestId?)`, `expire(requestId?)` for the latest request or one by its id; `autoApprove`, `numberMatch`, `secretTtlMs`, `offlineCode`, `totpCode`; `requests` (each with its `expiresAt`, 30 s after it was made, which its status answer gives) and `calls` (method, path, body) in order; `install()` / `uninstall()` as the default client; `{ logger }`. Calls outside the step-up throw `TouchqueAPIError` 404. A new `./testing` entry in `exports` (ES module and CommonJS, with types; `typesVersions` for TypeScript's `node` resolution). It loads the main entry instead of bundling a copy of it, so the fake, the guard and the errors are the same classes.
- README: "Testing your routes".

### Changed
- **Waiting polls carry the request's current `expiresAt`.** Only the first answer had it, so a page that read it from the latest answer never stopped by time. Now every later answer for that request in the `waiting` and `passkey_required` states carries it, also after a switch to the offline QR. It is the live expiry from Touchque's status answer, which grows when a push tapped during a call moves to a passkey (180 s more), else the one the token keeps (claim `rx`); the token re-issued keeps the value used. A token without `rx` whose status answer has no `expiresAt` answers as in 5.1. `tq.check()` returns `expiresAt` when Touchque's answer has one, and `LoginStatusResponse` has `expiresAt`.
- **`enroll: false` says why.** A user with no phone on a guard that may not show a QR is answered 202 `{ touchque: { state: 'enroll', reason: 'enrollment_off' }, token }` (`tq.start()` with `enroll: false` returns `{ state: 'enroll', reason: 'enrollment_off' }`); in 5.1 the step was a bare `{ state: 'enroll' }` that pages polled forever. `touchqueRouter` and `touchqueRelay` answer it on `POST /login` without `getLoginUser` and when adding a passkey. `@touchque/web` 2.2.0 stops polling on it and shows the not-linked error.
- README, "Guard inside your handler": the example uses `runGuard(null, …)` per request and `guardResponse`, with no client built at module scope; `getDefaultClient()` at startup is the fail-fast check and `setDefaultClient(new Touchque({ logger }))` gives the null path a logger (also under "No API key"); a new first-time QR comes about 15 s before the old one expires, with new recovery codes, and the old QR and codes stop working; waiting polls carry the request's current `expiresAt`; `enroll: false` answers `enrollment_off`; a 202 state other than `waiting` or a plain `enroll` needs `@touchque/web` or your own UI following the contract.
- README, the three primitives: `tq.check(step.requestId!)` and `tq.complete(step.requestId!, …)` (it said `step.id`), and the `enroll` state with reason `enrollment_off`. "Testing your routes" imports `test`, `expect`, `beforeEach` and `afterEach` from `vitest` (globals in Jest) and is valid TypeScript.

## [5.1.0] — 2026-11-12

### Fixed
- **The first-time QR stays the same while the page polls.** Each poll with an `enroll` token started again and replaced the QR and the recovery codes, so the QR being scanned stopped working. Now:
  - An `enroll` step with a QR has `enroll.expiresAt`: the API's `expiresAt` when it is an ISO 8601 time, else now + `ttlMs`. Its token carries that expiry.
  - While the QR is up, a poll only reads whether the phone is linked (`GET /users/{externalUsername}`) and answers 202 `{ touchque: { state: 'enroll', expiresAt }, token }`, without `enroll`: keep showing the QR you have.
  - Once the phone is linked the approval starts as before. When the QR is within 15 seconds of its expiry, or gone, the poll brings a new QR with `enroll.qrCodeDataUrl`.
  - `touchqueRouter` and `touchqueRelay` count these polls like other status polls, so their per-user limit no longer refuses them after a few seconds. What such a poll starts is still charged to the user like a new attempt: the push once the phone is linked, and a new QR (also when the token is an old one, replayed). Over the limit they answer their usual 429. `runGuard` has a `beforeStart` input for this; relays pass it, a handler that guards one route does not need it.
  - Pages on `@touchque/web` need 2.1.0, which keeps the QR on screen for such a step.
- **A missing API key no longer throws.** `requireTouchque` and `withTouchque` build the default client on a request and keep it once built. Without `TQ_API_KEY` / `TQ_API_SECRET` a guarded route answers 500 `misconfigured` in JSON (`Cache-Control: no-store`), or 401 `unauthenticated` when no one is signed in, and the handler never runs. `requireTouchque` used to pass the error to `next()`, which gave an HTML 500, and `withTouchque` threw.

### Added
- **`errorBody` on `requireTouchque` and `withTouchque`: your app's own error shape.** Called for every answer with status 400 or more (401, 403, 408, 423, 429, 500, 503), never for a 202 step or an approval, with a `GuardRefusal` (`status`, `code`, `message`, and `touchque`, a copy of the step). What it returns is judged by its JSON: what encodes to an object (a plain object, a class instance, `toJSON()`, a `Map` as its entries) is sent with `touchque` set to the step (the SDK's key wins, no `token`); anything else is sent as it is, and `undefined` keeps the default body. Status and headers do not change. A callback that throws, or a result JSON cannot encode, sends the default body and logs `[Touchque] errorBody failed: …` through the client's logger.
- **Refusal headers.** Every guard answer with status 400 or more, from `requireTouchque`, `withTouchque`, `touchqueRouter` and `touchqueRelay`, carries `X-Touchque-State` and, when the step has a reason, `X-Touchque-Reason`. `@touchque/web` 2.1.0 reads them when the body has no `touchque` (an `errorBody` that returns a non-object). On another origin, expose them with `Access-Control-Expose-Headers`.
- `GuardRefusal` type; `beforeStart` in `GuardInput`.
- README: "Guard inside your handler" (`runGuard` after your own checks, what to answer, the poll contract), the `errorBody` option, what a missing key answers, and a Touchque Login section (`HostedLogin`, `authorizationUrl`, `handleCallback`, `TokenSet.claims`, `HostedLoginError`, the `fetch` option, the Express helpers).

### Changed
- README: the passkey domain is set in the dashboard under Developers → App user policy. Touchque Login is added under Organization → Modules and set up under Touchque Login → Setup.

## [5.0.0] — 2026-11-11

### Breaking
- **Every name is spelled Touchque instead of TouchQue.** Code that uses the old names must be updated; nothing else changes (the same API, requests and answers, the package name `@touchque/node` with its `./next/middleware` entry, and the lowercase names such as `touchqueRouter`, `touchqueRelay`, `touchqueMiddleware` and `touchqueCanUseTool`).
  - The client: `TouchQue` → `Touchque` (`new Touchque()`).
  - The errors, and their `name`: `TouchQueError` → `TouchqueError`, `TouchQueAPIError` → `TouchqueAPIError`, `TouchQueNetworkError` → `TouchqueNetworkError`, `TouchQueTimeoutError` → `TouchqueTimeoutError`, `TouchQueRejectedError` → `TouchqueRejectedError`, `TouchQueConfigError` → `TouchqueConfigError`, `TouchQueWebhookSignatureError` → `TouchqueWebhookSignatureError`, `TouchQueWebhookReplayError` → `TouchqueWebhookReplayError`, `TouchQuePasskeyRequiredError` → `TouchquePasskeyRequiredError`, `TouchQueApprovalError` → `TouchqueApprovalError`, `TouchQueApprovalMismatchError` → `TouchqueApprovalMismatchError`, `TouchQueFeatureError` → `TouchqueFeatureError`, `TouchQueFeatureNotInPlanError` → `TouchqueFeatureNotInPlanError`, `TouchQueFeatureReadOnlyError` → `TouchqueFeatureReadOnlyError`, `TouchQueFeatureOffError` → `TouchqueFeatureOffError`.
  - Guards and helpers: `requireTouchQue` → `requireTouchque`, `withTouchQue` → `withTouchque`, `createTouchQueLogin` → `createTouchqueLogin`, `withTouchQueApproval` → `withTouchqueApproval`, `approveInterruptionsWithTouchQue` → `approveInterruptionsWithTouchque`, `myAccount.unlinkTouchQueApp()` → `myAccount.unlinkTouchqueApp()`.
  - Agents: `TouchQueAgent` → `TouchqueAgent`, `TouchQueOrgAgent` → `TouchqueOrgAgent`.
  - Types: `TouchQueConfig` → `TouchqueConfig`, `TouchQueLogger` → `TouchqueLogger`, `TouchQueErrorData` → `TouchqueErrorData`, `TouchQueMiddlewareOptions` → `TouchqueMiddlewareOptions` (Express and `@touchque/node/next/middleware`), `WithTouchQueOptions` → `WithTouchqueOptions`, `TouchQueNextOptions` → `TouchqueNextOptions`, `TouchQueRouterOptions` → `TouchqueRouterOptions`, `TouchQueRelayOptions` → `TouchqueRelayOptions`, `TouchQueAgentConfig` → `TouchqueAgentConfig`, `TouchQueOrgAgentConfig` → `TouchqueOrgAgentConfig`.
  - Headers: `X-TouchQue-Token`, `X-TouchQue-Offline`, `X-TouchQue-Code`, `X-TouchQue-Code-Type` and `X-TouchQue-Browser` are written `X-Touchque-Token`, `X-Touchque-Offline`, `X-Touchque-Code`, `X-Touchque-Code-Type` and `X-Touchque-Browser`. HTTP header names are case-insensitive, so servers are unaffected (the guards read them lowercase, as `GUARD_HEADERS` names them).
  - Error messages and log lines say Touchque (`Touchque API Error: HTTP 500`, `[Touchque] …`); match on the error class or its `code`, not on the text.

### Changed
- The README links work where the package is read (npm, PyPI, GitHub): the Actions and Touchque Login guides point to support.touchque.com, SECURITY.md and CONTRIBUTING.md to this package's public repository.
- The README has an "Action types" section: define a type once (dashboard → Developers → Action types, or from code); the guard answers 500 `misconfigured` for an undefined name and 403 `action_disabled` for one turned off.
- The README quick start names the approving user (`user:`) and builds the phone's details from your own records instead of the request body.

## [4.2.0] — 2026-11-10

### Security
- **The offline approval-token check refuses another workspace's token.** `GET /agents/jwks.json` is one key set for every Touchque workspace, and the check used to compare `aud` only when you passed an audience, so a token Touchque signed for someone else's workspace (their own phone, any person's name, any details) could pass your executor. Now:
  - `agents.verifyApprovalToken(token, { audience?, expect })` uses this workspace's own audience by default: `agents.approvalAudience()` asks `GET /agents/approval-audience` once (`touchque:workspace:<id>`) and keeps it.
  - `verifyApprovalTokenWith(token, jwks, { audience, expect, now })` requires the audience. A missing or empty one throws TouchqueApprovalMismatchError (`audience is required`).
  - A token without `aud` is refused (`the approval token names no workspace`), as is one for another workspace (`the approval token is for another workspace`).
  - Breaking for callers of the low-level function who passed no audience: pass agents.approvalAudience()'s value.
  - `redeemApproval` was already safe: Touchque compares `aud` with your workspace there.

### Added
- **`deviceRisk.searchEvents(options)`: search your workspace's Device risk identifications**, newest first, one page at a time (`GET /device-risk/events`): `from`/`to` (7 days by default, at most 90, within your retention), `signal`, `stepUp`, `kind`, `origin`, `ip` (an address or a CIDR range; never returned), `account`, `visitorId`, `requestId`, `limit` (1 to 100) and the opaque `cursor` from the previous page's `nextCursor`. `DeviceRiskSearchOptions`, `DeviceRiskIdentification`, `DeviceRiskSearchResult` types.
- `deviceRisk.check()` returns `engine` (`string | null`): the engine's state for this check; `'unavailable'` when the risk engine could not be reached and the verdict is a safe default (`stepUp: true`), so an outage can be told apart from risk.
- **`webauthn.primaryAvailability()`: is passkey sign-in on for your workspace?** `GET /webauthn/authenticate/primary/availability` answers `{ enabled, userVerification }`. Ask before your sign-in page shows its passkey button and passkey autofill; when it is off, `primaryOptions` answers 403 `passwordless_login_disabled`. `WebAuthnPrimaryAvailability` type.
- **`login.consume(requestId)`**: use an approved request exactly once, as the Python, PHP, Go, .NET, Ruby and Java SDKs already allow (`POST /login/{id}/consume`; a second call throws `TouchqueAPIError` with `code: 'already_used'`, 409). `ConsumeResponse` type. `tq.complete()` still does the same and also checks the user, action and transaction.
- **`touchqueRelay(tq, options)`: the relay routes for Next.js (App Router) and other Fetch-API runtimes** (Hono, Remix, SvelteKit, Bun, Deno, Workers). The same routes, answers and checks as `touchqueRouter` (enrollment, POST /login's two-phase contract, offline codes, passkeys), as one `(req: Request) => Promise<Response>` handler with no express: `getLoginUser` binds POST /login and the offline routes to your first factor (the offline routes stay off without it), the same rate limiter per IP and per username, `onAuthenticated(req, info, headers)` adds your `Set-Cookie` to the success response. `basePath` (default `/touchque`); the client address comes from `ip` or `trustedProxyHops` as for `withTouchque` (without one, only the per-username limits apply). JSON bodies up to 100 KiB.
- **`FixedWindowLimiter` is exported** (with `RateLimitOptions`): the relays' in-memory rate limiter, for `withTouchque` and hand-written relays. `new FixedWindowLimiter({ windowMs, perIp, perUser })`, `hit(key, limit)` returns the seconds to wait once over the limit. `touchqueRouter` is unchanged.
- **Webhook events `MOBILE_PUSH`, `RECOVERY_*` and `ASSIST_*`** (`WebhookEvents`), the names the backend sends: `MOBILE_PUSH`; `RECOVERY_STARTED`, `RECOVERY_DEVICE_BOUND`, `RECOVERY_COOLING`, `RECOVERY_COMPLETED`, `RECOVERY_VETOED`, `RECOVERY_EXPIRED`, `RECOVERY_FAILED`; `ASSIST_OPENED`, `ASSIST_ENDED`, `ASSIST_CHECK_PASSED`, `ASSIST_CHECK_FAILED`, `ASSIST_UNFROZEN`, `ASSIST_CLAIM_CONFIRMED`, `ASSIST_CLAIM_UNVERIFIED`.
- README: "Shared Signals (security events from Touchque SSO)", verifying a pushed SET and polling.
- **Shared Signals: receive the security events an identity provider sends after sign-in.** Touchque SSO sends Security Event Tokens (OpenID Shared Signals Framework 1.0) for an organization's members to the receivers its admin adds (Organization > Continuous access): CAEP `session-revoked`, `credential-change`, `device-compliance-change`, RISC `account-disabled`, `credential-compromise`; `txn` carries the case code of Touchque's decision. `new SecurityEventVerifier({ issuer, audience, jwksUri?, jwks?, clockSkew? }).verify(token)` returns `{ jti, issuer, audience, issuedAt, txn, subject, type, name, claims }` or throws `SecurityEventError` with the RFC 8935 code to answer (`invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience`); `pollSecurityEvents({ url, token, ack, setErrs, maxEvents })` for poll delivery (RFC 8936); `SECURITY_EVENT_TYPES`. The keys come from the issuer's `/.well-known/ssf-configuration`; a SET does not expire, so keep the jtis you handled. Tested against the shared vectors (`fixtures/security-event-vectors.json`).
- **Safe Guard: Safe transactions approved on the approver's phone, for TouchqueSafeGuard.** `tq.safeGuard.request({ externalUsername, type, safeTx })` sends the raw transaction (the phone decodes it itself and signs with a key only its biometrics unlock), `status(requestId)` and `waitForApproval({ requestId })` hand back the 105-byte approval. `verifySafeApproval(target, approval, approverKey, { purpose, approverIndex, rows | displayDigest, now })` checks it the way the guard does, without trusting Touchque: the Safe transaction hash (EIP-712) and the governance hash computed here, the 149-byte message, low `s`, the one-day expiry window, the P-256 signature. `withSafeApprovals(ownerSignatures, approvals)` for `execTransaction`, `safeScheduleCall(safe, governanceHash, approvals)` for a governance change; `safeTxHash`, `safeGovernanceHash`, `safeApprovalMessage`, `safeDisplayDigest`. Tested against the shared vectors (`fixtures/safe-guard-vectors.json`).

### Fixed
- The main entry no longer loads express, an optional peer dependency: a Next.js app, a Fastify app or a plain script imports `@touchque/node` without it (it failed with "Cannot find module 'express'"). `touchqueRouter()` and `hostedLoginRoutes()` require express when called and throw a `TouchqueConfigError` that names it when it is missing.
- `deviceRisk.check({ deviceRisk })` sends the relayed report (`deviceRisk.collect()`) whole. It was cut to 64 characters, so Touchque could not decode it and every relayed-report check asked for a step-up. Only the requestId field is capped.
- `WebhookPayload.status` is typed `'SUCCESS' | 'REJECTED'` (or an event webhook's own string), what login-result webhooks send: `payload.status === 'SUCCESS'` no longer fails to compile.
- `identity.customDomains.get(id)` finds the domain in the list (the API has no read by id, so it always answered 404) and throws a 404 `not_found` `TouchqueAPIError` when there is none. New `identity.customDomains.verify(id)` checks the domain's DNS TXT record.

### Security
- **Hosted login: an empty `iss` is refused too (RFC 9207).** `handleCallback` already refused a callback whose `iss` names another issuer; one with an empty `iss=` now throws `issuer_mismatch` as well, before the code is exchanged. A callback without `iss` (a server that does not send it yet) is still accepted.
- `verifySafeApproval` checks only the purpose you name, `approve` by default. Without `purpose` it also accepted an approval to schedule a governance change (signed over the governance hash, which leaves out the Safe nonce and gas) as valid, so a co-signer could take it as permission to execute. Pass `purpose: 'schedule'` for a governance change.
- `webhook.verify()` keeps a top-level `"__proto__"` member in the string it checks. It was dropped, so a genuine delivery with one added still verified and carried unsigned data; such a body now fails, as in the other SDKs.
- `tq.webhook` no longer holds the API secret as an enumerable field: `console.log(tq)`, `util.inspect(tq)` and `JSON.stringify` of the client do not show it.
- `HostedLogin` and `MyAccount` (and so `createTouchqueLogin`) refuse a plaintext `http://` domain except on localhost, 127.0.0.1, ::1 and *.localhost, the rule the API `baseUrl` follows (`HostedLoginError` / `MyAccountError` code `config`). Authorization codes, PKCE verifiers, the client secret and tokens no longer travel in the clear.

## [4.1.0] — not published (these changes ship in 4.2.0)

### Added
- **Device risk events like a device-intelligence event, without raw traits:** `deviceRisk.check` and `getEvent` answers carry `network`, `velocity` and `bot` (typed `DeviceRiskNetwork`, `DeviceRiskVelocity`, `DeviceRiskBot`): the address as the risk engine saw it (country, region, city, never coordinates; the operator; `type` isp, hosting or tor; `timezoneMismatch` when the browser's clock does not fit the address), the visitor's counts (accounts, sign-ups, countries, stored-id resets, identifications in the last hour and day) and one answer to "a bot?" (`detected`, `suspected` or `not_detected`, with reasons). The field the script tag fills may now carry its pointer summary after the requestId: pass it as it came.

### Changed
- **Silent by default.** The SDK no longer writes to the console on its own: a misconfigured guard, a failed `onChallenge`, a relay error or a relay mounted without `getLoginUser` go to `new Touchque({ logger })` (anything with `warn` and `error`: `console`, pino, winston) or, with `debug: true`, to `console`; otherwise nowhere. Log lines carry an error's class, code and message, never the error object, a request or a user.
- `TouchqueApprovalMismatchError` no longer names the other person in its message; `console.log(tq)` / `JSON.stringify` no longer show the API key or secret.

### Added
- **A code typed back on the phone:** `login.request({ reply: { kind: 'code', key, channel, target } })` asks the person to type on the phone a sign-in code another service sent them; the phone encrypts it to your one-time key (`newCodeReplyKey()`), `login.status().reply.ct` hands back only the ciphertext and `openCodeReply(privateKey, requestId, ct)` opens it (ECDH P-256, HKDF-SHA256, AES-256-GCM, the same format as Touchque SSO's shared-account codes). The shared fake API seals a code on demand (`/__test/approve` `replyCode`).
- **Feature errors:** a feature your organization cannot use here (403 `feature_not_in_plan`, `feature_read_only`, `feature_off`) throws `TouchqueFeatureNotInPlanError`, `TouchqueFeatureReadOnlyError` or `TouchqueFeatureOffError`, all `TouchqueFeatureError` (with `feature` and `reason`) and still `TouchqueAPIError`.
- **Webhook events `DEVICE_RISK_SIGNAL` and `DEVICE_RISK_ALERT`** (`WebhookEvents`): a Device risk signal that asks for more (identifiers, signals and the engine's verdict, never a trait), and an alert rule of the workspace that went off. Signed like every event.
- **Device risk in one line: `tq.deviceRisk.check(req.body.touchque_request_id, { event, externalUsername, clientIp })`** with the script tag (`device.js`, `@touchque/web` 1.6.0), which fills that field. Pass it as it came: missing, empty, made up or expired is still a verdict (`report: 'missing' | 'unknown' | 'expired' | 'invalid'`, the signal `device_identification_missing`, a number-matched step-up at most), never an exception. The object form `check({ requestId | deviceRisk, … })` still works. `DEVICE_RISK_REPORTS`, `DeviceRiskCheckRequest`.
- **Device risk: `tq.deviceRisk.check({ requestId, event, externalUsername, clientIp })` and `tq.deviceRisk.getEvent(requestId)`** (a paid add-on; 409 `device_risk_off` until the workspace turns it on). The page identifies with `@touchque/web` `deviceRisk.identify({ siteKey, purpose })` and sends you `requestId`; `getEvent` reads the trusted identification (visitorId, confidence, what the page showed, the risk engine's verdict), `check` binds it to an account (one per identification) on sign-up and password-reset pages, and `login.request` / `risk.check` take `deviceRiskRequestId` (or the relayed report as `deviceRisk`). Every signal only ever asks for more (`stepUp`, never a refusal), each says whether it is `enforced`; signals start in shadow, a visitor your admin marked "step up always" asks at once. `parseDeviceRiskCheck`, `DEVICE_RISK_EVENTS`.
- **Pairing a browser by QR code: `tq.qrPairings`.** `create({ keyThumbprint, clientIp, userAgent, browser, os, ttlSeconds })` registers a pairing for the browser key your page holds (`@touchque/web` `browserKey.thumbprint()`) and returns `uri` (`touchque://pair-browser?…`) to show as a QR code; the nonce in it stays with you (Touchque keeps its hash). `get(pairingId)` says who scanned it and how near the phone was (`proximity`), `refuse(pairingId, { reason, message })` tells the phone why your own checks said no. `login.request({ …, qrPairing })` asks the phone that scanned, once, with number matching. `qrPairingUri`, `QR_PAIRING_REFUSAL_REASONS`.
- **Webhook reason `user_blocked_agent`** (`WebhookReasons.USER_BLOCKED_AGENT`): the person rejected an AI agent's request with Block this agent on their phone; the agent may not ask them again, and 2FA is not frozen. `AgentBlock.reason` gains `'phone'` for such a block.
- **Actions: the `agent.approval` trigger.** Your own code before an AI agent's request reaches the phone (`event.agent`, `event.request.authorizationDetails`, `amounts`, `destinations`, `newDestination`, `presence`, `reason`, `event.policy`); only tightening counts: `api.deny` (403 `action_denied`), `api.requirePasskey` (the passkey path), `api.stepUp` (a background agent must bring the person in).
- **AI agents: events for a SIEM.** `agents.listEvents({ after, since, limit })`: the workspace's agent events (`AGENT_*`, `AGENTS_*`) oldest first, each with its agent, person, approval and case code; keep `next` and pass it as `after`.
- **AI agents: the workspace's policy and a passkey line.** `agents.getWorkspacePolicy()` / `setWorkspacePolicy(policy)`: every agent's floor (an agent's own policy can only be stricter, field by field). `requirePasskeyAbove: { TRY: '10000.00' }` in any policy: over it the person approves with a passkey on your page (`AgentApprovalState.requiresPasskey`), never on the phone or with a mandate; a background request gets 409 `interactive_required`. Webhook `AGENT_WORKSPACE_POLICY_CHANGED`. A second approver who answers sooner than a person can gets no token (status `blocked`, reason `inhuman_approval`).
- **Touchque Login: the approving app's name and custom-domain-only sign-in.** `identity.setApproverAppName(name)`: the phone app the hosted pages tell customers to approve on ("Approve on the Acme app"; `null` = your brand when the Mobile SDK is set up, else Touchque). `identity.setCustomDomainOnly(true)`: serve sign-in only on the primary custom domain ({slug}.login.touchque.com redirects page loads there and refuses other calls; needs a verified primary domain with a working certificate). `identity.checkDomainCertificate(domainId)`: the domain's certificate at the sign-in edge now (`certificate`: pending, active or error).
- **Cross App Access (ID-JAG) and A2A agent cards.** `requestIdJag` trades a member's ID token for an ID-JAG at the organization's identity provider, `redeemIdJag` trades it for an access token at the other service (jwt-bearer); `IdJagVerifier` checks one at your own authorization server (typ, issuer, single audience, client, expiry, used once; `firstUse` for a shared store). `verifyAgentCard` checks an A2A card's signatures (JWS over the RFC 8785 canonical card; `jku` only on the card's host or `trustedJkuHosts`), `signAgentCard`, `canonicalJson`.
- **Security-change lock, look-alike destinations, Second Thought questions — for any action type.** `login.request` takes `securityChanges: { password, mfa, device, email, phone }` (when each last changed in your system; a Date, ISO 8601 or epoch ms): access rules and Actions read `minutesSince.mfaChange`, `.deviceChange`, … (e.g. refuse `PAYOUT_CHANGE` within 24 h of a 2FA change). `destination: { kind: 'iban' | 'account' | 'wallet' | 'address' | 'payee', value, known? }` is shown in full on the phone in groups of four, with a warning when it looks like one the user used before but is not the same; the answer's `destination` is `{ known, lookalike }`, rules read `destination.lookalike`. `locale: 'tr' | 'en'` for those rows. `actionTypes.define(type, { secondThought: { questions, locale } })` (at most two of `SECOND_THOUGHT_QUESTIONS`): the phone asks them before Approve and a risky answer makes the approval `provisional`.
- **Mobile SDK: your own app approves for your users.** `tq.mobile.createEnrollment({ externalUsername, replace?, ttlSeconds? })` gives a one-time `tqe_` token your iOS/Android app spends with the Touchque Mobile SDK for iOS and Android; `listDevices`, `getDevice`, `removeDevice`, `settings`, `updateSettings` (app ids, attestation). `mobilePushFromWebhook(event)` turns the signed `MOBILE_PUSH` webhook into the APNs payload / FCM data you send with your own keys; `isMobilePushExpired`.
- **Mobile SDK: Touchque can send the push.** `updateSettings({ apns: { keyId, teamId, topic, key, production }, fcm: { serviceAccount } })` gives Touchque your own APNs key / Firebase service account; it then pushes that platform itself instead of the `MOBILE_PUSH` webhook (`null` removes a key). `settings().push` shows who pushes, never the keys. `updateSettings({ androidCerts })`: the SHA-256 of each Android app's signing certificate, checked against Key Attestation at enrollment. `mobile.testPush(deviceId)` sends a harmless push the way a request would reach the phone and says which way it went (`touchque` / `webhook`) and whether APNs / FCM took it; a `MOBILE_PUSH` webhook may now have `kind: 'test'`.
- **`clientSignals` on `login.request` and `risk.check`:** pass the end user's page check from `@touchque/web` (`startClientSignals().encode()`); a browser driven by software (automation, an AI browser agent) is never silent and asks with number matching, or is refused where the workspace blocks it (403 `automated_client`).
- **Help desk.** `tq.assist.open({ externalUsername, agent: { name, title, ref }, reason })` before your help desk acts on someone's account (their phone gets a calm notice; their "someone says they're from IT" button shows the agent), `verify(id, { action })` before a sensitive action (a 2-digit `challengeCode` the agent reads to the person, who types it and approves on their phone; `no_phone` routes to Never Locked Out), `spend(id, { requestId, action })` right before the action, `unfreeze`, `get`, `list`, `end`; `isAssistCheckPassed(session, requestId)`. Webhooks `ASSIST_*`, among them `ASSIST_CLAIM_UNVERIFIED` (someone pretended to be IT).
- **Touchque Login: an app acting for a customer.** `login.exchangeToken(userAccessToken, { audience, scope })` (RFC 8693; `sub` the customer, `act.sub` the app), `login.askUser({ loginHint, scope, audience, bindingMessage, authorizationDetails })` and `login.waitForUser(ask)` (CIBA, poll mode); `TokenSet.authorizationDetails`, `issuedTokenType`.
- **Touchque Login: token vault.** `login.getConnectionToken(userAccessToken, { connection, scope })` returns the provider's own access token (Google, Microsoft, GitHub…) for the signed-in customer from a connection that stores tokens (`options.tokenVault`); Touchque refreshes it and the refresh token never leaves (`TokenSet.connection`, `CONNECTION_TOKEN_TYPE`). `identity.users.connectedAccounts(id)` and `disconnectAccount(id, accountId)`; My Account `stopAppAccess(id)` and `identities[].appAccess`.
- **`expiresIn` on `login.request`:** how long the push waits for the person, 30 (default) to 300 seconds, for requests the person has to read first (an AI agent asking on their behalf).
- **`McpAuth` for MCP servers whose authorization server is Touchque SSO** (Organization → MCP servers). `new McpAuth({ issuer, resource, tools })`:
  `protectedResourceMetadata()` at `metadataPaths()` (RFC 9728), `verifyRequest({ method, url, headers })` (Touchque's JWKS, issuer,
  audience = this server, expiry, DPoP proof for a bound token), `requireTool(claims, tool)` (403 `insufficient_scope` with the scope),
  `express()` middleware (`req.touchqueMcp`). `McpAuthError` carries the status and the `WWW-Authenticate` header.
- **Next.js (App Router) for Touchque Login:**
  - `createTouchqueLogin({ domain, clientId, clientSecret, secret, appUrl })` gives `handlers.GET` for `app/auth/[action]/route.ts` (`/auth/login`, `/auth/signup`, `/auth/callback`, `/auth/logout`, `/auth/me`, `/auth/token`) and `getSession(await cookies())`.
  - The session is an encrypted cookie, so no store is needed.
  - `@touchque/node/next/middleware` exports `touchqueMiddleware({ secret, protect })`. It protects pages on the Edge with WebCrypto only.
- **Attack protection in `tq.identity`:** `getAttackProtection()`, `setAttackProtection(settings)`, `attackEvents()`.
  **Actions:** the Touchque Login triggers `identity.pre_user_registration` (`deny`), `identity.post_login` (`deny`,
  `requireMfa`, `api.idToken` / `api.accessToken.setCustomClaim`, `api.user.setAppMetadata` / `setUserMetadata`) and
  `identity.post_user_registration`, with their event (`connection`) and `api` types.
- **Email and SMS providers in `tq.identity`:** `getDelivery()`, `setDelivery(channel, provider)` (email: smtp, ses,
  postmark, sendgrid; SMS: twilio, netgsm; a secret left out keeps its stored value), `removeDelivery(channel)`,
  `testDelivery(channel, to)`. **My Account:** `startSmsEnrollment(phone)`, `verifySmsEnrollment(code)`,
  `removeSmsCodes()`; `authenticationMethods().smsCodes`.
- **Touchque Login My Account API.** `login.myAccountToken(refreshToken, scope)` trades a first-party app's
  refresh token for a token for `https://<domain>/me/` (the refresh token rotates: keep the new one);
  `login.myAccount(accessToken)` returns `MyAccount` (`get`, `getProfile`, `updateProfile`, `authenticationMethods`,
  `renamePasskey`, `removePasskey`, `unlinkTouchqueApp`, `setEmailCodes`, `unlinkIdentity`, `setPassword`,
  `removePassword`, `changeEmail`, `sendVerificationEmail`, `sessions`, `endSession`, `endOtherSessions`, `apps`,
  `revokeApp`, `consents`, `setMarketing`, `exportData`, `deleteAccount`). A too-old sign-in throws
  `MyAccountError` with `stepUp: true` (RFC 9470). `login.accountUrl(section?)` links the hosted account page.
- **Touchque Login Management API: `tq.identity`.** `users` (list/search, get, create with a password,
  a bcrypt/argon2 `passwordHash` or an Auth0-style `customPasswordHash`, update with merged metadata, `block`,
  `unblock`, `delete` (KVKK/GDPR erasure), `export`, `sessions`, `signOutEverywhere`, `resetMfa`, `unlinkIdentity`,
  `sendVerificationEmail`, `passwordReset`, `addRoles`, `removeRole`, `logs`), `imports` and `exports` (`start`,
  `get`, `wait`, `file`), `roles`, `organizations` (members, connections, `invite`), `clients` (`rotateSecret`),
  `apis`, `connections`, `customDomains`, and the tenant (`getTenant`, `updateTenant`, `rotateSigningKey`, `outbox`).
- **Touchque Login (hosted sign-in) for your app.** `HostedLogin` is an OpenID Connect client for your tenant
  (`acme.login.touchque.com` or your own domain): `authorizationUrl()` (PKCE S256, state, nonce, `screenHint`,
  `loginHint`, `uiLocales`, `connection`, `organization`, `maxAge`, `acrValues`), `handleCallback()` (state and `iss`
  checks, code exchange, ID token verified against the JWKS: signature, issuer, audience, expiry, nonce, `at_hash`),
  `refresh()` (rotating refresh tokens), `clientCredentials()`, `revoke()`, `userinfo()`, `logoutUrl()`, and
  `verifyAccessToken(token, { audience, requiredScopes })` for your API. Express in two lines:
  `app.use(hostedLoginRoutes({ login, secret }))` mounts `/login`, `/callback` and `/logout` with the session in an
  encrypted cookie (AES-256-GCM, split when large); `requireSignIn()` guards pages and refreshes tokens;
  `requireAccessToken(login, { audience, scopes })` guards APIs.
- **AI agents as identities of their own.** `tq.agents` registers an agent with its PUBLIC key, an accountable
  owner, the action types it may ask approvals for and a review date (`create`, `list`, `get`, `update`, `addKey`,
  `removeKey`, `suspend`, `resume`, `revoke`, `setKillSwitch` for every agent of the workspace at once).
  `TouchqueAgent` is the agent side: it signs in with its own key (private_key_jwt, RFC 7523) for a 10-minute token
  bound to that key with DPoP (RFC 9449) and proves the key on every call, so the agent never holds your API key
  and a stolen token is useless on its own. `generateAgentKey('ES256' | 'EdDSA')`, `jwkThumbprint()`.
  Configured from `TQ_AGENT_ID` / `TQ_AGENT_KEY` when not passed. Shared vectors: `fixtures/agent-vectors.json`.
- **Agent policies and people who stopped an agent:** `tq.agents.setPolicy(id, { requestsPer10Min, requestsPerUserPer10Min,
  amountPerRequest, amountPerDay, background, newRecipients, recipientAllowlist })`, `listBlocks(id)`, `liftBlock(id, user)`.
  Agents carry `policy`. New refusals of `requestApproval`: `blocked_by_person`, `amount_over_limit`, `daily_amount_over_limit`,
  `recipient_not_allowed`, `new_recipient`, `loop_detected`.
- **Agents ask people to approve on their phone.** `agent.requestApproval({ user, type, authorizationDetails, reason,
  presence, expiresIn, locale })` sends structured details (RFC 9396 style: `payment_initiation`, `purchase`,
  `data_access`, `account_change`, `message_send`, `generic`); Touchque draws the phone's rows from them and the phone
  signs exactly those rows. Show `challengeCode` in the conversation. `agent.waitForApproval(id)` resolves with an
  approval token (ES256, `act` = the agent, the exact `authorization_details`, 5 minutes) or throws
  `TouchqueApprovalError` (rejected, blocked, revoked, expired, stale, redeemed). Your executor calls
  `tq.agents.redeemApproval(token, { user, type, authorizationDetails })`: checked against the token before anything is
  used, then used exactly once on Touchque; `TouchqueApprovalMismatchError` on any difference.
  `tq.agents.verifyApprovalToken()` / `verifyApprovalTokenWith()` verify offline with Touchque's keys
  (`GET /agents/jwks.json`); `matchesAuthorizationDetails()` is the shared matching rule.
- **Four eyes and mandates.** `policy.fourEyes = { approvers, above?, types? }`: after the person, a second person
  (never the same one, never the agent's owner) approves on their phone before any token; `waitForApproval` keeps
  waiting through `awaiting_second` (`secondApprover`, `secondChallengeCode`). `agent.requestMandate({ user, type,
  maxCount, maxTotal, perRequest, recipients, validFor })` asks once for a bounded standing permission; pass
  `mandateId` to `requestApproval` and each request within it is approved without a push, counted atomically.
  `agent.getMandate()`, `agent.revokeMandate()`, `tq.agents.listMandates(id, { user })`, `tq.agents.revokeMandate()`.
- **What Touchque notices about an agent.** Every refusal of `requestApproval` / `requestMandate` carries a `caseCode`
  (open it in the dashboard). New codes: `suspicious_content` (400, `markers`: an instruction to the model or a link that
  carries data in the agent's text), `interactive_required` (409: the risk checks asked for the number and the agent asked in
  the background), `name_too_similar` (409 on `tq.agents.create` / `update`, with `similarTo`). An approval whose number came
  back sooner than a person can answer ends `blocked` with reason `inhuman_approval`. `WebhookEvents` names every agent event
  (`AGENT_SUSPENDED`, `AGENT_INJECTION_SUSPECTED`, `AGENT_INHUMAN_APPROVAL`, `AGENT_LOOKALIKE_NAME`, …).
- **Organization AI agents on Touchque SSO: `TouchqueOrgAgent`.** An agent added in Organization → AI agents gets
  5-minute DPoP-bound tokens for one of the organization's apps from `/sso/token`, proving who it is with its own key
  (private_key_jwt) or with its platform's token (`assertion: githubActionsToken('touchque')` or `fileToken(path)` for a
  Kubernetes service account; GitLab, Google Cloud and Azure tokens the same way). `getToken({ resource, scope })` (cached),
  `authorization(method, url)` (the Authorization and DPoP headers), `fetch(url, init)`, `dpopProof()`. Configured from
  `TQ_ORG_AGENT_ID`, `TQ_ORG_AGENT_KEY` and `TQ_SSO_URL` when not passed.
- **An organization's agent acts for a member.** `agent.exchangeToken({ subjectToken, resource, scope })` (RFC 8693:
  the member's own token for one of the agent's apps), `agent.askMember({ loginHint, bindingMessage, authorizationDetails,
  resource, scope })` and `agent.waitForMember(request)` (CIBA, poll mode: the member approves on the phone with the number
  in `bindingCode`; the token carries the approved `authorizationDetails`). Both need the agent's delegation setting.
- **An organization's agent uses a member's own account elsewhere (token vault).** `agent.getConnectionToken({ subjectToken, connection, scope })`: the member's own access token at Google, Microsoft 365, GitHub, Slack, Salesforce or any OAuth 2.0 service they connected on Touchque (portal `/connections`), for a connection that names the agent (Organization → AI agents → Accounts agents may use). A Bearer token for that service; Touchque refreshes it and the refresh token never leaves; `invalid_grant` when the member has not connected it, disconnected or left.
- **An organization's agent asks for a shared account.** `agent.askToOpenSharedAccount({ account, loginHint, message })` → `{ askId, openUrl, status, expiresIn }`: the member opens `openUrl` where their Touchque extension is paired, their phone approves with the agent named, and the extension signs in there; the agent never sees the password. `agent.sharedAccountAskStatus(askId)` and `agent.waitForSharedAccount(ask)` say only how it ended (`opened`, `refused` with a reason, `declined`, `expired`).
- **Token vault for your agents (`tq.agents.vault`).** `putConnection(name, { provider, clientId, clientSecret, tenant?, issuer?, agentIds })` (google, microsoft, github, facebook, linkedin, x, oidc: your OAuth app there), `deposit(connection, user, { accessToken, refreshToken, expiresIn, scope })` after your own OAuth flow with the person, `listConnections`, `listAccounts(user)` (never a token), `removeAccount`, `removeConnection`. The agent: `agent.getConnectionToken({ user, connection, scope })` (scope `vault:read`): a fresh Bearer token for that service, refreshed by Touchque; the refresh token never leaves.
- **Agent framework helpers.** `withTouchqueApproval(fn, policy)` runs a tool only after the person approved on the phone (`currentApproval()` holds the approval token inside it; the function keeps its arguments, so it fits LangChain `tool()`, Vercel AI SDK `execute`, LlamaIndex `FunctionTool`, OpenAI Agents SDK `tool({ execute })`), `requireAgentApproval(policy, args)`, `approveInterruptionsWithTouchque(result, policies)` (OpenAI Agents SDK `needsApproval`), `touchqueCanUseTool` / `touchquePreToolUseHook` (Claude Agent SDK), `guardMcpClient(client, policies)` (the token goes in `_meta['touchque/approvalToken']`).
- **API key scopes are enforced:** a key created with narrower scopes (for example `login:*`) is refused
  elsewhere with 403 `insufficient_scope`. Keys with `authenticator:*` (the Dashboard default) are unchanged.
- **`device` on `auth.getUser()`:** the linked phone's posture (`DevicePosture`: platform, model, OS version, security
  patch, screen lock, jailbreak/root, hardware key, attestation, `state` and `issues`), or `null` before a phone is linked.
- **`challengeDigits`** on `login.request` / `login.verify` (`2 | 3`): the length of the matching number when
  one is shown, `3` for 100–999. The longer of this and your workspace policy wins: a request can lengthen the
  number, never shorten it.
- **Codes during a Touchque outage:** `offline.totpVerifiers()` and `offline.matchTotpVerifier()`. While Touchque answers, fetch salted,
  slow digests of your users' next time-based codes (up to 4 hours ahead, 24,000 user-steps a call; never a key); while it
  cannot be reached, check a typed code against them locally. Needs the workspace policies `offlineTotpEnabled`
  and `outageVerifiersEnabled`; frozen and removed users fall out on the next fetch.

## [4.0.0] — 2026-10-20 — Touchque Actions

> 3.6.0 (Never Locked Out) and 3.7.0 ("Why?" case codes) below were not published on their own; they ship in 4.0.0.

### Breaking
- **Action types moved to `tq.actionTypes`** (`define`, `list`; class `ActionTypes`). `tq.actions` is now
  Touchque Actions. Replace `tq.actions.define(...)` with `tq.actionTypes.define(...)`.

### Added
- **Touchque Actions** (`tq.actions`): your own code at points of the approval pipeline, run by Touchque in a
  sandbox. See [Actions](https://support.touchque.com/actions).
  - `deploy(slug, { trigger, code | handler | template, secrets, allowedHosts, capabilities, onFailure, order,
    enabled, activate })` (idempotent; a version asking for a loosening capability returns
    `approval.required` and waits for an admin's phone approval), `list`, `get`, `version`, `update`,
    `delete`, `rollback(slug, version?)`.
  - `handler`: deploy a self-contained typed function as `onExecute` (`handlerToCode`).
  - Developer loop: `test({ … , eventId | event })` (one run, nothing sent), `dryRun({ …, replaces, limit,
    since })` (replay against recent real decisions: `changed`, `transitions`, errors, timing), `events`,
    `logs`, `metrics`.
  - `triggers()`, `templates()`, `renderTemplate(id, trigger, params)`; `secrets.set | list | delete`.
  - Types for writing Actions: `LoginRequestEvent`, `RiskCheckEvent`, `ApprovalDecidedEvent`, `FactEvent`,
    `LoginRequestApi`, `RiskCheckApi`, `ActionApi`, `ActionHandler`.
- `context` on `login.request`, `risk.check`, `start` and the guards (`requireTouchque`, `withTouchque`,
  `runGuard`: `context: (req) => ({ roles, amount })`): for your Actions only (`event.context`), never shown on
  the phone.
- **`onChallenge` on `login.verify()`** (and `tq.protect()`): with number matching the phone asks for a number
  that `verify()` used to return only after the approval. `onChallenge` runs once, right after the request is
  created and before the wait, with `{ requestId, challengeCode?, expiresAt, reasons?, caseCode? }` (type
  `VerifyChallenge`; options type `VerifyOptions`). Show `challengeCode` to the user now; the phone asks for it.
  Not called when only a passkey can approve. An error it throws, or a promise it returns that rejects, is logged
  and ignored: `verify()` keeps waiting.
- `RiskReason.action`: with `code: 'action'`, the slug of the Action that asked.
- `HttpClient.put` / `patch`.
- **Passkey autofill** (WebAuthn conditional mediation): `webauthn.primaryOptions()` without
  `externalUsername` asks for options that accept any passkey of your site (empty `allowCredentials`), and
  `primaryVerify` names the user the passkey belongs to. `touchqueRouter`'s `POST /passkey/authenticate/options`
  does the same when the body has no `email`, so `@touchque/web`'s `passkeys.autofill()` works with no extra
  route. Needs the API that answers usernameless options (authenticator 2026-10-20).

## [3.7.0] — 2026-10-19 — "Why?" case codes

### Added
- **Case codes.** Every approval decision Touchque makes (`login.request`, `risk.check`) now names a short case
  code (`K7P-2QX`: 6 characters without I, O, 0 or 1). Show it to your user ("Tell your support team: K7P-2QX");
  your team opens the whole decision by that code in the dashboard (Logs → Look up a case): each check, the rule
  that matched, the signals the risk engine acted on and the ones it only measured, and the single change that
  would have let it through.
  - `LoginRequestResponse.caseCode` and `reasons` (why number matching or a passkey is needed: a fixed list of
    plain English reasons, never a score).
  - `RiskCheckResult.caseCode`.
  - `TouchqueAPIError.caseCode` on refusals (blocked, frozen, rate limited, provisional, keys lost).
  - Steps (`tq.start`, `requireTouchque`, `withTouchque`, `touchqueRouter`) carry `caseCode` and `reasons`; the
    guard keeps showing the code while it waits. Both are safe to send to the browser.
- The fake API (`startFakeApi`) answers with case codes (`K7P-2QX` for a push, `REF-USE` for a refusal,
  `CHK-2QX` for a check).

## [3.6.0] — 2026-10-19 — Never Locked Out

### Added
- **Never Locked Out.** A user whose phone is lost, dead or replaced moves to a new phone without a help desk:
  colleagues they named vouch on their own phones, then a cooling-off anyone can veto.
  - `tq.recovery.setVouchers({ externalUsername, vouchers })` and `tq.recovery.vouchers({ externalUsername })`
    (who can vouch today and why not). Ask for the user's phone before you change the list.
  - `tq.recovery.start({ externalUsername, clientIp?, userAgent?, displayName?, fallbackVouchers?, required?,
    coolOffMinutes?, details? })` → `RecoveryStarted` with `bindUri` (show it as a QR for the new phone);
    `tq.recovery.status(id)` (each voucher's `code` while it can be used, the receipt chain), `tq.recovery.list({
    externalUsername } | { open: true })`, `tq.recovery.veto(id, { by?, reason? })`, `isRecoveryOpen`.
  Only after your first factor (password, IdP). The risk engine's BLOCK refuses; hard signals add a voucher and
  double the cooling-off. Errors carry `code`: `not_enough_vouchers` (with `required`, `eligible`, `vouchers`),
  `recovery_in_progress`, `blocked`, `frozen`, `rate_limited`, `device_not_linked`. After a vouch move, critical
  actions answer 403 `blocked` / `recovery_probation` for 24 h. New webhook events `RECOVERY_STARTED`,
  `RECOVERY_DEVICE_BOUND`, `RECOVERY_COOLING`, `RECOVERY_COMPLETED`, `RECOVERY_VETOED`, `RECOVERY_EXPIRED`,
  `RECOVERY_FAILED`; `DEVICE_LINKED` can carry `via: 'recovery'`.
- `details` / `noticeDetails` on start: what the vouchers' phones and the old phone show, in your words (default
  English lines otherwise).
- Approval requests on the phone carry `expiresAt` (a vouch stays open for 10 minutes).

### Changed
- Phone-to-phone transfers must be signed by a phone with a hardware key (the apps do since this release) and move
  only the accounts the phone chose.
## [3.5.0] — 2026-10-18 — Silent sign-ins

### Added
- **Silent sign-ins.** Stop asking the phone again and again when nothing about a sign-in is new. Touchque's
  risk engine decides; the push is skipped only when it says so.
  - `tq.risk.check({ externalUsername, type?, clientIp?, userAgent?, browserProof?, maxAgeSeconds? })` →
    `{ prompt, reasons, assurance, silentMode }` (`RiskCheckOptions`, `RiskCheckResult`, `RiskReason`). Sends
    nothing to the phone. Read fail-closed: `prompt` is `false` only when the API answered the boolean `false`;
    malformed `reasons` become `[]`, a missing `assurance` is `'normal'` (`parseRiskCheck`).
  - `tq.risk.browsers({ externalUsername })` and `tq.risk.forgetBrowsers({ externalUsername, thumbprint? })`: the
    browsers Touchque knows for a user, and forgetting one or all of them.
  - `login.request({ …, browserProof })` and `tq.start(action, { …, browserProof })`: the browser's device-bound key
    proof (`X-Touchque-Browser`, made by `@touchque/web` 1.4.0), passed through untouched; once the request is
    approved, Touchque knows that browser.
  - `silentSignIn` option (default off) on `requireTouchque`, `withTouchque`, `touchqueRouter` (POST /login) and
    `runGuard`: a new attempt carrying the `X-Touchque-Browser` header is checked first; `prompt: false` approves
    it at once with no push (`assurance.method: 'silent'`, `confirmedVia: 'SILENT'`, `requestId: 'silent'`,
    `reasons`; `onAuthenticated` gets `via: 'silent'`). Otherwise, and on any error in the check, the usual push
    starts with the proof attached. `{ maxAgeSeconds }` sets your own limit on the age of the last phone approval.
  - `GUARD_HEADERS.browser` (`x-touchque-browser`), `SilentSignInOptions`.

## [3.4.0] — 2026-10-18

### Added
- **Vishing Shield.** When the user taps Approve during a call (or with the screen shared or the phone
  remote-controlled), Touchque can move the request to a passkey, refuse it, or approve it as provisional:
  - `Approval` (and `GET /login/status`, `LoginStatusResponse`) carry `provisional`, `reconfirmedAt`,
    `revoked` and `revokeReason`. A provisional approval lets the user in, but Touchque refuses their critical
    actions (`blocked` / `provisional`) until the phone re-confirms it after the call.
  - `WebhookReasons` (`vishing_suspected`, `phishing_origin`, `user_reported_coached`, and the existing ones)
    and `WebhookEvents` (`APPROVAL_RECONFIRMED`, `APPROVAL_REVOKED`, and the existing ones).
- **Mirror Alarm.** The first waiting step carries `canary: { url }`; `@touchque/web` 1.3.0 loads it on the
  page that shows the sign-in, so a real-time phishing proxy gets the approval refused
  (`reason: 'phishing_origin'`). Allow the canary host in your CSP (`img-src`, `connect-src`).

### Changed (behaviour)
- **`login.waitForApproval`, `login.verify` and `tq.protect` throw `TouchquePasskeyRequiredError`
  (`reason: 'step_up'`) when a poll shows the request now needs a passkey** (PENDING with `requiresPasskey`),
  instead of polling into a `TouchqueTimeoutError`. Finish it in the browser with
  `@touchque/web` `passkeys.approveLogin({ requestId })`. The error's new `reason` is `'policy'` for the
  passkey-only policy, as before.
- The guard switches a waiting offline QR to `passkey_required` when its push moved to a passkey, and an
  offline code Touchque refuses for that reason answers `passkey_required` instead of `blocked`.
- An approval the user took back on the phone answers the guard with `expired` / `revoked`.

## [3.3.0] — 2026-10-12

### Changed (behaviour)
- **`withTouchque` (Next.js / Fetch) no longer trusts `X-Forwarded-For` by default.** It used to send the
  leftmost hop as the end user's address; behind a proxy that appends (nginx
  `$proxy_add_x_forwarded_for`) that hop is whatever the client sent, so an attacker could pick the
  address every risk signal and the phone's location display used. Without `ip` it now sends no
  address. Set `trustedProxyHops` (the number of proxies in front of your app) or use a preset:
  `ipFromVercel`, `ipFromCloudflare`, or your own function.

### Security
- **Adding a passkey needs the phone.** `touchqueRouter`'s `/passkey/register/options` used to hand out
  registration options to anyone holding your app's session, and a passkey approves requests on its
  own, so a stolen session cookie could become a permanent second factor. For a user with a linked
  phone the route now answers the same two-phase step as `/login` (202 with the number to show; the
  user approves a `PASSKEY_ENROLL` request on the phone) and returns the options only after that
  approval, once. Users without a linked phone are unchanged. The Touchque API enforces this too:
  `tq.webauthn.registerOptions` takes the approved request id as `approvalRequestId`.
- **Passkey delete needs the user.** The API now refuses `DELETE /webauthn/credentials/{id}` without
  `externalUsername`: `tq.webauthn.deleteCredential(id, { externalUsername })`.

### Fixed
- **Waiting on an approval no longer hits the rate limit.** Each browser poll of `/login` counted against
  the per-user limit (5 a minute), so a user who took more than about 7.5 s to approve got a 429 while
  the push was still on the phone. A poll that carries a valid, still-waiting token only reads the
  status and now has its own per-IP budget; new attempts are counted as before.

### Added
- The waiting step carries `telemetryToken` when the workspace collects behavioural signals, so
  `@touchque/web` can send them (pass `telemetry: { apiBaseUrl }` to `touchqueFetch`). Before, the token
  never reached the browser and the bot and browser signals never ran for SDK integrations.
- `forwardedFor(req, hops)`, `ipFromVercel`, `ipFromCloudflare`.

## [3.2.1] — 2026-10-11

### Security
- **The pre-auth relay no longer hands out a first-time linking QR.** `touchqueRouter`'s `POST /login` used to answer
  an unlinked user with a linking QR code and recovery codes for whatever username was typed.
  Anyone could scan that QR first and link their own phone to someone else's account. Now it
  answers `{ state: 'enroll' }` without a QR unless `getLoginUser` is set, i.e. unless the route
  only runs after your own password step. Linking from a signed-in page (`/enroll/start`, the
  step-up guard) is unchanged. Your own guards can opt out with `runGuard({ enroll: false })`.

## [3.2.0] — 2026-10-11

### Added
- **`tq.login.reportFraud(requestId, { reason, note })`** — report a request you later learned
  was fraud (chargeback, account takeover, social engineering). Touchque's risk engine uses it as
  its strongest training signal and it is kept in your audit log; the request's status does not
  change. Idempotent (`alreadyReported: true` on a repeat).
- `verifyApprovalProof` is now checked against the cross-SDK golden vectors
  (`fixtures/approval-proof-vectors.json`) shared with the Python, PHP and Go SDKs.

## [3.1.0] — 2026-09-30

### Security
- **A phone-side reject kills the offline QR.** `tq.offline.challenge({ requestId })` and
  `verifyTotp({ requestId })` tie the QR / time-based code to the push it follows. Once the phone REJECTS the push,
  no new QR is issued for that sign-in (`409 request_rejected`) and no code — QR or time-based — finishes it
  (`reason: 'request_rejected'`). `requireTouchque`, `touchqueRouter` and `tq.start` flows link the QR
  automatically; while the QR is on screen the guard keeps checking the push, so the page learns about a reject
  straight away (`state: 'rejected'`) — and about an approval, which finishes the action without typing a code.

### Added
- **Number matching on the offline QR.** When the linked push (or `requireNumberMatch: true`) uses number
  matching, `challenge()` returns `challengeCode` — print it under the QR. The phone shows it among two decoys
  after scanning and the user taps the match; the phone is never told which is right, so a wrong tap yields a code
  that fails verification. `Step.offline.challengeCode` carries it through the step-up flow.

## [3.0.0] — 2026-09-29

### Security
- **Webhook replay protection.** `webhook.verify()` now rejects a webhook whose
  signed `timestamp` is missing or unparseable (previously the freshness check
  was silently skipped). New `replayCache` option (`MemoryWebhookReplayCache`,
  or your own `WebhookReplayCache` over Redis/DB): a second delivery of the
  same `jti` throws `TouchqueWebhookReplayError` (a subclass of
  `TouchqueWebhookSignatureError`) — answer 200 to it, it is a duplicate.
- **`verifyApprovalProof` fails closed without a pinned key.** It now returns
  `false` unless `expectedPublicKey` is given, or `allowUnpinnedKey: true` is
  passed explicitly (trust-on-first-use: store `proof.publicKey` and pin it
  from then on). **Behavior change:** callers that did not pin now get `false`.
- **`touchqueRouter` offline routes are off without a first factor.**
  `/offline/challenge`, `/offline/verify` and `/offline/totp` answer 403
  `OFFLINE_REQUIRES_FIRST_FACTOR` unless `getLoginUser` is set (or
  `allowOfflineWithoutFirstFactor: true`), so they can't be used to burn an
  arbitrary user's offline attempts. **Behavior change** for routers without
  `getLoginUser`.

## [2.0.0] — 2026-09-28

### Added
- `Touchque()` with no arguments reads `TQ_API_KEY` / `TQ_API_SECRET` /
  `TQ_API_URL` from the environment.
- `tq.start` / `tq.check` / `tq.complete` — the headless step-up flow: start
  an approval, get back a JSON-safe `Step` (the matching number, the
  enrollment QR, or a `blocked`/`frozen`/`rate_limited` refusal) to render in
  your own UI, and complete an approved request exactly once
  (`POST /login/:id/consume`, atomic).
- `requireTouchque('ACTION', options?)` — new single-argument signature; the
  client defaults to one built from the environment. The old
  `requireTouchque(tq, action, options)` signature still works.
- `withTouchque` — the same guard for Next.js route handlers / any Fetch API framework.
- `tq.actions.define` / `tq.actions.list` — define action types from code
  instead of the Dashboard; never re-enables a type an admin disabled.
- `retryAfter` on `TouchqueAPIError`.

### Changed
- **Breaking:** default `baseUrl` is `https://api.touchque.com` (the
  previous default, `api-authenticator.touchque.com`, had no DNS record and
  was unreachable).
- **Breaking:** the matching number for number-matching is now available
  **before** approval through `requireTouchque` and `touchqueRouter`'s
  `POST /login`, which both answer `202 { touchque: step, token }` while
  waiting instead of blocking until approved. Previously the number arrived
  only in the final response, with no way for a partner's frontend to see it
  in time — number matching could not be completed through the one-line guard.
  `touchqueRouter`'s `/login` response on success no longer includes
  `challengeCode` at the top level (it is in the intermediate step instead).
- **Breaking:** `touchqueRouter`'s `POST /enroll/start` no longer falls back
  to `resetSecret` when a phone is already linked (409) — that let a session
  satisfying `getUserId` silently unlink and replace a victim's phone. It now
  returns `409 { error: 'already_linked' }`; only issues a fresh secret when
  the account is confirmed not linked.
- Relay errors from `touchqueRouter` forward Touchque's machine-readable
  `code` only, never its internal message text.

## [1.9.0] — 2026-09-27

### Added
- Phishing-resistant sign-in with passkeys on your own domain. When the
  workspace requires a passkey for an action (Security Policy), no push is
  sent: `login.request()` returns `requiresPasskey: true`, `login.verify()`
  throws the new `TouchquePasskeyRequiredError` (with `requestId`) instead of
  polling, and `touchqueRouter` answers `409 PASSKEY_REQUIRED`.
- `assurance: { phishingResistant, method }` on `LoginStatusResponse` and on
  SUCCESS `WebhookPayload` (`ApprovalAssurance` type). Only passkeys are
  phishing-resistant.

### Changed
- With `getLoginUser`, a passkey approval for a different user opens no
  session (`401 verification_failed`).
- Touchque now requires user verification (PIN / biometric) for passkey
  registration and approval.

## [1.8.0] — 2026-09-27

### Added
- `touchqueRouter` option **`getLoginUser(req)`**: binds `POST /login`,
  `POST /offline/challenge`, `POST /offline/totp` (and the user an offline code
  may sign in) to the user who passed your first factor. The username in the
  request body is then ignored, and without a first-factor user the routes
  answer `401 FIRST_FACTOR_REQUIRED`. Recommended for every deployment: it stops
  anyone from pushing to, or locking out, an arbitrary user through your server.
- Built-in rate limiting for the pre-auth routes (`rateLimit`, on by default:
  20 per IP and 5 per username per route per minute, `429 RATE_LIMITED` with
  `Retry-After`). `rateLimit: false` turns it off. `RateLimitOptions` is exported.

### Changed
- The router logs a one-time warning when `getLoginUser` is not set.

## [1.7.2] — 2026-09-27

### Security
- `touchqueRouter` `POST /passkey/login/verify` no longer opens a session for an
  `externalUsername` sent by the browser. It now uses the user Touchque reports
  as approved (the API returns it). Previously a signed-in user could approve
  their own pending request with their own passkey and claim to be someone
  else. Upgrade if you use `onAuthenticated` with passkey approvals.
- `DELETE /passkey/credentials/:id` is scoped to the signed-in user
  (`tq.webauthn.deleteCredential(id, { externalUsername })`), so one user can
  no longer remove another user's passkey.

## [1.7.1] — 2026-09-27

### Fixed
- `offline.verify()` / `offline.verifyTotp()` reported every rejected code as
  `reason: 'not_approved'` and never returned `attemptsLeft`: the HTTP client
  dropped `reason` and `attemptsLeft` from error bodies. They now come through
  (`invalid_code`, `locked`, `expired`, `used`, …).

### Changed
- The offline QR content is encrypted for the user's phone (`TQ2.…`); it is no
  longer readable by a QR or JWT decoder. Requires Touchque API with offline
  sign v2 (deployed) and the current Touchque app.

## [1.7.0] — 2026-09-26

### Added
- `tq.offline` — approvals that work while the user's phone has **no
  internet**. `challenge({ externalUsername, type, details?, clientIp?,
  userAgent?, ttlSeconds? })` returns a QR (`qr`, and a ready PNG in
  `qrDataUrl`) whose content is encrypted for the user's phone, so a QR
  decoder or any other device sees only ciphertext; the phone scans it
  offline, opens it after Face ID, shows the brand, the action
  and the transaction details, asks for Face ID and shows a 7-character code;
  `verify({ challengeId, code })` checks what the user typed. A code is bound
  to one challenge and works once; a challenge locks after 5 wrong codes.
  Wrong / expired / used / locked answers resolve `{ approved: false, reason }`
  instead of throwing.
- `verifyTotp({ externalUsername, code, type? })` — optional lower-assurance
  fallback: the rolling 30-second code the app shows without a QR. It carries
  no transaction details, so it is refused for critical actions. Needs
  `offlineTotpEnabled` in the workspace policy.
- `touchqueRouter` relays `POST /offline/challenge`, `/offline/verify` and
  `/offline/totp`; `onAuthenticated` receives `via: 'offline' | 'offline-totp'`.
- Both features are off until you turn on "Offline sign" in the dashboard's
  Security Policy page.

### Notes
- This is a MAC-based scheme: only Touchque can verify a code, so unlike
  `verifyApprovalProof` it is not verifiable by a third party.
- A phishing page can show a real QR unchanged; the phone displays the brand,
  location and device so the user can notice.

## [1.6.0] — 2026-09-26

### Added
- `verifyApprovalProof(proof, { requestId, type, details, challengeCode,
  expectedPublicKey })` and `detailsDigest(details)`: verify the phone's
  device-signed proof that the user approved exactly the transaction you
  requested ("what you see is what you sign"). The proof (`approvalProof`)
  comes in the SUCCESS webhook and in `login.status()`; it is present when
  the approving phone holds a Secure Enclave key. Checking it does not
  require trusting Touchque: it shows the enrolled device signed these
  details, and any change to amount, recipient, type or request fails.
- `approvalProof` / `confirmedVia` on `LoginStatusResponse` and
  `WebhookPayload` types.

## [1.5.0] — 2026-09-26

### Added
- `details` on `login.request()` / `login.verify()`: transaction context
  shown on the mobile approval screen (e.g. `{ Amount: '1,250.00 USD',
  Recipient: 'Jane Doe' }`), as an object or an ordered
  `[{ label, value }]` array. The API rejects out-of-limit values with a 400
  (at most 8 entries, labels ≤ 40, values ≤ 120 characters) rather than
  truncating what the user sees.
- `getDetails(req)` option on `requireTouchque` and `touchqueRouter`, and
  `getContext(...args)` on `tq.protect()` (returns `clientIp`, `userAgent`,
  `details`).

### Changed
- `requireTouchque` now forwards `req.ip` and the `User-Agent` header as
  `clientIp` / `userAgent`, like `touchqueRouter` already did. Previously
  requests sent through the middleware showed no location or device on the
  approval screen.

## [1.4.1] — 2026-09-23

### Documentation
- `touchqueRouter`'s `POST /login` route: clarified inline (and in this
  entry) that the `clientIp` it forwards from `req.ip` only reflects the
  real end user's address when the integrator's own Express app has its
  own `app.set('trust proxy', ...)` configured for its deployment —
  otherwise it is the reverse proxy's own loopback address. No functional
  change; the router still intentionally does not read `X-Forwarded-For`
  itself, since doing so would let a directly-connecting client spoof its
  IP on a deployment with no reverse proxy in front.

## [1.4.0] — 2026-09-16

### Added
- `touchqueRouter(tq, options)` — a mountable Express Router that wires the
  ~9 relay routes every partner backend needs for classic push 2FA
  (enrollment + login) and passkeys (ceremonies + management). Previously
  every partner hand-copied this from `@touchque/web`'s README ("Minimal
  Express relay") or a reference server — ~95 lines of
  generic glue code, identical for any partner apart from how they resolve
  the signed-in user. `app.use('/touchque', touchqueRouter(tq, {
  getUserId, onAuthenticated }))` replaces all of it. `requireTouchque`'s
  existing error-class-to-HTTP-status mapping is reused unchanged.
- `GenerateSecretResponse`/`ResetSecretResponse` types now include the
  `qrCodeDataUrl` field the API already returned (a ready-to-render
  `data:image/png;base64,...` QR code) — previously untyped, so TypeScript
  users lost autocomplete on the one field enrollment actually needs.

## [1.3.1] — 2026-09-16

### Added
- New `TouchqueNetworkError` class: thrown when a request never reached
  Touchque at all (connection refused, DNS failure, client-side timeout).
  Previously these were indistinguishable from a real Touchque 500
  (`HttpClient.handleError` always fell back to `TouchqueAPIError(500, {})`
  when there was no HTTP response), which made it impossible for callers
  to build a sane retry policy. `TouchqueNetworkError` is generally safe
  to retry; `TouchqueAPIError` often is not.

## [1.3.0] — 2026-09-06

### Changed
- `webauthn.deleteCredential()` return type corrected to `{ deleted: boolean }`
  (the API returns `deleted`, not `success`).
- Doc: the WebAuthn resource header no longer says "there's no client-side SDK"
  — the browser side is `@touchque/web`.

### Note
- Version bumped to **1.3.0** to align the whole server SDK line (node / go /
  php / python) now that Go/PHP/Python have caught up to full parity — WebAuthn
  resource, `getUser`, and the `telemetryToken` login-response field.

## [1.2.0] — 2026-08-27

First release published to npm as **`@touchque/node`**.

### Changed
- **Reverted** the 1.1.0 rename: the package name is `@touchque/node` again
  (never actually shipped to npm under either name). Every consumer, the
  public docs, and the MCP server already reference `@touchque/node`; the
  cross-language rename in 1.1.0 was applied to the manifests but never to a
  single consumer. Product scoping for other Touchque products is expressed by the package
  *name* under the shared `@touchque` scope, not by a separate scope.
- `repository.url` corrected to point at this package's own repository.

### Added
- `tq.webauthn.primaryOptions()` / `tq.webauthn.primaryVerify()` — the
  passwordless-primary passkey login flow (no password, no prior
  `login.request`), gated on `TenantPolicy.passwordlessLoginEnabled`.
  Returns `{ requiresStepUp }` when risk/policy demands a second factor.
- `discoverable?: boolean` on `tq.webauthn.registerOptions()` — registers a
  resident credential with forced user verification and a stable WebAuthn
  user handle (the shape a passwordless-primary login authenticates against).
- `tq.auth.getUser({ externalUsername })` — fetch a user's link status
  (`{ used, deviceId }`), previously added but unreleased.
- `telemetryToken` on `LoginRequestResponse` — issued when the integration
  has `behavioralBiometricsEnabled`, for the `@touchque/behavioral-widget`
  browser embed, previously added but unreleased.
- `WebAuthn` resource test suite (`src/resources/WebAuthn.test.ts`); tests
  for `Auth.getUser()` and the Express middleware.

### Packaging
- `package.json` is now publish-shaped: `files: ["dist"]` (no `src`/config in
  the tarball), a conditional `exports` map (ESM/CJS + per-format types),
  `engines.node >= 18`, `sideEffects: false`, `publishConfig.access public`,
  a `prepublishOnly` build+test guard, and `express` declared as an optional
  peer dependency (it is type-only in the SDK).

## [1.1.0] — 2026-08-22

### Changed
- **Breaking:** package renamed from `@touchque/node` to
  `@touchque-authenticator/node` to reflect that this SDK is scoped to the
  Touchque Authenticator (2FA/MFA) product specifically, not Touchque as a
  whole (Touchque's other products have their own separately-named SDKs).

### Fixed
- README no longer documents `tq.actionTypes.*` / `tq.users.*` — these
  resources never existed in the SDK; the corresponding unused
  `ActionType`/`ActionTypeOptions` types and the unused `UnlinkSecretOptions`/
  `UnlinkSecretResponse` import in `Auth.ts` were also removed.

### Added
- First real automated test suite (`vitest`, 36 tests covering `HttpClient`
  signing/error-handling, `Auth`, `Login`, `Webhook`, and error classes).
  The previous `package.json` `test` script pointed at a nonexistent
  `test.js` and never ran anything.
- `LICENSE` (MIT) file, matching the license already declared in
  `package.json`.

## [1.0.1] — prior to this changelog

Initial public functionality: `Auth` (generateSecret/resetSecret/
validateSecret), `Login` (request/status/waitForApproval/verify/
approveWithRecoveryCode), `Webhook` (verify/isValid), Express middleware,
full TypeScript types.
