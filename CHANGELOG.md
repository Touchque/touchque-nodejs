# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [3.4.0] — 2026-10-18

### Added
- **Vishing Shield.** When the user taps Approve during a call (or with the screen shared or the phone
  remote-controlled), TouchQue can move the request to a passkey, refuse it, or approve it as provisional:
  - `Approval` (and `GET /login/status`, `LoginStatusResponse`) carry `provisional`, `reconfirmedAt`,
    `revoked` and `revokeReason`. A provisional approval lets the user in, but TouchQue refuses their critical
    actions (`blocked` / `provisional`) until the phone re-confirms it after the call.
  - `WebhookReasons` (`vishing_suspected`, `phishing_origin`, `user_reported_coached`, and the existing ones)
    and `WebhookEvents` (`APPROVAL_RECONFIRMED`, `APPROVAL_REVOKED`, and the existing ones).
- **Mirror Alarm.** The first waiting step carries `canary: { url }`; `@touchque/web` 1.3.0 loads it on the
  page that shows the sign-in, so a real-time phishing proxy gets the approval refused
  (`reason: 'phishing_origin'`). Allow the canary host in your CSP (`img-src`, `connect-src`).

### Changed (behaviour)
- **`login.waitForApproval`, `login.verify` and `tq.protect` throw `TouchQuePasskeyRequiredError`
  (`reason: 'step_up'`) when a poll shows the request now needs a passkey** (PENDING with `requiresPasskey`),
  instead of polling into a `TouchQueTimeoutError`. Finish it in the browser with
  `@touchque/web` `passkeys.approveLogin({ requestId })`. The error's new `reason` is `'policy'` for the
  passkey-only policy, as before.
- The guard switches a waiting offline QR to `passkey_required` when its push moved to a passkey, and an
  offline code TouchQue refuses for that reason answers `passkey_required` instead of `blocked`.
- An approval the user took back on the phone answers the guard with `expired` / `revoked`.

## [3.3.0] — 2026-10-12

### Changed (behaviour)
- **`withTouchQue` (Next.js / Fetch) no longer trusts `X-Forwarded-For` by default.** It used to send the
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
  approval, once. Users without a linked phone are unchanged. The TouchQue API enforces this too:
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
  was fraud (chargeback, account takeover, social engineering). TouchQue's risk engine uses it as
  its strongest training signal and it is kept in your audit log; the request's status does not
  change. Idempotent (`alreadyReported: true` on a repeat).
- `verifyApprovalProof` is now checked against the cross-SDK golden vectors
  (`fixtures/approval-proof-vectors.json`) shared with the Python, PHP and Go SDKs.

## [3.1.0] — 2026-09-30

### Security
- **A phone-side reject kills the offline QR.** `tq.offline.challenge({ requestId })` and
  `verifyTotp({ requestId })` tie the QR / time-based code to the push it follows. Once the phone REJECTS the push,
  no new QR is issued for that sign-in (`409 request_rejected`) and no code — QR or time-based — finishes it
  (`reason: 'request_rejected'`). `requireTouchQue`, `touchqueRouter` and `tq.start` flows link the QR
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
  same `jti` throws `TouchQueWebhookReplayError` (a subclass of
  `TouchQueWebhookSignatureError`) — answer 200 to it, it is a duplicate.
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
- `TouchQue()` with no arguments reads `TQ_API_KEY` / `TQ_API_SECRET` /
  `TQ_API_URL` from the environment.
- `tq.start` / `tq.check` / `tq.complete` — the headless step-up flow: start
  an approval, get back a JSON-safe `Step` (the matching number, the
  enrollment QR, or a `blocked`/`frozen`/`rate_limited` refusal) to render in
  your own UI, and complete an approved request exactly once
  (`POST /login/:id/consume`, atomic).
- `requireTouchQue('ACTION', options?)` — new single-argument signature; the
  client defaults to one built from the environment. The old
  `requireTouchQue(tq, action, options)` signature still works.
- `withTouchQue` — the same guard for Next.js route handlers / any Fetch API framework.
- `tq.actions.define` / `tq.actions.list` — define action types from code
  instead of the Dashboard; never re-enables a type an admin disabled.
- `retryAfter` on `TouchQueAPIError`.

### Changed
- **Breaking:** default `baseUrl` is `https://api.touchque.com` (the
  previous default, `api-authenticator.touchque.com`, had no DNS record and
  was unreachable).
- **Breaking:** the matching number for number-matching is now available
  **before** approval through `requireTouchQue` and `touchqueRouter`'s
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
- Relay errors from `touchqueRouter` forward TouchQue's machine-readable
  `code` only, never its internal message text.

## [1.9.0] — 2026-09-27

### Added
- Phishing-resistant sign-in with passkeys on your own domain. When the
  workspace requires a passkey for an action (Security Policy), no push is
  sent: `login.request()` returns `requiresPasskey: true`, `login.verify()`
  throws the new `TouchQuePasskeyRequiredError` (with `requestId`) instead of
  polling, and `touchqueRouter` answers `409 PASSKEY_REQUIRED`.
- `assurance: { phishingResistant, method }` on `LoginStatusResponse` and on
  SUCCESS `WebhookPayload` (`ApprovalAssurance` type). Only passkeys are
  phishing-resistant.

### Changed
- With `getLoginUser`, a passkey approval for a different user opens no
  session (`401 verification_failed`).
- TouchQue now requires user verification (PIN / biometric) for passkey
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
  `externalUsername` sent by the browser. It now uses the user TouchQue reports
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
  longer readable by a QR or JWT decoder. Requires TouchQue API with offline
  sign v2 (deployed) and the current TouchQue app.

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
- This is a MAC-based scheme: only TouchQue can verify a code, so unlike
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
  require trusting TouchQue: it shows the enrolled device signed these
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
- `getDetails(req)` option on `requireTouchQue` and `touchqueRouter`, and
  `getContext(...args)` on `tq.protect()` (returns `clientIp`, `userAgent`,
  `details`).

### Changed
- `requireTouchQue` now forwards `req.ip` and the `User-Agent` header as
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
  Express relay") or the reference `demo-company/server.js` — ~95 lines of
  generic glue code, identical for any partner apart from how they resolve
  the signed-in user. `app.use('/touchque', touchqueRouter(tq, {
  getUserId, onAuthenticated }))` replaces all of it. `requireTouchQue`'s
  existing error-class-to-HTTP-status mapping is reused unchanged.
- `GenerateSecretResponse`/`ResetSecretResponse` types now include the
  `qrCodeDataUrl` field the API already returned (a ready-to-render
  `data:image/png;base64,...` QR code) — previously untyped, so TypeScript
  users lost autocomplete on the one field enrollment actually needs.

## [1.3.1] — 2026-09-16

### Added
- New `TouchQueNetworkError` class: thrown when a request never reached
  TouchQue at all (connection refused, DNS failure, client-side timeout).
  Previously these were indistinguishable from a real TouchQue 500
  (`HttpClient.handleError` always fell back to `TouchQueAPIError(500, {})`
  when there was no HTTP response), which made it impossible for callers
  to build a sane retry policy. `TouchQueNetworkError` is generally safe
  to retry; `TouchQueAPIError` often is not.

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
  single consumer. Product scoping for other TouchQue products is expressed by the package
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
  TouchQue Authenticator (2FA/MFA) product specifically, not TouchQue as a
  whole (TouchQue's other products have their own separately-named SDKs).

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
