# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
