// src/index.ts
// Touchque Node.js SDK
//
//   // .env: TQ_API_KEY=tq_…  TQ_API_SECRET=…
//   const { requireTouchque } = require('@touchque/node');
//   app.post('/transfer', requireTouchque('SEND_MONEY'), (req, res) => { … });
//
// The guard answers 202 { touchque: step, token } until the user approves on
// their phone; your page shows the step (matching number, first-time QR) in
// its own design and sends the request again with the token. See README.

import { HttpClient } from './core/HttpClient';
import { Auth } from './resources/Auth';
import { Login } from './resources/Login';
import { Webhook } from './resources/Webhook';
import { WebAuthn } from './resources/WebAuthn';
import { Offline } from './resources/Offline';
import { Actions } from './resources/Actions';
import { ActionTypes } from './resources/ActionTypes';
import { Risk } from './resources/Risk';
import { Recovery } from './resources/Recovery';
import { Assist } from './resources/Assist';
import { Agents } from './resources/Agents';
import { Identity } from './resources/Identity';
import { Mobile } from './resources/Mobile';
import { QrPairings } from './resources/QrPairings';
import { DeviceRisk } from './resources/DeviceRisk';
import { SafeGuard } from './resources/SafeGuard';
import { TouchqueConfig } from './types';
import { TouchqueConfigError } from './errors';
import { registerInternals } from './internal';
import { start, check, complete, Step, StartOptions, Approval, CompleteExpectations } from './steps';

// Export everything developers might need
export * from './types';
export * from './errors';
export * from './resources/Auth';
export * from './resources/Login';
export * from './resources/Webhook';
export * from './resources/WebAuthn';
export * from './resources/Offline';
export * from './resources/Actions';
export * from './resources/ActionTypes';
export * from './resources/Risk';
export * from './resources/Recovery';
export * from './resources/Assist';
export * from './resources/Agents';
export * from './resources/Identity';
export * from './resources/Mobile';
export * from './resources/QrPairings';
export * from './resources/DeviceRisk';
export * from './resources/SafeGuard';
export * from './safeGuard';
export * from './agent';
// An agent's tool calls approved on the person's phone, in any agent framework.
export * from './agentFrameworks';
export * from './orgAgent';
export * from './mcpAuth';
export * from './crossAppAccess';
export * from './securityEvents';
export * from './agentCard';
export * from './approvalToken';
export type { Step, StepState, StartOptions, Approval, CompleteExpectations } from './steps';

export const DEFAULT_BASE_URL = 'https://api.touchque.com';

export class Touchque {
  public readonly auth: Auth;
  public readonly login: Login;
  /** Webhook signature verification */
  public readonly webhook: Webhook;
  /** WebAuthn/FIDO2 (passkey) registration and login approval */
  public readonly webauthn: WebAuthn;
  /** Offline Sign — QR challenge / typed code approvals that work with the phone offline */
  public readonly offline: Offline;
  /** Action types: what users approve (LOGIN, SEND_MONEY…). Was `actions` before 4.0. */
  public readonly actionTypes: ActionTypes;
  /** Touchque Actions: your own code in the approval pipeline (deploy, test, dry run, logs). */
  public readonly actions: Actions;
  /** Silent sign-ins: should this sign-in ask the phone, and which browsers Touchque knows */
  public readonly risk: Risk;
  /** Never Locked Out: move a user whose phone is gone to a new phone, with colleagues vouching */
  public readonly recovery: Recovery;
  /** Help desk: IT working on a person's account in the open, and checks on their phone before sensitive actions */
  public readonly assist: Assist;
  /** AI agents as identities of their own: register (public key), suspend, revoke, kill switch. The agent itself uses TouchqueAgent. */
  public readonly agents: Agents;
  /** Touchque Login: your customers' accounts, roles, organizations, apps, connections (Management API). */
  public readonly identity: Identity;
  /** Mobile SDK: your own iOS/Android app approves for your users (enrollment tokens, devices, settings). */
  public readonly mobile: Mobile;
  /** Pairing a browser by QR code: the phone that scans it is the one asked to approve. */
  public readonly qrPairings: QrPairings;
  /** Device risk: the device on your sign-up, reset, sign-in or approval page (a paid add-on). */
  public readonly deviceRisk: DeviceRisk;
  /** Safe Guard: Safe transactions approved on the approver's phone, for TouchqueSafeGuard. */
  public readonly safeGuard: SafeGuard;

  /**
   * @param config - Optional. Falls back to the environment:
   *   TQ_API_KEY, TQ_API_SECRET, TQ_API_URL (default https://api.touchque.com).
   *
   * @example
   * const tq = new Touchque();                       // from the environment
   * const tq = new Touchque({ apiKey, apiSecret });  // explicit
   */
  constructor(config: Partial<TouchqueConfig> = {}) {
    const env = typeof process !== 'undefined' ? process.env : {};
    const resolved: TouchqueConfig = {
      apiKey: config.apiKey ?? env.TQ_API_KEY ?? '',
      apiSecret: config.apiSecret ?? env.TQ_API_SECRET ?? '',
      baseUrl: config.baseUrl ?? env.TQ_API_URL ?? DEFAULT_BASE_URL,
      timeout: config.timeout,
      logger: config.logger,
      debug: config.debug,
    };
    if (!resolved.apiKey || !resolved.apiSecret) {
      throw new TouchqueConfigError('Set TQ_API_KEY and TQ_API_SECRET (or pass { apiKey, apiSecret }).');
    }
    const http = new HttpClient(resolved);

    this.auth = new Auth(http);
    this.login = new Login(http);
    this.webhook = new Webhook(resolved.apiSecret);
    this.webauthn = new WebAuthn(http);
    this.offline = new Offline(http);
    this.actionTypes = new ActionTypes(http);
    this.actions = new Actions(http);
    this.risk = new Risk(http);
    this.recovery = new Recovery(http);
    this.assist = new Assist(http);
    this.agents = new Agents(http);
    this.identity = new Identity(http);
    this.mobile = new Mobile(http);
    this.qrPairings = new QrPairings(http);
    this.deviceRisk = new DeviceRisk(http);
    this.safeGuard = new SafeGuard(http);
    registerInternals(this, { apiSecret: resolved.apiSecret, resources: { http, auth: this.auth, login: this.login, offline: this.offline, risk: this.risk } });
  }

  /**
   * Starts an approval and returns immediately — show the step in your UI.
   * `waiting` + `number`: show the number, the user picks it on the phone.
   * `enroll`: show `enroll.qrCodeDataUrl` so the user links the Touchque app first.
   *
   * @example
   * const step = await tq.start('SEND_MONEY', { user: 'jane@acme.com', details: { Amount: '250 EUR' } });
   */
  start(action: string, options: StartOptions): Promise<Step> {
    return start({ http: httpOf(this), auth: this.auth, login: this.login, offline: this.offline }, action, options);
  }

  /** Where a started approval is now: waiting, approved, rejected, expired… */
  check(requestId: string): Promise<Step> {
    return check({ http: httpOf(this), auth: this.auth, login: this.login, offline: this.offline }, requestId);
  }

  /**
   * Uses an approved request exactly once, after checking it is for this user,
   * action and transaction. Call it right before doing the protected thing.
   */
  complete(requestId: string, expect: CompleteExpectations): Promise<Approval> {
    return complete({ http: httpOf(this), auth: this.auth, login: this.login, offline: this.offline }, requestId, expect);
  }

  /**
   * Wrap and protect any async function with Touchque 2FA.
   * 
   * @param fn The function to protect
   * @param options Configuration for extracting the user identity and 2FA type
   * @returns A new function that requires 2FA approval before executing the original function
   * 
   * @example
   * const secureWithdraw = tq.protect(processWithdraw, {
   *   type: 'WITHDRAW',
   *   getUserIdentifier: (username, amount) => username,
   *   // Number matching: show challengeCode to the user now; the phone asks for it.
   *   onChallenge: ({ challengeCode }) => { if (challengeCode) notifyUser(`Pick ${challengeCode} on your phone`); },
   * });
   * 
   * await secureWithdraw("user@company.com", 500); // Prompts 2FA automatically
   */
  public protect<TArgs extends any[], TReturn>(
    fn: (...args: TArgs) => Promise<TReturn> | TReturn,
    options: import('./types').ProtectOptions<TArgs>
  ): (...args: TArgs) => Promise<TReturn> {
    return async (...args: TArgs): Promise<TReturn> => {
      const externalUsername = options.getUserIdentifier(...args);
      const referenceId = options.getReferenceId ? options.getReferenceId(...args) : undefined;
      const context = options.getContext ? options.getContext(...args) : undefined;

      // Send 2FA request and wait for user approval
      await this.login.verify({
        externalUsername,
        type: options.type,
        referenceId,
        ...context,
        timeout: options.timeout,
        pollInterval: options.pollInterval,
        onChallenge: options.onChallenge,
      });
      
      // If we reach here, it was approved. Call the original function.
      return fn(...args);
    };
  }
}

// ─── Re-export everything for convenience ───

export { Auth } from './resources/Auth';
export { Login } from './resources/Login';
export { Webhook } from './resources/Webhook';
export { verifyApprovalProof, detailsDigest } from './approvalProof';
export type { ApprovalProof, VerifyApprovalProofOptions } from './approvalProof';

export {
  TouchqueError,
  TouchqueAPIError,
  TouchqueNetworkError,
  TouchqueTimeoutError,
  TouchqueRejectedError,
  TouchqueWebhookSignatureError,
  TouchqueConfigError,
} from './errors';

export { requireTouchque, TouchqueMiddlewareOptions } from './middleware/express';
export { withTouchque, WithTouchqueOptions, forwardedFor, ipFromVercel, ipFromCloudflare } from './next';
export { createTouchqueLogin } from './nextLogin';
export type { NextSession, TouchqueNextOptions, CookieSource } from './nextLogin';
export { runGuard, GUARD_HEADERS, GuardInput, GuardResult, GuardBody, GuardRefusal, SilentSignInOptions } from './guard';
export { signGuardToken, verifyGuardToken, normalizeDetails } from './steps';
export { touchqueRouter, TouchqueRouterOptions } from './router';
// The same relay routes for Next.js (App Router) and other Fetch-API runtimes: Request in, Response out.
export { touchqueRelay } from './relay';
export type { TouchqueRelayOptions } from './relay';
// Touchque Login (hosted sign-in): OpenID Connect client, cookie sessions, Express routes
export * from './hostedLogin';
export { MyAccount, MyAccountError } from './myAccount';
export type { MyAccountConfig, MyAccountProfile, MyAccountMethods, MyAccountProfileChanges } from './myAccount';
export { seal as sealSession, unseal as unsealSession, safeReturnTo } from './hostedLoginSession';
export { hostedLoginRoutes, requireSignIn, requireAccessToken } from './middleware/hostedLoginExpress';
export type { HostedLoginSession, HostedLoginRoutesOptions, RequireSignInOptions } from './middleware/hostedLoginExpress';
export type { RateLimitOptions } from './rateLimiter';
// The relay's rate limiter, for withTouchque and your own relays.
export { FixedWindowLimiter } from './rateLimiter';

export { newCodeReplyKey, openCodeReply } from './codeReply';
export type { CodeReplyKey } from './codeReply';
export type {
  TouchqueConfig,
  TouchqueLogger,
  LoginReplyRequest,
  GenerateSecretOptions,
  GenerateSecretResponse,
  ResetSecretOptions,
  ResetSecretResponse,
  LoginType,
  LoginRequestOptions,
  LoginRequestResponse,
  LoginStatus,
  LoginStatusResponse,
  WaitForApprovalOptions,
  WaitForApprovalResult,
  VerifyOptions,
  VerifyChallenge,
  VerifyWebhookOptions,
  WebhookPayload,
  ProtectOptions,
  RiskCheckOptions,
  RiskCheckResult,
  RiskReason,
  RiskBrowser,
  RiskBrowsersOptions,
  RiskBrowsersResponse,
  ForgetBrowsersOptions,
  ForgetBrowsersResponse,
  RecoveryStatus,
  RecoveryCase,
  RecoveryVoucherEligibility,
  RecoveryVouchersResponse,
  SetRecoveryVouchersOptions,
  StartRecoveryOptions,
  RecoveryVoucherState,
  RecoveryReceipt,
  RecoveryStarted,
  VetoRecoveryOptions,
  ListRecoveriesOptions,
} from './types';

import { resources as internalResources } from './internal';
function httpOf(client: Touchque): HttpClient {
  return internalResources(client).http;
}

let defaultClient: Touchque | undefined;
/** The client built from TQ_API_KEY / TQ_API_SECRET, created on first use. */
export function getDefaultClient(): Touchque {
  if (!defaultClient) defaultClient = new Touchque();
  return defaultClient;
}
