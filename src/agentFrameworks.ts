// src/agentFrameworks.ts
// A person approves an AI agent's tool call on their phone before it runs,
// in whichever agent framework the agent is built with. One rule, a policy,
// says who approves (user), as which action type, and what the phone shows
// (authorizationDetails drawn from the tool's arguments); TouchQue draws the
// rows, the person types the number the conversation shows and confirms with
// Face ID, and the call runs only once they approved. The approval token
// (single use, bound to exactly what was approved) is there for the service
// that executes: currentApproval() inside the tool, or the MCP request's _meta.
//
//   const pay = withTouchQueApproval(async ({ iban, amount }) => bank.pay(iban, amount, currentApproval()!.approvalToken), {
//     agent, user: 'ada@acme.com', type: 'PAY_INVOICE',
//     details: ({ iban, amount }) => [{ type: 'payment_initiation', instructedAmount: { currency: 'TRY', amount }, creditorAccount: { iban } }],
//     onChallenge: (s) => reply(`Type ${s.challengeCode} in the TouchQue app.`),
//   });
//
// The wrapped function keeps its arguments, so it drops into LangChain's
// tool(), the Vercel AI SDK's execute, LlamaIndex's FunctionTool and the
// OpenAI Agents SDK's tool({ execute }) unchanged. For frameworks with their
// own approval step: approveInterruptionsWithTouchQue (OpenAI Agents SDK),
// touchqueCanUseTool and touchquePreToolUseHook (Claude Agent SDK),
// guardMcpClient (any MCP client).

import { AsyncLocalStorage } from 'async_hooks';
import type { AuthorizationDetail } from './approvalToken';
import type { AgentApprovalParams, AgentApprovalState, TouchQueAgent } from './agent';
import { TouchQueApprovalError, TouchQueTimeoutError } from './errors';

type Maybe<T, A> = T | ((args: A, toolName: string) => T);

export interface ApprovalPolicy<A = any> {
  agent: TouchQueAgent;
  /** The person the agent acts for: their phone approves. */
  user: Maybe<string, A>;
  /** One of the agent's allowed action types. */
  type: Maybe<string, A>;
  /** What the phone shows, from the tool's arguments (RFC 9396 authorization details). */
  details: (args: A, toolName: string) => AuthorizationDetail[];
  /** The agent's own words, shown as unverified. */
  reason?: Maybe<string | undefined, A>;
  presence?: AgentApprovalParams['presence'];
  locale?: AgentApprovalParams['locale'];
  /** Approve within an active mandate: no push. */
  mandateId?: string;
  /** While the phone waits: show challengeCode in the conversation. */
  onChallenge?: (state: AgentApprovalState, toolName: string) => void | Promise<void>;
  /** How long to wait for the phone (default 5 minutes). */
  timeoutMs?: number;
}

const store = new AsyncLocalStorage<AgentApprovalState>();

/** Inside a tool wrapped by withTouchQueApproval: the approval it runs under (its approvalToken for the service). */
export function currentApproval(): AgentApprovalState | undefined {
  return store.getStore();
}

const pick = <T, A>(v: Maybe<T, A>, args: A, toolName: string): T => (typeof v === 'function' ? (v as (a: A, n: string) => T)(args, toolName) : v);

/**
 * Asks the person's phone and waits: the approved state (with approvalToken),
 * or TouchQueApprovalError (rejected, blocked, expired…) / TouchQueTimeoutError.
 */
export async function requireAgentApproval<A>(policy: ApprovalPolicy<A>, args: A, toolName = 'tool'): Promise<AgentApprovalState> {
  const asked = await policy.agent.requestApproval({
    user: pick(policy.user, args, toolName),
    type: pick(policy.type, args, toolName),
    authorizationDetails: policy.details(args, toolName),
    ...(policy.reason !== undefined && { reason: pick(policy.reason, args, toolName) }),
    ...(policy.presence && { presence: policy.presence }),
    ...(policy.locale && { locale: policy.locale }),
    ...(policy.mandateId && { mandateId: policy.mandateId }),
  });
  if (asked.status === 'approved' && asked.approvalToken) return asked;
  if (asked.challengeCode && policy.onChallenge) await policy.onChallenge(asked, toolName);
  return policy.agent.waitForApproval(asked.approvalId, { timeoutMs: policy.timeoutMs ?? 5 * 60 * 1000 });
}

/** The function runs only after the person approved on the phone; currentApproval() is set while it runs. */
export function withTouchQueApproval<A, R, Rest extends unknown[]>(
  fn: (args: A, ...rest: Rest) => R | Promise<R>,
  policy: ApprovalPolicy<A>,
  toolName = fn.name || 'tool',
): (args: A, ...rest: Rest) => Promise<R> {
  return async (args: A, ...rest: Rest) => {
    const approval = await requireAgentApproval(policy, args, toolName);
    return store.run(approval, () => fn(args, ...rest));
  };
}

const parseArgs = (raw: unknown): any => {
  if (typeof raw !== 'string') return raw ?? {};
  try {
    return JSON.parse(raw);
  } catch {
    return {};
  }
};

/**
 * OpenAI Agents SDK: tools created with needsApproval interrupt the run; this
 * asks the phone for each interruption in `policies` (by tool name) and
 * approves or rejects it on the run state. Returns the state to resume with
 * run(agent, state). Tools without a policy are left for you.
 */
export async function approveInterruptionsWithTouchQue(
  result: { interruptions?: any[]; state: { approve(item: any): void; reject(item: any): void } },
  policies: Record<string, ApprovalPolicy>,
): Promise<typeof result.state> {
  for (const item of result.interruptions || []) {
    const raw = item.rawItem || item.raw_item || {};
    const name = raw.name || item.name;
    const policy = policies[name];
    if (!policy) continue;
    try {
      await requireAgentApproval(policy, parseArgs(raw.arguments ?? item.arguments), name);
      result.state.approve(item);
    } catch (err) {
      if (!(err instanceof TouchQueApprovalError) && !(err instanceof TouchQueTimeoutError)) throw err;
      result.state.reject(item);
    }
  }
  return result.state;
}

/**
 * Claude Agent SDK: a canUseTool callback. Tools with a policy run only after
 * the phone approved (tokenField: put the approval token into the tool's input
 * under that name); tools without one are allowed or, with denyOthers, denied.
 */
export function touchqueCanUseTool(policies: Record<string, ApprovalPolicy>, options: { tokenField?: string; denyOthers?: boolean } = {}) {
  return async (toolName: string, input: Record<string, unknown>): Promise<{ behavior: 'allow'; updatedInput: Record<string, unknown> } | { behavior: 'deny'; message: string }> => {
    const policy = policies[toolName];
    if (!policy) return options.denyOthers ? { behavior: 'deny', message: `${toolName} is not allowed for this agent` } : { behavior: 'allow', updatedInput: input };
    try {
      const approval = await requireAgentApproval(policy, input, toolName);
      return { behavior: 'allow', updatedInput: options.tokenField ? { ...input, [options.tokenField]: approval.approvalToken } : input };
    } catch (err) {
      return { behavior: 'deny', message: `The person did not approve ${toolName} on their phone (${(err as TouchQueApprovalError).status || (err as Error).message})` };
    }
  };
}

/** Claude Agent SDK: the same as a PreToolUse hook (hooks: { PreToolUse: [{ hooks: [touchquePreToolUseHook(policies)] }] }). */
export function touchquePreToolUseHook(policies: Record<string, ApprovalPolicy>) {
  const decide = touchqueCanUseTool(policies);
  return async (input: { tool_name: string; tool_input: Record<string, unknown> }) => {
    if (!policies[input.tool_name]) return {};
    const d = await decide(input.tool_name, input.tool_input);
    return {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: d.behavior === 'allow' ? 'allow' : 'deny',
        permissionDecisionReason: d.behavior === 'allow' ? 'Approved on the person\'s phone (TouchQue)' : d.message,
      },
    };
  };
}

/**
 * Any MCP client (@modelcontextprotocol/sdk Client): the tools in `policies`
 * are called only after the phone approved; the approval token goes to the
 * server in the request's _meta ("touchque/approvalToken").
 */
export function guardMcpClient<C extends { callTool: (params: any, ...rest: any[]) => Promise<any> }>(client: C, policies: Record<string, ApprovalPolicy>): C {
  const callTool = client.callTool.bind(client);
  return new Proxy(client, {
    get(target, prop, receiver) {
      if (prop !== 'callTool') return Reflect.get(target, prop, receiver);
      return async (params: { name: string; arguments?: Record<string, unknown>; _meta?: Record<string, unknown> }, ...rest: any[]) => {
        const policy = policies[params.name];
        if (!policy) return callTool(params, ...rest);
        const approval = await requireAgentApproval(policy, params.arguments || {}, params.name);
        return callTool({ ...params, _meta: { ...(params._meta || {}), 'touchque/approvalToken': approval.approvalToken } }, ...rest);
      };
    },
  });
}
