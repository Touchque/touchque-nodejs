// src/resources/ActionTypes.ts
// Action types ("LOGIN", "SEND_MONEY", …) — what a user is asked to approve.
// Define them from code at start-up instead of clicking them into the Dashboard.
// (Before 4.0 this was `tq.actions`; `tq.actions` is Touchque Actions now.)

import { HttpClient } from '../core/HttpClient';

/** The Second Thought questions an action type can ask (at most two). */
export const SECOND_THOUGHT_QUESTIONS = [
  'someone_guiding',
  'safe_account',
  'remote_access',
  'asked_for_code',
  'support_call',
  'met_online',
  'promised_return',
  'know_recipient',
  'sim_in_hand',
] as const;

export type SecondThoughtQuestion = (typeof SECOND_THOUGHT_QUESTIONS)[number];

/**
 * Second Thought: short yes/no questions the phone asks before Approve, for
 * actions people get talked into ("Is someone on a call telling you to do
 * this right now?"). A risky answer never refuses: the approval comes back
 * `provisional: true`, the user's critical actions wait, and the phone asks
 * "Was this you?" later. Hold the action until it is reconfirmed.
 */
export interface SecondThought {
  questions: SecondThoughtQuestion[];
  /** Language on the phone (default `'tr'`). */
  locale?: 'tr' | 'en';
}

export interface ActionType {
  id: string;
  type: string;
  name: string;
  description: string;
  /** Critical actions always use number matching and never accept recovery / offline time-based codes. */
  critical: boolean;
  active: boolean;
  secondThought?: SecondThought | null;
}

export interface DefineActionOptions {
  /** Shown on the phone and in the Dashboard (default: the slug). */
  name?: string;
  description?: string;
  /** Leave undefined to keep what the Dashboard has. */
  critical?: boolean;
  /** Questions the phone asks before Approve; `null` turns them off, undefined keeps what the Dashboard has. */
  secondThought?: SecondThought | null;
}

export class ActionTypes {
  constructor(private readonly http: HttpClient) {}

  /**
   * Creates the action type, or updates its name, description, critical flag
   * and Second Thought questions.
   * Safe to call on every start-up: it never re-enables a type an admin disabled.
   *
   * @example
   * await tq.actionTypes.define('SEND_MONEY', { name: 'Send money', critical: true });
   */
  async define(type: string, options: DefineActionOptions = {}): Promise<ActionType> {
    return this.http.post<ActionType>('/action-types', {
      type,
      name: options.name || type,
      ...(options.description !== undefined && { description: options.description }),
      ...(options.critical !== undefined && { critical: options.critical }),
      ...(options.secondThought !== undefined && { secondThought: options.secondThought }),
    });
  }

  async list(): Promise<ActionType[]> {
    return this.http.get<ActionType[]>('/action-types');
  }
}
