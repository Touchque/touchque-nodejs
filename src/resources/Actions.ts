// src/resources/Actions.ts
// Action types ("LOGIN", "SEND_MONEY", …) — what a user is asked to approve.
// Define them from code at start-up instead of clicking them into the Dashboard.

import { HttpClient } from '../core/HttpClient';

export interface ActionType {
  id: string;
  type: string;
  name: string;
  description: string;
  /** Critical actions always use number matching and never accept recovery / offline time-based codes. */
  critical: boolean;
  active: boolean;
}

export interface DefineActionOptions {
  /** Shown on the phone and in the Dashboard (default: the slug). */
  name?: string;
  description?: string;
  /** Leave undefined to keep what the Dashboard has. */
  critical?: boolean;
}

export class Actions {
  constructor(private readonly http: HttpClient) {}

  /**
   * Creates the action type, or updates its name/description/critical flag.
   * Safe to call on every start-up: it never re-enables a type an admin disabled.
   *
   * @example
   * await tq.actions.define('SEND_MONEY', { name: 'Send money', critical: true });
   */
  async define(type: string, options: DefineActionOptions = {}): Promise<ActionType> {
    return this.http.post<ActionType>('/action-types', {
      type,
      name: options.name || type,
      ...(options.description !== undefined && { description: options.description }),
      ...(options.critical !== undefined && { critical: options.critical }),
    });
  }

  async list(): Promise<ActionType[]> {
    return this.http.get<ActionType[]>('/action-types');
  }
}
