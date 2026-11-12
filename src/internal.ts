// src/internal.ts
// Per-client internals the guards need, kept off the public Touchque object
// so the API secret is never enumerable / serialized with it.

import type { HttpClient, Transport } from './core/HttpClient';
import type { Auth } from './resources/Auth';
import type { Login } from './resources/Login';
import type { Offline } from './resources/Offline';
import type { Risk } from './resources/Risk';

interface Internals {
  apiSecret: string;
  resources: { http: HttpClient; auth: Auth; login: Login; offline: Offline; risk: Risk };
}

const store = new WeakMap<object, Internals>();

export function registerInternals(client: object, internals: Internals): void {
  store.set(client, internals);
}

function get(client: object): Internals {
  const i = store.get(client);
  if (!i) throw new TypeError('Not a Touchque client instance');
  return i;
}

export const guardSecret = (client: object): string => get(client).apiSecret;
export const resources = (client: object): Internals['resources'] => get(client).resources;

/**
 * What `@touchque/node/testing` reaches in the main entry at run time, as
 * `Touchque[TESTING_HOOKS]`. It is a separate entry that loads the main one
 * instead of bundling a copy, so both share one Touchque class, its errors and
 * one default client. Not part of the API.
 */
export interface TestingHooks {
  /** `client`'s API calls go to `transport`, in memory, instead of over the network. */
  useTransport(client: object, transport: Transport): void;
}

export const TESTING_HOOKS = Symbol.for('@touchque/node/testing');

const NO_LOG = { warn: () => {}, error: () => {} };
/** The client's log (silent unless the integrator passed a logger or debug), or a silent one for anything else, or no client. */
export const logOf = (client: object | null | undefined): { warn(message: string): void; error(message: string): void } =>
  (client ? store.get(client)?.resources.http.log : undefined) ?? NO_LOG;
