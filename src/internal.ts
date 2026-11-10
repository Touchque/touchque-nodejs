// src/internal.ts
// Per-client internals the guards need, kept off the public TouchQue object
// so the API secret is never enumerable / serialized with it.

import type { HttpClient } from './core/HttpClient';
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
  if (!i) throw new TypeError('Not a TouchQue client instance');
  return i;
}

export const guardSecret = (client: object): string => get(client).apiSecret;
export const resources = (client: object): Internals['resources'] => get(client).resources;

const NO_LOG = { warn: () => {}, error: () => {} };
/** The client's log (silent unless the integrator passed a logger or debug), or a silent one for anything else. */
export const logOf = (client: object): { warn(message: string): void; error(message: string): void } => store.get(client)?.resources.http.log ?? NO_LOG;
