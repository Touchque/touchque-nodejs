// src/internal.ts
// Per-client internals the guards need, kept off the public TouchQue object
// so the API secret is never enumerable / serialized with it.

import type { HttpClient } from './core/HttpClient';
import type { Auth } from './resources/Auth';
import type { Login } from './resources/Login';
import type { Offline } from './resources/Offline';

interface Internals {
  apiSecret: string;
  resources: { http: HttpClient; auth: Auth; login: Login; offline: Offline };
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
