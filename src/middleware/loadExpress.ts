// src/middleware/loadExpress.ts
// express is an optional peer dependency, and the Express helpers ship in the
// main entry. So the main entry never loads express itself: a Next.js app, a
// Fastify app or a plain script imports @touchque/node without it, and
// express is required only when touchqueRouter() or hostedLoginRoutes() is
// called, resolved from this package's own location.

import { createRequire } from 'module';
import type { Router } from 'express';
import { TouchqueConfigError } from '../errors';

function requireHere(): NodeRequire {
  // The CommonJS build has __filename; the ES module build has import.meta.url
  // (the source is type-checked as CommonJS, which has no import.meta).
  // @ts-expect-error TS1343: import.meta is read only in the ES module build.
  return createRequire(typeof __filename === 'string' ? __filename : import.meta.url);
}

/** A new express Router, or a clear error when express is not installed. */
export function expressRouter(helper: string): Router {
  let express: { Router: () => Router };
  try {
    express = requireHere()('express');
  } catch {
    throw new TouchqueConfigError(`${helper}() needs express: npm install express`);
  }
  return express.Router();
}
