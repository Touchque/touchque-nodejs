import { defineConfig } from 'tsup';
import type { Plugin } from 'esbuild';

// @touchque/node/testing loads the main entry at run time instead of bundling a
// copy of it (the CommonJS build has no shared chunks), so a FakeTouchque is a
// Touchque that runGuard and the adapters know, with the same error classes and
// the same default client.
const testingLoadsMainEntry: Plugin = {
  name: 'touchque-testing-main-entry',
  setup(build) {
    const main = build.initialOptions.format === 'esm' ? './index.mjs' : './index.js';
    build.onResolve({ filter: /^\.\/index$/ }, (args) =>
      (/[\\/]src[\\/]testing\.ts$/.test(args.importer) ? { path: main, external: true } : undefined));
  },
};

export default defineConfig({
  // nextMiddleware runs on the Edge: its own bundle, no Node.js modules.
  entry: ['src/index.ts', 'src/nextMiddleware.ts', 'src/testing.ts'],
  format: ['cjs', 'esm'],
  dts: true,
  clean: true,
  esbuildPlugins: [testingLoadsMainEntry],
  esbuildOptions(options, { format }) {
    // middleware/loadExpress.ts reads import.meta.url only in the ES module build.
    if (format === 'cjs') options.logOverride = { ...options.logOverride, 'empty-import-meta': 'silent' };
  },
});
