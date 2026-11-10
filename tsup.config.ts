import { defineConfig } from 'tsup';

export default defineConfig({
  // nextMiddleware runs on the Edge: its own bundle, no Node.js modules.
  entry: ['src/index.ts', 'src/nextMiddleware.ts'],
  format: ['cjs', 'esm'],
  dts: true,
  clean: true,
  esbuildOptions(options, { format }) {
    // middleware/loadExpress.ts reads import.meta.url only in the ES module build.
    if (format === 'cjs') options.logOverride = { ...options.logOverride, 'empty-import-meta': 'silent' };
  },
});
