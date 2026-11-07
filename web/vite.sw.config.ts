import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';

// Second build pass (package.json "build", after vite.config.ts): the Service Worker of the
// end-to-end encrypted downloads (src/e2e-sw/sw.ts) bundled with the shared/e2e modules it uses
// into one classic script, dist/e2e-sw.js. The name is fixed (the page registers /e2e-sw.js with
// the scope /e2e/, which must sit below the script) and the file is a root file of the build,
// served by internal/httpserver/webui.go with the public CSP and revalidated on every use. A
// classic script (IIFE), not a module: module Service Workers are not supported by every browser.
// scripts/check-dist.mjs checks it with the other files.
const here = (path: string): string => fileURLToPath(new URL(path, import.meta.url));

export default defineConfig({
  publicDir: false,
  build: {
    outDir: here('dist'),
    emptyOutDir: false,
    target: 'es2022',
    sourcemap: false,
    copyPublicDir: false,
    lib: {
      entry: here('src/e2e-sw/sw.ts'),
      formats: ['iife'],
      name: 'TransTeiraE2EServiceWorker',
      fileName: () => 'e2e-sw.js',
    },
  },
});
