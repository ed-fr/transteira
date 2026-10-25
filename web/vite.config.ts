import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { defineConfig, type Plugin } from 'vite';

// Two static applications built into web/dist and embedded in the Go binary (web/embed.go):
//   dist/public/index.html  tenant hosts (deposit, download, invitations, legal pages)
//   dist/admin/index.html   admin host, under /admin/
//   dist/assets/*-[hash].*  shared fingerprinted assets (served immutable)
// The served CSP is strict (internal/httpserver/webui.go): no inline script or style, no data:
// URI in the public app, nothing from another origin. scripts/check-dist.mjs enforces it on
// the output.
const here = (path: string): string => fileURLToPath(new URL(path, import.meta.url));
const docsUser = here('../docs/user');

/**
 * Dev server only: regenerates the integrated help (scripts/build-help.mjs) when a guide or the
 * screenshots manifest of docs/user changes, so that the help follows the guides being edited.
 * Errors are printed by the script and the previous modules are kept.
 */
function helpWatch(): Plugin {
  const posix = (path: string): string => path.replaceAll('\\', '/');
  const root = `${posix(docsUser)}/`;
  return {
    name: 'transteira-help-watch',
    apply: 'serve',
    configureServer(server) {
      let timer: ReturnType<typeof setTimeout> | undefined;
      let running = false;
      let again = false;
      const run = (): void => {
        if (running) {
          again = true;
          return;
        }
        running = true;
        const child = spawn(process.execPath, [here('scripts/build-help.mjs')], { stdio: 'inherit' });
        child.on('close', () => {
          running = false;
          if (again) {
            again = false;
            run();
          }
        });
      };
      const onChange = (file: string): void => {
        const path = posix(file);
        if (path.startsWith(root) && /\.(md|json)$/.test(path)) {
          clearTimeout(timer);
          timer = setTimeout(run, 150);
        }
      };
      server.watcher.add(docsUser);
      server.watcher.on('add', onChange);
      server.watcher.on('change', onChange);
      server.watcher.on('unlink', onChange);
    },
  };
}

export default defineConfig({
  root: here('src'),
  base: '/',
  publicDir: here('static'),
  plugins: [svelte({ configFile: here('svelte.config.js') }), helpWatch()],
  build: {
    outDir: here('dist'),
    emptyOutDir: true,
    assetsDir: 'assets',
    // Never inline assets as data: URIs (img-src 'self', font-src none).
    assetsInlineLimit: 0,
    // The polyfill is an inline script; ES2022 browsers support modulepreload natively.
    modulePreload: { polyfill: false },
    target: 'es2022',
    sourcemap: false,
    cssCodeSplit: true,
    rolldownOptions: {
      output: {
        // Shared chunks get a neutral name (otherwise named after an arbitrary module).
        chunkFileNames: 'assets/chunk-[hash].js',
        assetFileNames: (asset) =>
          asset.names.some((name) => name.endsWith('.css') && !/^(public|admin)\.css$/.test(name))
            ? 'assets/chunk-[hash][extname]'
            : 'assets/[name]-[hash][extname]',
      },
      input: {
        public: here('src/public/index.html'),
        admin: here('src/admin/index.html'),
      },
    },
  },
  server: {
    // Dev loop: Caddy (web/dev/Caddyfile) proxies /api to the Go server and the rest here.
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    fs: {
      // The generated help imports the screenshots of docs/user/screenshots, outside web/.
      allow: [here('.'), here('../docs/user/screenshots')],
    },
  },
});
