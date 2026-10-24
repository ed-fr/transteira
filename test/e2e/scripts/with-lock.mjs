// Runs a command while holding the machine-wide e2e run lock (lock.mjs), then releases it:
//
//   node test/e2e/scripts/with-lock.mjs <command> [args...]
//
// Used by `make e2e` and `make screenshots`, so that the build (web/dist, bin/transteira) and
// the Playwright runs of both engines happen under one lock: a second run started meanwhile
// waits instead of rebuilding the binary under the first one or reusing its Caddy and .run/.
// The command gets the lock token in E2E_LOCK_TOKEN; global-setup.ts then joins the lock
// instead of waiting for itself. The command runs without a shell (cross-platform).
import { spawn } from 'node:child_process';
import { LOCK_ENV, acquireLock } from './lock.mjs';

const [command, ...args] = process.argv.slice(2);
if (!command) {
  console.error('usage: node with-lock.mjs <command> [args...]');
  process.exit(2);
}

const lock = await acquireLock({ purpose: [command, ...args].join(' ').slice(0, 200) });
process.on('exit', () => lock.release());

const child = spawn(command, args, {
  stdio: 'inherit',
  env: { ...process.env, [LOCK_ENV]: lock.token },
});

// Ctrl+C reaches the whole process group (console on Windows): ignore it here and let the child
// stop by itself (Playwright runs its teardown); the lock is released when the child exits.
process.on('SIGINT', () => {});
// A termination aimed at this process only is passed on to the child.
process.on('SIGTERM', () => {
  if (child.exitCode === null) child.kill('SIGTERM');
});

child.on('error', (e) => {
  console.error(`with-lock: cannot start ${command}: ${e.message}`);
  lock.release();
  process.exit(127);
});
child.on('exit', (code, signal) => {
  lock.release();
  process.exit(code ?? (signal ? 1 : 0));
});
