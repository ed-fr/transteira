// Fallback teardown: the teardown returned by global-setup.ts normally stops everything; this
// one only removes what a run interrupted before that point may have left (server process by
// PID, Caddy container, temporary root). It is idempotent. Playwright runs it last, after the
// teardown returned by the global setup: it then releases the run lock (scripts/lock.mjs).
//
// Nothing is touched unless this process holds the run lock: a setup that failed while waiting
// for the lock must not stop the server or the Caddy of the run that holds it.
import fs from 'node:fs';
import { stopCaddy } from './support/caddy';
import { RM_TREE, RUNTIME_FILE } from './support/env';
import { holdsRunLock, releaseOwnedRunLock } from './support/runlock';
import { killStale } from './support/server';
import type { Runtime } from './global-setup';

export default async function globalTeardown(): Promise<void> {
  if (!holdsRunLock()) return;
  try {
    if (!fs.existsSync(RUNTIME_FILE)) return;
    const runtime = JSON.parse(fs.readFileSync(RUNTIME_FILE, 'utf8')) as Runtime;
    killStale(runtime.serverPid);
    stopCaddy();
    if (runtime.tempRoot) fs.rmSync(runtime.tempRoot, RM_TREE);
    fs.rmSync(RUNTIME_FILE, { force: true });
  } finally {
    releaseOwnedRunLock();
  }
}
