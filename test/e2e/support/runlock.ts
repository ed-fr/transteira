// Run lock of the Playwright process (see scripts/lock.mjs): global-setup.ts takes or joins it,
// global-teardown.ts (which Playwright runs last, in the same process) releases it.
import fs from 'node:fs';
import { LOCK_DIR, LOCK_ENV, readOwner } from '../scripts/lock.mjs';

export { acquireLock } from '../scripts/lock.mjs';

/** Set by global-setup.ts when this Playwright process took the lock itself. */
export const OWNED_LOCK_ENV = 'E2E_LOCK_OWNED';

/** True when this process holds the lock (its own, or the one of `make e2e` it joined). */
export function holdsRunLock(): boolean {
  const token = process.env[OWNED_LOCK_ENV] ?? process.env[LOCK_ENV];
  return token !== undefined && readOwner()?.token === token;
}

/** Releases the lock if this process took it itself (a joined lock stays with its owner). */
export function releaseOwnedRunLock(): void {
  const token = process.env[OWNED_LOCK_ENV];
  if (!token) return;
  delete process.env[OWNED_LOCK_ENV];
  if (readOwner()?.token === token) fs.rmSync(LOCK_DIR, { recursive: true, force: true });
}
