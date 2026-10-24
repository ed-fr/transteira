// Global setup of the end-to-end run (one per engine): fake clamd, server, Caddy, seed data and
// the admin storage states. Returns the teardown that stops everything; global-teardown.ts is a
// fallback for what a crashed run may have left.
import { chromium, type FullConfig } from '@playwright/test';
import fs from 'node:fs';
import { saveStorageStates } from './support/auth';
import { startCaddy, stopCaddy } from './support/caddy';
import { E2E_DB, RM_TREE, RUN_DIR, RUNTIME_FILE, newTempRoot } from './support/env';
import { startFakeClamd } from './support/fakeclamd';
import { resetE2EDatabase } from './support/postgres';
import { OWNED_LOCK_ENV, acquireLock } from './support/runlock';
import { seed } from './support/seed';
import { killStale, startServer } from './support/server';
import { saveState } from './support/state';

/** What the fallback teardown needs to clean up. */
export interface Runtime {
  serverPid?: number;
  tempRoot?: string;
}

function readRuntime(): Runtime {
  try {
    return JSON.parse(fs.readFileSync(RUNTIME_FILE, 'utf8')) as Runtime;
  } catch {
    return {};
  }
}

function log(msg: string): void {
  console.log(`[e2e ${E2E_DB}] ${msg}`);
}

export default async function globalSetup(_config: FullConfig): Promise<() => Promise<void>> {
  const started = Date.now();
  // One run at a time on the machine (shared .run/, Caddy, e2e database): joins the lock of
  // `make e2e` (E2E_LOCK_TOKEN) or waits for it when Playwright was started directly. Nothing of
  // an earlier run is touched before the lock is held, so a live run is never disturbed.
  const lock = await acquireLock({ purpose: `playwright (${E2E_DB})`, log });
  if (!lock.joined) process.env[OWNED_LOCK_ENV] = lock.token;
  // Leftovers of a crashed earlier run.
  const stale = readRuntime();
  killStale(stale.serverPid);
  if (stale.tempRoot) fs.rmSync(stale.tempRoot, RM_TREE);
  fs.rmSync(RUN_DIR, RM_TREE);
  fs.mkdirSync(RUN_DIR, { recursive: true });

  if (E2E_DB === 'postgres') {
    resetE2EDatabase();
    log('PostgreSQL database transteira_e2e reset');
  }

  const root = newTempRoot();
  const runtime: Runtime = { tempRoot: root };
  fs.writeFileSync(RUNTIME_FILE, JSON.stringify(runtime));

  const clamd = await startFakeClamd();
  let server: Awaited<ReturnType<typeof startServer>> | undefined;
  const teardown = async (): Promise<void> => {
    await server?.stop();
    await clamd.close();
    stopCaddy();
    fs.rmSync(root, RM_TREE);
    fs.rmSync(RUNTIME_FILE, { force: true });
    log('environment stopped');
  };

  try {
    server = await startServer({ root, clamavAddr: clamd.address });
    runtime.serverPid = server.pid;
    fs.writeFileSync(RUNTIME_FILE, JSON.stringify(runtime));
    log(`server up on port ${server.port}`);
    await startCaddy(server.port);
    log('Caddy up');

    const state = await seed(server.port, server.setupToken, clamd.address, E2E_DB);
    saveState(state);
    log('seed done');

    const browser = await chromium.launch();
    try {
      await saveStorageStates(browser, state);
    } finally {
      await browser.close();
    }
    log(`storage states saved; setup took ${((Date.now() - started) / 1000).toFixed(1)} s`);
  } catch (e) {
    await teardown();
    throw e;
  }
  return teardown;
}
