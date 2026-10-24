// Machine-wide run lock of the end-to-end suite: only one run at a time may use test/e2e/.run/,
// the Caddy container (port 443) and the e2e PostgreSQL database, and only one may rebuild
// web/dist and bin/transteira for a run.
//
// The lock is a directory (test/e2e/.run.lock) created with an atomic mkdir; owner.json inside
// records the owner process, its start time and a random token. A waiting process polls until
// the lock is free; it steals the lock only when the owner process is gone or the lock is older
// than the maximum age (a PID reused by an unrelated process cannot hold the lock forever).
// Stealing renames the directory first (atomic), so two waiters never both take a stale lock.
//
// Holders:
//   - scripts/with-lock.mjs (make e2e, make screenshots) takes the lock before the build and
//     passes its token to the children in E2E_LOCK_TOKEN;
//   - global-setup.ts takes it when Playwright is started directly (npx playwright test) and
//     joins the lock of its parent when E2E_LOCK_TOKEN matches the owner.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/** Lock directory (gitignored). */
export const LOCK_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '.run.lock');
const OWNER_FILE = 'owner.json';
/** Environment variable carrying the token of the lock held by a parent process. */
export const LOCK_ENV = 'E2E_LOCK_TOKEN';

const minutes = (name, fallback) => {
  const v = Number(process.env[name]);
  return (Number.isFinite(v) && v > 0 ? v : fallback) * 60_000;
};

/** True when a process with this PID exists (EPERM: it exists but belongs to someone else). */
export function processAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return e.code === 'EPERM';
  }
}

/** Owner of the lock, or undefined when there is no lock or owner.json is not written yet. */
export function readOwner(dir = LOCK_DIR) {
  try {
    return JSON.parse(fs.readFileSync(path.join(dir, OWNER_FILE), 'utf8'));
  } catch {
    return undefined;
  }
}

/** Why the current lock may be stolen, or undefined when its owner is alive and recent. */
function staleReason(dir, maxAgeMs) {
  const owner = readOwner(dir);
  if (!owner) {
    // Being created by another process (mkdir done, owner.json not yet written): give it time.
    let created;
    try {
      created = fs.statSync(dir).mtimeMs;
    } catch {
      return undefined; // gone meanwhile: the next mkdir decides
    }
    return Date.now() - created > 30_000 ? 'lock without owner for more than 30 s' : undefined;
  }
  const age = Date.now() - Date.parse(owner.startedAt);
  if (owner.hostname === os.hostname() && !processAlive(owner.pid)) return `owner PID ${owner.pid} is gone`;
  if (!(age < maxAgeMs)) return `lock older than ${Math.round(maxAgeMs / 60_000)} min`;
  return undefined;
}

/** Removes a stale lock: atomic rename first, so that only one waiter wins. */
function steal(dir) {
  const trash = `${dir}.stale-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
  try {
    fs.renameSync(dir, trash);
  } catch {
    return; // another waiter stole it first, or it was released
  }
  fs.rmSync(trash, { recursive: true, force: true });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Takes the lock, waiting while another live run holds it.
 *
 * Options: purpose (shown to the waiters), timeoutMs (E2E_LOCK_TIMEOUT minutes, default 45),
 * maxAgeMs (E2E_LOCK_MAX_AGE minutes, default 120), pollMs, log, dir.
 * Returns { token, release(), joined }: joined is true when the lock already belonged to the
 * parent process (E2E_LOCK_TOKEN), in which case release() does nothing.
 */
export async function acquireLock(opts = {}) {
  const dir = opts.dir ?? LOCK_DIR;
  const log = opts.log ?? ((m) => console.log(`[e2e lock] ${m}`));
  const inherited = process.env[LOCK_ENV];
  if (inherited && readOwner(dir)?.token === inherited) {
    return { token: inherited, joined: true, release: () => {} };
  }
  const timeoutMs = opts.timeoutMs ?? minutes('E2E_LOCK_TIMEOUT', 45);
  const maxAgeMs = opts.maxAgeMs ?? minutes('E2E_LOCK_MAX_AGE', 120);
  const pollMs = opts.pollMs ?? 2_000;
  const deadline = Date.now() + timeoutMs;
  const token = crypto.randomBytes(16).toString('hex');
  let announced = false;
  for (;;) {
    try {
      fs.mkdirSync(dir);
      const owner = {
        pid: process.pid,
        hostname: os.hostname(),
        startedAt: new Date().toISOString(),
        purpose: opts.purpose ?? 'e2e run',
        token,
      };
      fs.writeFileSync(path.join(dir, OWNER_FILE), JSON.stringify(owner, null, 2));
      let released = false;
      const release = () => {
        if (released) return;
        released = true;
        // Only ever remove our own lock (it may have been stolen after the maximum age).
        if (readOwner(dir)?.token === token) steal(dir);
      };
      return { token, joined: false, release };
    } catch (e) {
      if (e.code !== 'EEXIST') throw e;
    }
    const reason = staleReason(dir, maxAgeMs);
    if (reason) {
      log(`removing a stale lock (${reason})`);
      steal(dir);
      continue;
    }
    if (Date.now() > deadline) {
      const o = readOwner(dir);
      throw new Error(
        `another e2e run still holds ${dir} after ${Math.round(timeoutMs / 60_000)} min ` +
          `(PID ${o?.pid}, ${o?.purpose}, since ${o?.startedAt}); wait for it or remove the directory ` +
          `if that process is gone`,
      );
    }
    if (!announced) {
      const o = readOwner(dir);
      log(
        `waiting for another e2e run (PID ${o?.pid ?? '?'}, ${o?.purpose ?? '?'}, since ${o?.startedAt ?? '?'})`,
      );
      announced = true;
    }
    await sleep(pollMs);
  }
}
