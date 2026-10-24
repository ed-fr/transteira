// Types of lock.mjs (machine-wide run lock of the end-to-end suite).

/** Lock directory (test/e2e/.run.lock). */
export declare const LOCK_DIR: string;
/** Environment variable carrying the token of the lock held by a parent process. */
export declare const LOCK_ENV: string;

/** Content of owner.json. */
export interface LockOwner {
  pid: number;
  hostname: string;
  startedAt: string;
  purpose: string;
  token: string;
}

/** Options of acquireLock. */
export interface LockOptions {
  purpose?: string;
  timeoutMs?: number;
  maxAgeMs?: number;
  pollMs?: number;
  log?: (message: string) => void;
  dir?: string;
}

/** A held lock. */
export interface HeldLock {
  token: string;
  /** True when the lock belonged to the parent process (release() then does nothing). */
  joined: boolean;
  release(): void;
}

export declare function processAlive(pid: number): boolean;
export declare function readOwner(dir?: string): LockOwner | undefined;
export declare function acquireLock(opts?: LockOptions): Promise<HeldLock>;
