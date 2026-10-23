// Upload engine of the deposit page (CLAUDE.md section 8.6): sends the files of a transfer one
// after the other through tus, in Blob.slice chunks (a chunk is never read into memory), and
// survives cuts, stalls and server restarts by asking the server where to resume (HEAD).
//
// Retry policy:
// - network error, 5xx, 408 or stall (no progress for 45 s): HEAD then resume, after an
//   exponential delay 1, 2, 4... s capped at 30 s; the browser "online" event retries at once;
// - 429 / 503: waits Retry-After (not counted as a failure);
// - 409 / 400 (offset conflict, or the server still holds the upload lock of a request it has
//   not yet seen die): HEAD then resume after an exponential delay 1, 2, 4... s capped at 10 s;
//   conflicts are not counted as failures during the first 90 s of a streak (the server releases
//   its lock after its read timeout), then each one counts;
// - 10 consecutive failures without progress: paused, resume() starts again;
// - 401, 403, 404, 410, 413, 507 and any other unexpected status: fatal UploadError.
//
// Every upload URL must be a same-origin path under /api/v1/uploads/ (safeUploadUrl), otherwise
// the engine fails with protocol-error before sending anything.
//
// The engine is a Svelte-compatible readable store (subscribe), plus a throttled stream of
// announcements for the live region (at most every 10 % or 30 s, plus file done/paused/error).
import { safeUploadUrl } from '../safe/href';
import { CHUNK_SIZE, systemClock, type Clock, type UploadTransport } from './tus';

/** Time without upload progress (or without HEAD answer) after which a request is aborted. */
export const STALL_TIMEOUT_MS = 45_000;
/** Consecutive failures without progress after which the engine pauses. */
export const MAX_CONSECUTIVE_FAILURES = 10;
/** First retry delay; doubled after each failure. */
export const BASE_RETRY_DELAY_MS = 1_000;
/** Cap of the retry delay. */
export const MAX_RETRY_DELAY_MS = 30_000;
/** Cap of the delay between two attempts after an offset or lock conflict. */
export const MAX_CONFLICT_DELAY_MS = 10_000;
/** Time during which a streak of conflicts is not counted as failures. */
export const CONFLICT_BUDGET_MS = 90_000;
/** Progress announcements: at most one per step of this many percent... */
export const ANNOUNCE_STEP_PERCENT = 10;
/** ...or one per this interval while bytes keep flowing. */
export const ANNOUNCE_INTERVAL_MS = 30_000;

/** One file to upload. */
export interface UploadFileSpec {
  /** Display name (the name declared at transfer creation). */
  name: string;
  /**
   * File content; only slices are read, one chunk at a time. May be absent for a file already
   * complete on the server (offset equal to size), for example after a reload.
   */
  file?: Blob;
  /** Size in bytes, required when file is absent (otherwise file.size). */
  size?: number;
  /** tus upload URL returned by createTransfer (or getTransfer when resuming). */
  uploadUrl: string;
  /** Known server offset (uploadOffset); when absent the engine asks the server first (HEAD). */
  offset?: number;
}

/** Stable codes of fatal upload errors, translated as upload.error.<code>. */
export type UploadErrorCode =
  | 'unauthenticated'
  | 'forbidden'
  | 'upload-gone'
  | 'payload-too-large'
  | 'insufficient-storage'
  | 'protocol-error'
  /** The content of a file still to upload was not provided. */
  | 'file-missing';

/** Fatal upload error: retrying cannot help. */
export class UploadError extends Error {
  readonly code: UploadErrorCode;
  /** HTTP status that caused the error, when there is one. */
  readonly status: number | undefined;

  constructor(code: UploadErrorCode, status?: number) {
    super(status === undefined ? code : `${code} (HTTP ${status})`);
    this.name = 'UploadError';
    this.code = code;
    this.status = status;
  }
}

/** Maps a fatal tus status to its error code (other unexpected statuses: protocol-error). */
export function fatalCode(status: number): UploadErrorCode {
  switch (status) {
    case 401:
      return 'unauthenticated';
    case 403:
      return 'forbidden';
    case 404:
    case 410:
      return 'upload-gone';
    case 413:
      return 'payload-too-large';
    case 507:
      return 'insufficient-storage';
    default:
      return 'protocol-error';
  }
}

/** What to do after a non-success tus status. */
export type StatusAction = 'conflict' | 'retry' | 'wait' | 'fatal';

/** Classifies a non-success status of a HEAD or PATCH request. */
export function classifyStatus(status: number): StatusAction {
  if (status === 409 || status === 400) {
    return 'conflict';
  }
  if (status === 429 || status === 503) {
    return 'wait';
  }
  if (status === 408 || (status >= 500 && status !== 507)) {
    return 'retry';
  }
  return 'fatal';
}

/** Retry delay after the n-th consecutive failure (1-based): 1, 2, 4... s capped at 30 s. */
export function retryDelay(failures: number): number {
  return Math.min(BASE_RETRY_DELAY_MS * 2 ** Math.max(0, failures - 1), MAX_RETRY_DELAY_MS);
}

/** Delay after the n-th consecutive conflict (1-based): 1, 2, 4, 8, 10, 10... s. */
export function conflictDelay(conflicts: number): number {
  return Math.min(BASE_RETRY_DELAY_MS * 2 ** Math.max(0, conflicts - 1), MAX_CONFLICT_DELAY_MS);
}

/** Phase of the engine. */
export type UploadPhase = 'idle' | 'uploading' | 'retrying' | 'paused' | 'completed' | 'cancelled' | 'failed';

/** Why the engine is paused. */
export type PauseReason = 'user' | 'failures';

/** Progress of one file. */
export interface FileProgress {
  name: string;
  size: number;
  /** Bytes confirmed by the server plus bytes of the request in flight. */
  uploadedBytes: number;
  done: boolean;
}

/** Immutable state of the engine, emitted to subscribers on every change. */
export interface UploadSnapshot {
  phase: UploadPhase;
  pauseReason?: PauseReason;
  files: FileProgress[];
  /** Index of the file being uploaded (files.length once completed). */
  currentIndex: number;
  uploadedBytes: number;
  totalBytes: number;
  /** Integer percentage of totalBytes (100 for an empty transfer). */
  percent: number;
  /** Consecutive failures without progress. */
  failures: number;
  /** Clock time of the next attempt while phase is retrying. */
  retryAt?: number;
  /** Fatal error while phase is failed. */
  error?: UploadError;
}

/** Message for the live region (throttled). */
export type UploadAnnouncement =
  | { kind: 'progress'; percent: number }
  | { kind: 'file-done'; index: number; name: string }
  | { kind: 'paused'; reason: PauseReason }
  | { kind: 'error'; code: UploadErrorCode }
  | { kind: 'completed' }
  | { kind: 'cancelled' };

/** Final outcome of start(). A fatal error rejects with UploadError instead. */
export type UploadResult = 'completed' | 'cancelled';

/** Dependencies of the engine. */
export interface UploadEngineDeps {
  transport: UploadTransport;
  /** Abandons the transfer on the server (DELETE /transfers/{id}), called by cancel(). */
  cancelTransfer: () => Promise<void>;
  clock?: Clock;
  /**
   * Subscribes to the browser "online" event and returns the unsubscribe function.
   * Default: window 'online' when available.
   */
  onOnline?: (listener: () => void) => () => void;
  chunkSize?: number;
  stallTimeoutMs?: number;
  maxFailures?: number;
  /** Time during which a streak of conflicts is not counted as failures (default 90 s). */
  conflictBudgetMs?: number;
}

/** Upload engine of one transfer. */
export interface UploadEngine {
  /** Starts the upload; the promise settles once completed, cancelled or failed (fatal). */
  start(): Promise<UploadResult>;
  /** Pauses (aborts the request in flight); resume() continues from the server offset. */
  pause(): void;
  /** Resumes after a pause, or retries at once while waiting for a retry. */
  resume(): void;
  /** Aborts the upload and abandons the transfer on the server. */
  cancel(): Promise<void>;
  /**
   * Stops the engine for good without abandoning the transfer (the page or the screen is left):
   * aborts the request in flight and clears every timer; start() resolves cancelled, silently.
   */
  stop(): void;
  /** Current state. */
  getSnapshot(): UploadSnapshot;
  /** Svelte store contract: run is called at once, then on every change. */
  subscribe(run: (snapshot: UploadSnapshot) => void): () => void;
  /** Subscribes to live-region announcements. */
  onAnnounce(listener: (announcement: UploadAnnouncement) => void): () => void;
  /** True while bytes may still be sent (for a beforeunload warning). */
  isActive(): boolean;
}

interface FileState {
  spec: UploadFileSpec;
  size: number;
  offset: number;
  sent: number;
  needHead: boolean;
  done: boolean;
}

type CallResult<T> = { value: T } | { error: 'network' | 'stall' };

function defaultOnOnline(listener: () => void): () => void {
  const target = globalThis as unknown as Partial<EventTarget>;
  if (typeof target.addEventListener !== 'function' || typeof target.removeEventListener !== 'function') {
    return () => {};
  }
  target.addEventListener('online', listener);
  return () => target.removeEventListener?.('online', listener);
}

/** Creates the upload engine of a transfer's files, uploaded in the given order. */
export function createUploadEngine(specs: UploadFileSpec[], deps: UploadEngineDeps): UploadEngine {
  const clock = deps.clock ?? systemClock;
  const chunkSize = deps.chunkSize ?? CHUNK_SIZE;
  const stallMs = deps.stallTimeoutMs ?? STALL_TIMEOUT_MS;
  const maxFailures = deps.maxFailures ?? MAX_CONSECUTIVE_FAILURES;
  const conflictBudgetMs = deps.conflictBudgetMs ?? CONFLICT_BUDGET_MS;
  const { transport } = deps;

  const files: FileState[] = specs.map((spec) => {
    const size = spec.file?.size ?? spec.size ?? 0;
    const offset = Math.min(spec.offset ?? 0, size);
    return { spec, size, offset, sent: 0, needHead: spec.offset === undefined, done: false };
  });
  const totalBytes = files.reduce((sum, f) => sum + f.size, 0);

  let phase: UploadPhase = 'idle';
  let pauseReason: PauseReason | undefined;
  let error: UploadError | undefined;
  let retryAt: number | undefined;
  let index = 0;
  let failures = 0;
  /** Consecutive conflicts without progress, and clock time of the first one. */
  let conflicts = 0;
  let conflictSince: number | undefined;
  /** Incremented by pause, resume and cancel: a loop of an older generation stops. */
  let generation = 0;
  let inflight: AbortController | undefined;
  let wake: (() => void) | undefined;
  let unsubscribeOnline: (() => void) | undefined;
  let outcome: Promise<UploadResult> | undefined;
  let settle: { resolve: (r: UploadResult) => void; reject: (e: UploadError) => void } | undefined;

  const listeners = new Set<(s: UploadSnapshot) => void>();
  const announceListeners = new Set<(a: UploadAnnouncement) => void>();
  let lastAnnouncedPercent = 0;
  let lastAnnouncedAt = 0;

  function uploadedBytes(): number {
    return files.reduce((sum, f) => sum + Math.min(f.offset + f.sent, f.size), 0);
  }

  function percentOf(bytes: number): number {
    return totalBytes === 0 ? 100 : Math.floor((bytes * 100) / totalBytes);
  }

  function snapshot(): UploadSnapshot {
    const bytes = uploadedBytes();
    const s: UploadSnapshot = {
      phase,
      files: files.map((f) => ({
        name: f.spec.name,
        size: f.size,
        uploadedBytes: Math.min(f.offset + f.sent, f.size),
        done: f.done,
      })),
      currentIndex: index,
      uploadedBytes: bytes,
      totalBytes,
      percent: percentOf(bytes),
      failures,
    };
    if (pauseReason !== undefined) s.pauseReason = pauseReason;
    if (retryAt !== undefined) s.retryAt = retryAt;
    if (error !== undefined) s.error = error;
    return s;
  }

  function emit(): void {
    const s = snapshot();
    for (const run of listeners) run(s);
  }

  function announce(a: UploadAnnouncement): void {
    lastAnnouncedAt = clock.now();
    for (const listener of announceListeners) listener(a);
  }

  function maybeAnnounceProgress(): void {
    const percent = percentOf(uploadedBytes());
    const stepReached =
      Math.floor(percent / ANNOUNCE_STEP_PERCENT) > Math.floor(lastAnnouncedPercent / ANNOUNCE_STEP_PERCENT);
    const intervalElapsed =
      percent > lastAnnouncedPercent && clock.now() - lastAnnouncedAt >= ANNOUNCE_INTERVAL_MS;
    if (percent < 100 && (stepReached || intervalElapsed)) {
      lastAnnouncedPercent = percent;
      announce({ kind: 'progress', percent });
    }
  }

  function setPhase(next: UploadPhase): void {
    phase = next;
    if (next !== 'paused') pauseReason = undefined;
    if (next !== 'retrying') retryAt = undefined;
    emit();
  }

  function interrupt(): void {
    generation++;
    inflight?.abort();
    inflight = undefined;
    wake?.();
  }

  function stopListening(): void {
    unsubscribeOnline?.();
    unsubscribeOnline = undefined;
  }

  function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => {
      const handle = clock.setTimeout(done, ms);
      function done(): void {
        clock.clearTimeout(handle);
        wake = undefined;
        resolve();
      }
      wake = done;
    });
  }

  /** Runs one request with the stall watchdog (re-armed by touch on each progress event). */
  async function call<T>(
    run: (signal: AbortSignal, touch: () => void) => Promise<T>,
  ): Promise<CallResult<T>> {
    const controller = new AbortController();
    inflight = controller;
    let stalled = false;
    let timer: unknown;
    const touch = (): void => {
      clock.clearTimeout(timer);
      timer = clock.setTimeout(() => {
        stalled = true;
        controller.abort();
      }, stallMs);
    };
    touch();
    try {
      return { value: await run(controller.signal, touch) };
    } catch {
      return { error: stalled ? 'stall' : 'network' };
    } finally {
      clock.clearTimeout(timer);
      if (inflight === controller) inflight = undefined;
    }
  }

  function resetConflicts(): void {
    conflicts = 0;
    conflictSince = undefined;
  }

  /** Records a server offset; progress resets the failure and conflict counters. */
  function confirm(f: FileState, offset: number): void {
    if (offset > f.offset) {
      failures = 0;
      resetConflicts();
    }
    f.offset = Math.min(offset, f.size);
    f.sent = 0;
  }

  /**
   * Handles a failed attempt: counts it (unless rate limited), pauses after too many, else waits.
   * Returns false when the loop must stop (paused or superseded).
   */
  async function recover(gen: number, f: FileState, delayMs: number, counted: boolean): Promise<boolean> {
    f.needHead = true;
    f.sent = 0;
    if (counted) {
      failures++;
      if (failures >= maxFailures) {
        interrupt();
        phase = 'paused';
        pauseReason = 'failures';
        retryAt = undefined;
        emit();
        announce({ kind: 'paused', reason: 'failures' });
        return false;
      }
    }
    if (delayMs > 0) {
      phase = 'retrying';
      retryAt = clock.now() + delayMs;
      emit();
      await sleep(delayMs);
      if (gen !== generation) return false;
      setPhase('uploading');
    } else {
      emit();
    }
    return true;
  }

  /** Acts on a non-success status. Returns false when the loop must stop. */
  function onStatus(gen: number, f: FileState, status: number, retryAfterSeconds?: number): Promise<boolean> {
    switch (classifyStatus(status)) {
      case 'conflict': {
        conflicts++;
        conflictSince ??= clock.now();
        const counted = clock.now() - conflictSince >= conflictBudgetMs;
        return recover(gen, f, conflictDelay(conflicts), counted);
      }
      case 'wait':
        return recover(
          gen,
          f,
          retryAfterSeconds === undefined ? retryDelay(failures + 1) : retryAfterSeconds * 1000,
          false,
        );
      case 'retry':
        return recover(gen, f, retryDelay(failures + 1), true);
      default:
        throw new UploadError(fatalCode(status), status);
    }
  }

  /** Uploads one file. Returns false when superseded (pause, cancel). */
  async function uploadFile(gen: number, f: FileState): Promise<boolean> {
    for (;;) {
      if (f.needHead) {
        const r = await call((signal) => transport.head(f.spec.uploadUrl, signal));
        if (gen !== generation) return false;
        if ('error' in r) {
          if (!(await recover(gen, f, retryDelay(failures + 1), true))) return false;
          continue;
        }
        const { status, offset, retryAfterSeconds } = r.value;
        if (status !== 200) {
          if (!(await onStatus(gen, f, status, retryAfterSeconds))) return false;
          continue;
        }
        if (offset === undefined) throw new UploadError('protocol-error', status);
        confirm(f, offset);
        f.needHead = false;
        emit();
      }
      if (f.offset >= f.size) return true;

      if (f.spec.file === undefined) throw new UploadError('file-missing');
      const start = f.offset;
      const body = f.spec.file.slice(start, Math.min(start + chunkSize, f.size));
      const r = await call((signal, touch) =>
        transport.patch(f.spec.uploadUrl, start, body, {
          signal,
          onProgress: (sent) => {
            if (gen !== generation) return;
            touch();
            f.sent = Math.min(Math.max(sent, 0), body.size);
            emit();
            maybeAnnounceProgress();
          },
        }),
      );
      if (gen !== generation) return false;
      if ('error' in r) {
        if (!(await recover(gen, f, retryDelay(failures + 1), true))) return false;
        continue;
      }
      const { status, offset, retryAfterSeconds } = r.value;
      if (status === 204) {
        const next = offset ?? start + body.size;
        if (next > start) {
          confirm(f, next);
          emit();
          maybeAnnounceProgress();
          continue;
        }
        if (!(await recover(gen, f, 0, true))) return false;
        continue;
      }
      if (!(await onStatus(gen, f, status, retryAfterSeconds))) return false;
    }
  }

  async function loop(gen: number): Promise<void> {
    try {
      for (const f of files) {
        const url = safeUploadUrl(f.spec.uploadUrl);
        if (url === undefined) throw new UploadError('protocol-error');
      }
      while (index < files.length) {
        const f = files[index] as FileState;
        if (!(await uploadFile(gen, f))) return;
        f.done = true;
        index++;
        emit();
        announce({ kind: 'file-done', index: index - 1, name: f.spec.name });
      }
      phase = 'completed';
      stopListening();
      emit();
      announce({ kind: 'completed' });
      settle?.resolve('completed');
    } catch (err) {
      if (gen !== generation) return;
      generation++;
      error = err instanceof UploadError ? err : new UploadError('protocol-error');
      phase = 'failed';
      stopListening();
      emit();
      announce({ kind: 'error', code: error.code });
      settle?.reject(error);
    }
  }

  function run(): void {
    const gen = ++generation;
    setPhase('uploading');
    void loop(gen);
  }

  return {
    start() {
      if (outcome === undefined) {
        outcome = new Promise<UploadResult>((resolve, reject) => {
          settle = { resolve, reject };
        });
        lastAnnouncedAt = clock.now();
        unsubscribeOnline = (deps.onOnline ?? defaultOnOnline)(() => {
          if (phase === 'retrying') wake?.();
        });
        run();
      }
      return outcome;
    },

    pause() {
      if (phase !== 'uploading' && phase !== 'retrying') return;
      interrupt();
      // The request in flight is aborted: the server tells where to resume.
      const current = files[index] as FileState;
      current.sent = 0;
      current.needHead = true;
      phase = 'paused';
      pauseReason = 'user';
      retryAt = undefined;
      emit();
      announce({ kind: 'paused', reason: 'user' });
    },

    resume() {
      if (phase === 'retrying') {
        wake?.();
      } else if (phase === 'paused') {
        failures = 0;
        resetConflicts();
        run();
      }
    },

    async cancel() {
      if (phase === 'completed' || phase === 'cancelled') return;
      const wasFailed = phase === 'failed';
      interrupt();
      for (const f of files) f.sent = 0;
      phase = 'cancelled';
      pauseReason = undefined;
      retryAt = undefined;
      stopListening();
      emit();
      announce({ kind: 'cancelled' });
      if (!wasFailed) settle?.resolve('cancelled');
      await deps.cancelTransfer();
    },

    stop() {
      stopListening();
      if (phase === 'completed' || phase === 'cancelled' || phase === 'failed') return;
      interrupt();
      for (const f of files) f.sent = 0;
      phase = 'cancelled';
      pauseReason = undefined;
      retryAt = undefined;
      emit();
      settle?.resolve('cancelled');
    },

    getSnapshot: snapshot,

    subscribe(run) {
      listeners.add(run);
      run(snapshot());
      return () => listeners.delete(run);
    },

    onAnnounce(listener) {
      announceListeners.add(listener);
      return () => announceListeners.delete(listener);
    },

    isActive() {
      return phase === 'uploading' || phase === 'retrying' || phase === 'paused';
    },
  };
}
