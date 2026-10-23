// Deposit helpers around the upload engine: the idempotency key of createTransfer, the upload
// specs built from a transfer, and finalization followed by polling until the antivirus has
// decided (api/openapi.yaml finalizeTransfer, getTransfer).
import { ApiProblem, type ApiClient, type ProblemCode } from '../api/client';
import type { components } from '../api/schema';
import type { UploadFileSpec } from './engine';
import { systemClock, type Clock } from './tus';

/** Transfer as seen by its sender. */
export type SenderTransfer = components['schemas']['SenderTransfer'];

/**
 * Idempotency-Key of one submission: the same value is sent on every retry of createTransfer
 * (a lost answer then returns the transfer already created), renew() before a new submission.
 */
export class IdempotencyKey {
  #value: string;
  readonly #generate: () => string;

  constructor(generate: () => string = () => globalThis.crypto.randomUUID()) {
    this.#generate = generate;
    this.#value = generate();
  }

  /** Key of the current submission. */
  get value(): string {
    return this.#value;
  }

  /** Starts a new submission and returns its key. */
  renew(): string {
    this.#value = this.#generate();
    return this.#value;
  }
}

/**
 * Builds the engine specs from a transfer (createTransfer answer or getTransfer when resuming)
 * and the selected files in the declared order. A file already complete on the server needs no
 * content; the engine fails with file-missing if content is needed but absent.
 *
 * fresh is true only for the answer of createTransfer, whose offsets (0) are exact: the offsets
 * of getTransfer are only updated at the start and the end of an upload, so when resuming the
 * offset is left undefined and the engine asks the server first (HEAD).
 */
export function uploadSpecs(
  transfer: SenderTransfer,
  contents: readonly (Blob | undefined)[],
  fresh = false,
): UploadFileSpec[] {
  return transfer.files.map((file, i) => {
    const spec: UploadFileSpec = {
      name: file.name,
      size: file.size,
      uploadUrl: file.uploadUrl ?? '',
    };
    if (fresh) spec.offset = file.uploadOffset ?? 0;
    const content = contents[i];
    if (content !== undefined) spec.file = content;
    return spec;
  });
}

/** Part of the API client used here (any ApiClient fits). */
export type RequestClient = Pick<ApiClient, 'request'>;

/** Outcome of finalizeAndWait. */
export type FinalizeOutcome =
  /** The recipients have been notified. */
  | { kind: 'available'; transfer: SenderTransfer }
  /** No file could be delivered (all infected or scan_error). */
  | { kind: 'rejected'; transfer: SenderTransfer }
  /** Some files are not complete: resume the upload, then finalize again. */
  | { kind: 'upload-incomplete'; files: string[] }
  /** A file hash is on the tenant blocklist. */
  | { kind: 'blocked'; files: string[] }
  /** Fatal: code is the problem code (checksum-mismatch, state-conflict, transfer-gone...). */
  | { kind: 'failed'; code: ProblemCode | 'network'; status?: number }
  /** The signal was aborted (the page was left); the sender is notified by mail anyway. */
  | { kind: 'stopped' };

/** Options of finalizeAndWait. */
export interface FinalizeOptions {
  clock?: Clock;
  /** Called with every transfer read (per-file scan statuses). */
  onUpdate?: (transfer: SenderTransfer) => void;
  /** Stops polling. */
  signal?: AbortSignal;
  /** Attempts of the finalize request on network errors, 5xx, 429 and 503 (default 5). */
  finalizeAttempts?: number;
}

/** First polling delay. */
export const POLL_INITIAL_MS = 2_000;
/** Cap of the polling delay. */
export const POLL_MAX_MS = 10_000;

/** Polling delay after n reads (0-based): 2, 4, 8, 10, 10... s. */
export function pollDelay(n: number): number {
  return Math.min(POLL_INITIAL_MS * 2 ** n, POLL_MAX_MS);
}

function isTransient(err: unknown): boolean {
  return !(err instanceof ApiProblem) || err.status >= 500 || err.status === 429 || err.status === 408;
}

function failure(err: unknown): FinalizeOutcome {
  if (err instanceof ApiProblem) {
    return { kind: 'failed', code: err.code ?? 'internal-error', status: err.status };
  }
  return { kind: 'failed', code: 'network' };
}

function terminal(transfer: SenderTransfer): FinalizeOutcome | undefined {
  switch (transfer.status) {
    case 'available':
      return { kind: 'available', transfer };
    case 'rejected':
      return { kind: 'rejected', transfer };
    case 'expired':
    case 'deleted':
      return { kind: 'failed', code: 'transfer-gone' };
    default:
      return undefined;
  }
}

/** Returns a sleep function that ends early when signal is aborted. */
function waiter(clock: Clock, signal: AbortSignal | undefined): (ms: number) => Promise<void> {
  return (ms) =>
    new Promise((resolve) => {
      const onAbort = (): void => {
        clock.clearTimeout(handle);
        resolve();
      };
      const handle = clock.setTimeout(() => {
        signal?.removeEventListener('abort', onAbort);
        resolve();
      }, ms);
      signal?.addEventListener('abort', onAbort, { once: true });
    });
}

/**
 * Finalizes a transfer whose files are uploaded, then polls it until it is available or
 * rejected. A lost finalize answer is detected (409 state-conflict while the transfer is no
 * longer uploading) and polling continues.
 */
export async function finalizeAndWait(
  client: RequestClient,
  transferId: string,
  options: FinalizeOptions = {},
): Promise<FinalizeOutcome> {
  const clock = options.clock ?? systemClock;
  const { signal, onUpdate } = options;
  const attempts = options.finalizeAttempts ?? 5;
  const path = `/transfers/${encodeURIComponent(transferId)}`;

  const wait = waiter(clock, signal);

  const read = async (): Promise<SenderTransfer> => {
    const res = await client.request<SenderTransfer>('GET', path, { signal });
    onUpdate?.(res.data);
    return res.data;
  };

  let transfer: SenderTransfer | undefined;
  for (let attempt = 1; transfer === undefined; attempt++) {
    if (signal?.aborted) return { kind: 'stopped' };
    try {
      const res = await client.request<SenderTransfer>('POST', `${path}/finalize`, { signal });
      transfer = res.data;
      onUpdate?.(transfer);
    } catch (err) {
      if (signal?.aborted) return { kind: 'stopped' };
      if (err instanceof ApiProblem) {
        if (err.code === 'upload-incomplete') return { kind: 'upload-incomplete', files: err.files ?? [] };
        if (err.code === 'blocked-file') return { kind: 'blocked', files: err.files ?? [] };
        if (err.code === 'state-conflict') {
          // Already finalized by an attempt whose answer was lost?
          try {
            const current = await read();
            if (current.status !== 'uploading') {
              transfer = current;
              break;
            }
          } catch (readErr) {
            return failure(readErr);
          }
          return failure(err);
        }
      }
      if (!isTransient(err) || attempt >= attempts) return failure(err);
      const retryAfter = err instanceof ApiProblem ? err.retryAfterSeconds : undefined;
      await wait(retryAfter === undefined ? pollDelay(attempt - 1) : retryAfter * 1000);
    }
  }

  return poll(client, path, transfer, options);
}

/**
 * Polls a transfer already finalized (reload of the page during the antivirus analysis) until it
 * is available or rejected, without finalizing it again.
 */
export async function waitForDecision(
  client: RequestClient,
  transferId: string,
  options: FinalizeOptions = {},
): Promise<FinalizeOutcome> {
  return poll(client, `/transfers/${encodeURIComponent(transferId)}`, undefined, options);
}

async function poll(
  client: RequestClient,
  path: string,
  first: SenderTransfer | undefined,
  options: FinalizeOptions,
): Promise<FinalizeOutcome> {
  const clock = options.clock ?? systemClock;
  const { signal, onUpdate } = options;
  const wait = waiter(clock, signal);
  const read = async (): Promise<SenderTransfer> => {
    const res = await client.request<SenderTransfer>('GET', path, { signal });
    onUpdate?.(res.data);
    return res.data;
  };

  /** Reads the transfer after delay ms, retrying transient failures; an outcome stops polling. */
  const readAfter = async (delay: number): Promise<{ transfer: SenderTransfer } | FinalizeOutcome> => {
    for (let ms = delay; ;) {
      if (ms > 0) await wait(ms);
      if (signal?.aborted) return { kind: 'stopped' };
      try {
        return { transfer: await read() };
      } catch (err) {
        if (signal?.aborted) return { kind: 'stopped' };
        if (!isTransient(err)) return failure(err);
        const retryAfter = err instanceof ApiProblem ? err.retryAfterSeconds : undefined;
        ms = retryAfter === undefined ? POLL_MAX_MS : retryAfter * 1000;
      }
    }
  };

  let transfer: SenderTransfer;
  if (first === undefined) {
    const r = await readAfter(0);
    if ('kind' in r) return r;
    transfer = r.transfer;
  } else {
    transfer = first;
  }
  for (let n = 0; ; n++) {
    const done = terminal(transfer);
    if (done !== undefined) return done;
    const r = await readAfter(pollDelay(n));
    if ('kind' in r) return r;
    transfer = r.transfer;
  }
}
