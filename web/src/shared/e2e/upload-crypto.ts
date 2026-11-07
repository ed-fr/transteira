// Page side of the end-to-end encrypted upload: an UploadCrypto hashes the plaintext files before
// the transfer is created, then produces the encrypted ranges the upload engine sends. The
// browser implementation runs in a dedicated module Worker (upload.worker.ts) so that hashing and
// encrypting gigabytes never freezes the page; when the Worker cannot be started (old browser,
// blocked script) the same core runs in the page.
//
// The Worker receives the non-extractable HKDF key of importTransferKey (a CryptoKey is
// structured-cloneable), never the bytes of K, and the File objects (cloned by reference: their
// content is read in slices by the Worker, never copied whole).

import {
  UploadCryptoCore,
  abortError,
  responseError,
  type CryptoRequest,
  type CryptoResponse,
} from './upload-crypto-core';

/** Hashing and encryption service of one transfer. */
export interface UploadCrypto {
  /**
   * Returns the lowercase hexadecimal SHA-256 of the plaintext of file index and records the
   * SHA-256 of each of its chunks of chunkSize bytes (UploadCryptoCore.hash). onProgress receives
   * the number of bytes of this file hashed so far; signal aborts (AbortError).
   */
  hash(
    index: number,
    file: Blob,
    chunkSize: number,
    onProgress?: (bytes: number) => void,
    signal?: AbortSignal,
  ): Promise<string>;
  /**
   * Prepares the encryption of file index with its header salt and chunk size (the same values
   * on every resume) and returns the size of its encrypted stream. The file must have been hashed
   * first in this service; a range whose plaintext differs from the hashed one rejects with a
   * FileChangedError (isFileChangedError) and nothing of it is encrypted.
   */
  prepare(index: number, file: Blob, salt: Uint8Array, chunkSize: number): Promise<number>;
  /** Returns the bytes [start, end) of the encrypted stream of a prepared file. */
  range(index: number, start: number, end: number): Promise<Uint8Array<ArrayBuffer>>;
  /** Releases the Worker and forgets the files; later calls reject. */
  dispose(): void;
}

/** In-page implementation (tests, and fallback when no Worker can be started). */
export function createInThreadUploadCrypto(key: CryptoKey | Uint8Array): UploadCrypto {
  const core = new UploadCryptoCore(key);
  let disposed = false;
  const check = (): void => {
    if (disposed) throw new Error('upload crypto: disposed');
  };
  return {
    async hash(index, file, chunkSize, onProgress, signal) {
      check();
      return core.hash(
        index,
        file,
        chunkSize,
        (bytes) => onProgress?.(bytes),
        () => signal?.aborted === true || disposed,
      );
    },
    async prepare(index, file, salt, chunkSize) {
      check();
      return core.prepare(index, file, salt, chunkSize);
    },
    async range(index, start, end) {
      check();
      return core.range(index, start, end);
    },
    dispose() {
      disposed = true;
      core.clear();
    },
  };
}

/** The part of Worker used by the client. */
export interface WorkerLike {
  postMessage(message: CryptoRequest): void;
  onmessage: ((event: { data: CryptoResponse }) => void) | null;
  onerror: ((event: unknown) => void) | null;
  terminate(): void;
}

interface Pending {
  resolve: (value: CryptoResponse & { kind: 'ok' }) => void;
  reject: (err: Error) => void;
  onProgress?: ((bytes: number) => void) | undefined;
}

/** Worker-backed implementation; init(key) must succeed before any other call. */
export class WorkerUploadCrypto implements UploadCrypto {
  readonly #worker: WorkerLike;
  readonly #pending = new Map<number, Pending>();
  #next = 0;
  #failure: Error | undefined;

  constructor(worker: WorkerLike) {
    this.#worker = worker;
    worker.onmessage = (event) => this.#receive(event.data);
    worker.onerror = () => this.#fail(new Error('upload crypto: worker failed'));
  }

  /** Hands the transfer key to the Worker; resolves once it is ready. */
  async init(key: CryptoKey): Promise<void> {
    await this.#call((id) => ({ id, op: 'init', key }));
  }

  async hash(
    index: number,
    file: Blob,
    chunkSize: number,
    onProgress?: (bytes: number) => void,
    signal?: AbortSignal,
  ): Promise<string> {
    if (signal?.aborted) throw abortError();
    let id = -1;
    const onAbort = (): void => {
      this.#worker.postMessage({ id: ++this.#next, op: 'abort', target: id });
    };
    signal?.addEventListener('abort', onAbort, { once: true });
    try {
      const r = await this.#call((n) => {
        id = n;
        return { id: n, op: 'hash', index, file, chunkSize };
      }, onProgress);
      return r.value as string;
    } finally {
      signal?.removeEventListener('abort', onAbort);
    }
  }

  async prepare(index: number, file: Blob, salt: Uint8Array, chunkSize: number): Promise<number> {
    const r = await this.#call((id) => ({ id, op: 'prepare', index, file, salt, chunkSize }));
    return r.value as number;
  }

  async range(index: number, start: number, end: number): Promise<Uint8Array<ArrayBuffer>> {
    const r = await this.#call((id) => ({ id, op: 'range', index, start, end }));
    return new Uint8Array(r.value as ArrayBuffer);
  }

  dispose(): void {
    this.#worker.terminate();
    this.#fail(new Error('upload crypto: disposed'));
  }

  #call(
    build: (id: number) => CryptoRequest,
    onProgress?: (bytes: number) => void,
  ): Promise<CryptoResponse & { kind: 'ok' }> {
    if (this.#failure !== undefined) return Promise.reject(this.#failure);
    const id = ++this.#next;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject, onProgress });
      this.#worker.postMessage(build(id));
    });
  }

  #receive(r: CryptoResponse): void {
    const pending = this.#pending.get(r.id);
    if (pending === undefined) return;
    if (r.kind === 'progress') {
      pending.onProgress?.(r.bytes);
      return;
    }
    this.#pending.delete(r.id);
    if (r.kind === 'ok') pending.resolve(r);
    else pending.reject(responseError(r));
  }

  #fail(err: Error): void {
    this.#failure ??= err;
    for (const pending of this.#pending.values()) pending.reject(err);
    this.#pending.clear();
  }
}

/** Options of openUploadCrypto. */
export interface OpenUploadCryptoOptions {
  /** Worker factory (the bundled upload.worker.ts by default). */
  createWorker?: () => WorkerLike;
  /** Time allowed for the Worker to start before falling back to the page (default 10 s). */
  readyTimeoutMs?: number;
}

/** Default time allowed for the Worker to answer its init request. */
export const WORKER_READY_TIMEOUT_MS = 10_000;

function bundledWorker(): WorkerLike {
  // This exact form lets Vite emit the Worker as a separate file under /assets/.
  return new Worker(new URL('./upload.worker.ts', import.meta.url), {
    type: 'module',
  }) as unknown as WorkerLike;
}

/**
 * Opens the upload encryption of a transfer whose key is the non-extractable HKDF key of
 * importTransferKey: in a Worker when one starts within the timeout, else in the page.
 */
export async function openUploadCrypto(
  key: CryptoKey,
  options: OpenUploadCryptoOptions = {},
): Promise<UploadCrypto> {
  let client: WorkerUploadCrypto;
  try {
    client = new WorkerUploadCrypto((options.createWorker ?? bundledWorker)());
  } catch {
    return createInThreadUploadCrypto(key);
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(new Error('upload crypto: worker timeout')),
      options.readyTimeoutMs ?? WORKER_READY_TIMEOUT_MS,
    );
  });
  try {
    await Promise.race([client.init(key), timeout]);
    return client;
  } catch {
    client.dispose();
    return createInThreadUploadCrypto(key);
  } finally {
    clearTimeout(timer);
  }
}
