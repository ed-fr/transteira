// Contracts of the resumable upload layer (tus 1.0.0, api/openapi.yaml "Large uploads").
// The engine (engine.ts) drives one file at a time through an UploadTransport; the browser
// implementation (transport-xhr.ts) uses XMLHttpRequest for progress events, tests use a fake.

/** tus protocol version sent in every request (Tus-Resumable header). */
export const TUS_VERSION = '1.0.0';

/** Size of one PATCH request body, cut with Blob.slice (never the whole file in memory). */
export const CHUNK_SIZE = 32 * 1024 * 1024;

/** Outcome of a HEAD request on an upload resource. */
export interface HeadResult {
  /** HTTP status (200 on success; tus errors have no body, the status is the whole answer). */
  status: number;
  /** Upload-Offset: bytes already received by the server (present on 200). */
  offset?: number;
  /** Upload-Length: declared size of the file (present on 200). */
  length?: number;
  /** Retry-After in seconds (429, 503). */
  retryAfterSeconds?: number;
}

/** Outcome of a PATCH request. */
export interface PatchResult {
  /** HTTP status (204 on success). */
  status: number;
  /** Upload-Offset after the request (present on 204). */
  offset?: number;
  /** Retry-After in seconds (429, 503). */
  retryAfterSeconds?: number;
}

/** Options of a PATCH request. */
export interface PatchOptions {
  /** Called with the number of bytes of this request sent so far. */
  onProgress?: (sentBytes: number) => void;
  /** Aborts the request (cancel, pause, stall watchdog). */
  signal?: AbortSignal;
}

/**
 * Transport used by the upload engine. Implementations add Tus-Resumable, the CSRF token and,
 * for PATCH, Content-Type: application/offset+octet-stream and Upload-Offset. A network failure
 * or an abort rejects the promise; any HTTP response resolves it with its status.
 */
export interface UploadTransport {
  head(url: string, signal?: AbortSignal): Promise<HeadResult>;
  patch(url: string, offset: number, body: Blob, options?: PatchOptions): Promise<PatchResult>;
  terminate(url: string): Promise<{ status: number }>;
}

/** Timer source of the upload layer, injected so that tests control time. */
export interface Clock {
  /** Current time in milliseconds. */
  now(): number;
  /** Schedules fn after ms milliseconds and returns a handle for clearTimeout. */
  setTimeout(fn: () => void, ms: number): unknown;
  /** Cancels a timer scheduled by setTimeout. */
  clearTimeout(handle: unknown): void;
}

/** Clock of the browser (globals resolved at call time, so fake timers apply). */
export const systemClock: Clock = {
  now: () => Date.now(),
  setTimeout: (fn, ms) => globalThis.setTimeout(fn, ms),
  clearTimeout: (handle) => globalThis.clearTimeout(handle as ReturnType<typeof setTimeout>),
};

/** Request failure without an HTTP response (network error, timeout or abort). */
export class TransportError extends Error {
  /** True when the request was aborted through its AbortSignal. */
  readonly aborted: boolean;

  constructor(message: string, aborted = false) {
    super(message);
    this.name = 'TransportError';
    this.aborted = aborted;
  }
}
