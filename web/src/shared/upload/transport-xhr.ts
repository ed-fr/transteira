// Browser UploadTransport built on XMLHttpRequest: fetch has no upload progress events, and the
// engine needs them for the progress bar and the stall watchdog. The XMLHttpRequest factory is
// injected so that the transport is testable in Node.
import { TransportError, TUS_VERSION, type HeadResult, type PatchResult, type UploadTransport } from './tus';

/** Subset of XMLHttpRequest used by the transport. */
export interface XhrLike {
  open(method: string, url: string): void;
  setRequestHeader(name: string, value: string): void;
  getResponseHeader(name: string): string | null;
  send(body?: Blob | null): void;
  abort(): void;
  readonly status: number;
  onload: (() => void) | null;
  onerror: (() => void) | null;
  ontimeout: (() => void) | null;
  onabort: (() => void) | null;
  readonly upload: { onprogress: ((event: { loaded: number }) => void) | null };
}

/** Dependencies of the XHR transport. */
export interface XhrTransportDeps {
  /** Current CSRF token (memory only), sent as X-CSRF-Token on PATCH and DELETE. */
  csrfToken: () => string | undefined;
  /** XMLHttpRequest factory (default: new XMLHttpRequest()). */
  createXhr?: () => XhrLike;
}

interface SendOptions {
  body?: Blob;
  headers?: Record<string, string>;
  signal?: AbortSignal | undefined;
  onProgress?: ((sent: number) => void) | undefined;
}

/** Parses a non-negative integer header; undefined when absent or malformed. */
export function parseIntHeader(value: string | null): number | undefined {
  if (value === null || !/^\d+$/.test(value.trim())) {
    return undefined;
  }
  return Number(value.trim());
}

/** Creates the XMLHttpRequest transport of the upload engine. */
export function createXhrTransport(deps: XhrTransportDeps): UploadTransport {
  const createXhr = deps.createXhr ?? (() => new XMLHttpRequest() as unknown as XhrLike);

  function send(method: string, url: string, options: SendOptions, unsafe: boolean): Promise<XhrLike> {
    return new Promise((resolve, reject) => {
      const { signal } = options;
      if (signal?.aborted) {
        reject(new TransportError('aborted', true));
        return;
      }
      const xhr = createXhr();
      const onAbortSignal = (): void => xhr.abort();
      const cleanup = (): void => signal?.removeEventListener('abort', onAbortSignal);
      xhr.onload = () => {
        cleanup();
        if (xhr.status === 0) {
          reject(new TransportError('network error'));
          return;
        }
        resolve(xhr);
      };
      xhr.onerror = () => {
        cleanup();
        reject(new TransportError('network error'));
      };
      xhr.ontimeout = () => {
        cleanup();
        reject(new TransportError('timeout'));
      };
      xhr.onabort = () => {
        cleanup();
        reject(new TransportError('aborted', true));
      };
      if (options.onProgress !== undefined) {
        const onProgress = options.onProgress;
        xhr.upload.onprogress = (event) => onProgress(event.loaded);
      }
      signal?.addEventListener('abort', onAbortSignal);
      xhr.open(method, url);
      xhr.setRequestHeader('Tus-Resumable', TUS_VERSION);
      const token = deps.csrfToken();
      if (unsafe && token !== undefined) {
        xhr.setRequestHeader('X-CSRF-Token', token);
      }
      for (const [name, value] of Object.entries(options.headers ?? {})) {
        xhr.setRequestHeader(name, value);
      }
      xhr.send(options.body ?? null);
    });
  }

  return {
    async head(url, signal): Promise<HeadResult> {
      const xhr = await send('HEAD', url, { signal }, false);
      const result: HeadResult = { status: xhr.status };
      if (xhr.status === 200) {
        result.offset = parseIntHeader(xhr.getResponseHeader('Upload-Offset'));
        result.length = parseIntHeader(xhr.getResponseHeader('Upload-Length'));
      } else {
        result.retryAfterSeconds = parseIntHeader(xhr.getResponseHeader('Retry-After'));
      }
      return result;
    },

    async patch(url, offset, body, options = {}): Promise<PatchResult> {
      const xhr = await send(
        'PATCH',
        url,
        {
          body,
          signal: options.signal,
          onProgress: options.onProgress,
          headers: {
            'Content-Type': 'application/offset+octet-stream',
            'Upload-Offset': String(offset),
          },
        },
        true,
      );
      const result: PatchResult = { status: xhr.status };
      if (xhr.status === 204) {
        result.offset = parseIntHeader(xhr.getResponseHeader('Upload-Offset'));
      } else {
        result.retryAfterSeconds = parseIntHeader(xhr.getResponseHeader('Retry-After'));
      }
      return result;
    },

    async terminate(url): Promise<{ status: number }> {
      const xhr = await send('DELETE', url, {}, true);
      return { status: xhr.status };
    },
  };
}
