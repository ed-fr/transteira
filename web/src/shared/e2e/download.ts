// Page side of the end-to-end encrypted downloads (CLAUDE.md section 22). Files are decrypted in
// the browser, never by the server, and delivered as ordinary downloads:
//
//   - with a Service Worker (e2e-sw/sw.ts, served as /e2e-sw.js, scope /e2e/), in streaming,
//     whatever the size: the page registers the file (or the archive) under a random id over a
//     MessageChannel, with the non-extractable HKDF base key of K (never K itself: the file key
//     depends on the salt of the ciphertext header, so the worker derives it), then navigates to
//     /e2e/<id>. A navigation is always routed to the worker whose scope contains the target URL,
//     in Chromium, Firefox and Safari alike, while a request of the page itself (fetch, or an
//     <a download> in some browsers) only goes to the worker controlling the page, which /d/...
//     is not. The worker answers with Content-Disposition: attachment, so the browser saves the
//     file and the page stays; a failure before streaming is answered 204, which also leaves the
//     page as it is. Progress and errors come back on the reply port;
//   - without a Service Worker (none, registration refused as in some private modes, worker not
//     activated in time): the ciphertext is fetched and decrypted in memory, checked, and saved
//     through a blob: URL, up to MEMORY_LIMIT bytes of plaintext (per file, or for the whole
//     archive); beyond, unsupported-browser. The ciphertext is decrypted as it arrives (only the
//     plaintext is kept) and capped at the largest stream size its declared size allows.
//
// Downloads are serialized: a download waits until the previous one has started (or failed)
// before it registers and navigates, because a navigation started before the worker answered
// the previous one would cancel it.
//
// Every browser dependency is injected (DownloadDeps), so that the logic runs in the unit tests.
import { ARCHIVE_NAME, safeFileName, validEntryNames } from './archive-names';
import { encodeBase64Url } from './base64url';
import { DownloadFailure, decryptFile, failureCode, openCiphertext, type FetchLike } from './ciphertext';
import { MIN_CHUNK_SIZE, ciphertextSize } from './tte2';
import { createZipStream } from './zip';
import {
  SW_SCOPE,
  SW_URL,
  entryUrl,
  type FailureCode,
  type RegisterMessage,
  type SwEntry,
  type SwFile,
  type SwReply,
} from './sw-protocol';

/** Largest plaintext decrypted in memory without a Service Worker (512 MiB). */
export const MEMORY_LIMIT = 512 * 1024 * 1024;

/** Time allowed for the Service Worker to activate after its registration. */
export const ACTIVATION_TIMEOUT_MS = 10_000;

/**
 * Time allowed between the navigation and the start of the response by the worker; beyond, the
 * download is reported unavailable (the page reloads the transfer).
 */
export const START_TIMEOUT_MS = 30_000;

/** Delay before a blob: URL of the fallback is revoked (the browser has started the save). */
export const REVOKE_DELAY_MS = 60_000;

/**
 * Stable code of a download failure: wrong-key (the key does not open the transfer), corrupt
 * (authentication, truncation, size or fingerprint mismatch), unsupported-browser (no Service
 * Worker and too large for memory), network, unavailable (access expired, transfer gone or
 * download limit reached: reload the page), cancelled (by the user, not an error to show).
 */
export type DownloadErrorCode = 'wrong-key' | 'unsupported-browser' | FailureCode;

/** Error of a download, with its stable code. */
export class E2EDownloadError extends Error {
  readonly code: DownloadErrorCode;

  constructor(code: DownloadErrorCode, detail?: string) {
    super(detail === undefined ? `e2e download: ${code}` : `e2e download: ${code}: ${detail}`);
    this.name = 'E2EDownloadError';
    this.code = code;
  }
}

/** Progress of one download, reported to the page. */
export interface DownloadEvents {
  /**
   * Called once the browser has the file: the worker answered and streams it, or the fallback
   * handed the blob to the browser. The next download may start from then on.
   */
  onStarted?: () => void;
}

/** One encrypted file to download, as described by its sealed metadata. */
export interface DownloadFile {
  /** Same-origin ciphertext URL (downloadUrl of the API). */
  url: string;
  /** 0-based index of the file in the transfer. */
  index: number;
  /** Name to save the file under, or its entry path inside an archive. */
  name: string;
  /** Plaintext size (sealed metadata). */
  size: number;
  /** Plaintext SHA-256, lowercase hexadecimal (sealed metadata). */
  sha256: string;
}

/** The part of a ServiceWorker the page uses. */
export interface WorkerLike {
  readonly state: string;
  postMessage(message: RegisterMessage, transfer: Transferable[]): void;
  addEventListener(type: 'statechange', listener: () => void): void;
}

/** The part of a ServiceWorkerRegistration the page uses. */
export interface RegistrationLike {
  readonly active: WorkerLike | null;
  readonly waiting: WorkerLike | null;
  readonly installing: WorkerLike | null;
}

/** The part of navigator.serviceWorker the page uses. */
export interface ServiceWorkerContainerLike {
  register(url: string, options: { scope: string }): Promise<RegistrationLike>;
}

/** The page end of a MessageChannel and the port handed to the worker. */
export interface ChannelLike {
  port1: { onmessage: ((event: { data: unknown }) => void) | null; close(): void };
  port2: Transferable;
}

/** Browser dependencies of the downloader. */
export interface DownloadDeps {
  /** navigator.serviceWorker, undefined when the browser has none. */
  serviceWorker: ServiceWorkerContainerLike | undefined;
  fetch: FetchLike;
  /** Navigates the page to a same-origin URL (location.assign). */
  navigate(url: string): void;
  /** Saves a blob under name (blob: URL and a temporary <a download>). */
  saveBlob(blob: Blob, name: string): void;
  /** Returns a new MessageChannel. */
  channel(): ChannelLike;
  /** Returns 16 random bytes. */
  random(): Uint8Array;
  setTimeout(handler: () => void, ms: number): unknown;
  clearTimeout(id: unknown): void;
}

/** Dependencies of a real browser page. */
export function browserDeps(): DownloadDeps {
  return {
    serviceWorker: 'serviceWorker' in navigator ? navigator.serviceWorker : undefined,
    fetch: (input, init) => fetch(input, init),
    navigate: (url) => window.location.assign(url),
    saveBlob: (blob, name) => {
      const href = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = href;
      a.download = name;
      a.hidden = true;
      document.body.append(a);
      a.click();
      a.remove();
      // Revoked later, not at once: Firefox reads the URL after the click returns.
      window.setTimeout(() => URL.revokeObjectURL(href), REVOKE_DELAY_MS);
    },
    channel: () => new MessageChannel() as unknown as ChannelLike,
    random: () => crypto.getRandomValues(new Uint8Array(16)),
    setTimeout: (handler, ms) => window.setTimeout(handler, ms),
    clearTimeout: (id) => window.clearTimeout(id as number),
  };
}

/** Downloads the decrypted files of an end-to-end encrypted transfer. */
export class E2EDownloader {
  private worker: Promise<WorkerLike | undefined> | undefined;
  /** Settled once the last download requested has started or failed. */
  private gate: Promise<void> = Promise.resolve();

  constructor(private readonly deps: DownloadDeps = browserDeps()) {}

  /** Downloads one file, saved under its (sanitized) name. Rejects with an E2EDownloadError. */
  async downloadFile(key: CryptoKey, file: DownloadFile, events: DownloadEvents = {}): Promise<void> {
    const swFile = toSwFile(key, file);
    swFile.name = safeFileName(file.name);
    await this.run({ kind: 'file', file: swFile }, events, (started) => this.memoryFile(swFile, started));
  }

  /**
   * Downloads the files as one ZIP archive built in the browser; each file name is its entry path
   * (archive-names.ts archiveEntries). Rejects with an E2EDownloadError.
   */
  async downloadArchive(
    key: CryptoKey,
    files: readonly DownloadFile[],
    name = ARCHIVE_NAME,
    events: DownloadEvents = {},
  ): Promise<void> {
    const swFiles = files.map((f) => toSwFile(key, f));
    await this.run({ kind: 'archive', name, files: swFiles }, events, (started) =>
      this.memoryArchive(name, swFiles, started),
    );
  }

  private async run(
    entry: SwEntry,
    events: DownloadEvents,
    fallback: (started: () => void) => Promise<void>,
  ): Promise<void> {
    const previous = this.gate;
    let open!: () => void;
    this.gate = new Promise<void>((resolve) => {
      open = resolve;
    });
    let started = false;
    const onStarted = (): void => {
      if (started) return;
      started = true;
      open();
      events.onStarted?.();
    };
    try {
      await previous;
      const worker = await this.activeWorker();
      if (worker === undefined) {
        await fallback(onStarted);
      } else {
        await this.viaWorker(worker, entry, onStarted);
      }
    } catch (err) {
      if (err instanceof E2EDownloadError) throw err;
      throw new E2EDownloadError(failureCode(err), String(err));
    } finally {
      open();
    }
  }

  /** The active Service Worker, registered once; undefined when unavailable (fallback). */
  private activeWorker(): Promise<WorkerLike | undefined> {
    this.worker ??= this.register().catch(() => undefined);
    return this.worker;
  }

  private async register(): Promise<WorkerLike | undefined> {
    const container = this.deps.serviceWorker;
    if (container === undefined) return undefined;
    const reg = await container.register(SW_URL, { scope: SW_SCOPE });
    if (reg.active !== null) return reg.active;
    const pending = reg.installing ?? reg.waiting;
    if (pending === null) return undefined;
    return new Promise<WorkerLike | undefined>((resolve) => {
      const timer = this.deps.setTimeout(() => resolve(undefined), ACTIVATION_TIMEOUT_MS);
      pending.addEventListener('statechange', () => {
        if (pending.state === 'activated' || pending.state === 'redundant') {
          this.deps.clearTimeout(timer);
          resolve(pending.state === 'activated' ? pending : undefined);
        }
      });
    });
  }

  /** Registers the entry with the worker, navigates to it and waits for the end of the stream. */
  private viaWorker(worker: WorkerLike, entry: SwEntry, onStarted: () => void): Promise<void> {
    const id = encodeBase64Url(this.deps.random());
    const channel = this.deps.channel();
    return new Promise<void>((resolve, reject) => {
      let timer: unknown;
      const finish = (err?: E2EDownloadError): void => {
        this.deps.clearTimeout(timer);
        channel.port1.onmessage = null;
        channel.port1.close();
        if (err === undefined) resolve();
        else reject(err);
      };
      channel.port1.onmessage = (event) => {
        const reply = event.data as SwReply;
        switch (reply.type) {
          case 'registered':
            timer = this.deps.setTimeout(
              () => finish(new E2EDownloadError('unavailable', 'the worker did not answer')),
              START_TIMEOUT_MS,
            );
            this.deps.navigate(entryUrl(id));
            break;
          case 'rejected':
            finish(new E2EDownloadError('corrupt', 'entry rejected by the worker'));
            break;
          case 'started':
            this.deps.clearTimeout(timer);
            onStarted();
            break;
          case 'done':
            finish();
            break;
          case 'failed':
            finish(new E2EDownloadError(reply.code));
            break;
        }
      };
      worker.postMessage({ type: 'register', id, entry }, [channel.port2]);
    });
  }

  /**
   * Fetches, decrypts and checks one file in memory, chunk by chunk: only the plaintext parts are
   * kept, and a ciphertext longer than the largest stream its declared size allows (the smallest
   * chunk size has the most tags) is corrupt, so that a hostile answer cannot exhaust the memory.
   */
  private async decryptInMemory(file: SwFile): Promise<Uint8Array[]> {
    const body = await openCiphertext(file.url, this.deps.fetch);
    const capped = body.pipeThrough(byteCap(ciphertextSize(file.size, MIN_CHUNK_SIZE)));
    const reader = decryptFile(capped, file).getReader();
    const parts: Uint8Array[] = [];
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return parts;
      parts.push(value);
    }
  }

  private async memoryFile(file: SwFile, started: () => void): Promise<void> {
    if (file.size > MEMORY_LIMIT) throw new E2EDownloadError('unsupported-browser', 'file too large');
    const parts = await this.decryptInMemory(file);
    this.deps.saveBlob(new Blob(parts as BlobPart[], { type: 'application/octet-stream' }), file.name);
    started();
  }

  private async memoryArchive(name: string, files: readonly SwFile[], started: () => void): Promise<void> {
    if (files.reduce((n, f) => n + f.size, 0) > MEMORY_LIMIT) {
      throw new E2EDownloadError('unsupported-browser', 'archive too large');
    }
    // The same check as the Service Worker on a registration (the names come from the sender).
    if (files.length === 0 || !validEntryNames(files.map((f) => f.name))) {
      throw new E2EDownloadError('corrupt', 'invalid archive entry names');
    }
    const decrypted: Uint8Array[][] = [];
    for (const f of files) decrypted.push(await this.decryptInMemory(f));
    const zip = createZipStream(
      files.map((f, i) => ({ name: f.name, size: f.size, data: drain(decrypted, i) })),
    );
    const parts: Uint8Array[] = [];
    const reader = zip.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      parts.push(value);
    }
    this.deps.saveBlob(
      new Blob(parts as BlobPart[], { type: 'application/octet-stream' }),
      safeFileName(name),
    );
    started();
  }
}

/** Pass-through stream erroring corrupt once more than max bytes crossed it. */
export function byteCap(max: number): TransformStream<Uint8Array, Uint8Array> {
  let seen = 0;
  return new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      seen += chunk.length;
      if (seen > max) throw new DownloadFailure('corrupt', `ciphertext longer than ${max} bytes`);
      controller.enqueue(chunk);
    },
  });
}

/** Stream of the parts of file i, each released once read (no copy, no second buffer). */
function drain(decrypted: Uint8Array[][], i: number): ReadableStream<Uint8Array> {
  const parts = decrypted[i]!;
  decrypted[i] = [];
  let next = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (next >= parts.length) {
        controller.close();
        return;
      }
      controller.enqueue(parts[next]!);
      parts[next++] = EMPTY;
    },
  });
}

const EMPTY = new Uint8Array(0);

function toSwFile(key: CryptoKey, f: DownloadFile): SwFile {
  return { url: f.url, key, index: f.index, name: f.name, size: f.size, sha256: f.sha256 };
}
