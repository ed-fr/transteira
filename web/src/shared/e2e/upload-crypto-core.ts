// Encryption side of an end-to-end encrypted upload (docs/architecture/e2e-format.md), shared by
// the dedicated Worker (upload-crypto-serve.ts) and the in-thread fallback (upload-crypto.ts):
// the SHA-256 pass over each plaintext file, then the range encryptor of each file, called by the
// upload engine for every tus chunk. It also defines the messages exchanged with the Worker.
//
// Nonce reuse guard: the encryption of a file is deterministic once its header salt is drawn
// (the same key, salt and counter give the same nonce), which is what lets a tus upload resume.
// Encrypting a different plaintext under the same nonces would break AES-GCM, so the hash pass
// also keeps the SHA-256 of every TTE2 chunk of plaintext (32 bytes per chunk), and every chunk
// read later for a range is hashed again and compared before it is encrypted: a file changed on
// disk since the hash pass fails with a FileChangedError and its chunk is never encrypted. A file
// must be hashed (with the chunk size of its stream) before it can be prepared.
//
// No DOM API is used: the code runs unchanged in a window and in a dedicated Worker.

import { E2EError, type E2EErrorCode } from './errors';
import { Sha256, toHex } from './sha256';
import { prepareFileEncryption, validChunkSize, type FileEncryption, type TransferKey } from './tte2';

/** Size of the plaintext slices read by the hash pass (8 MiB: few reads, bounded memory). */
export const HASH_SLICE_SIZE = 8 * 1024 * 1024;

/** Error thrown when an operation was aborted (same name as the DOM AbortError). */
export function abortError(): Error {
  const err = new Error('aborted');
  err.name = 'AbortError';
  return err;
}

/** Reports whether err is an abort (abortError or a DOMException AbortError). */
export function isAbortError(err: unknown): boolean {
  return err instanceof Error && err.name === 'AbortError';
}

/** Name of the error raised when a file changed since its hash pass (kept across postMessage). */
export const FILE_CHANGED_ERROR = 'FileChangedError';

/** Error raised when the plaintext of a chunk differs from the one hashed by the hash pass. */
export class FileChangedError extends Error {
  constructor(index: number, counter: number) {
    super(`upload crypto: file ${index} changed since it was hashed (chunk ${counter})`);
    this.name = FILE_CHANGED_ERROR;
  }
}

/** Reports whether err is a FileChangedError (also once rebuilt from a Worker answer). */
export function isFileChangedError(err: unknown): boolean {
  return err instanceof Error && err.name === FILE_CHANGED_ERROR;
}

/** Size of a SHA-256 digest. */
const DIGEST_SIZE = 32;

/** SHA-256 of every plaintext chunk of a file, recorded by the hash pass. */
interface ChunkDigests {
  chunkSize: number;
  size: number;
  /** DIGEST_SIZE bytes per chunk, in order. */
  digests: Uint8Array<ArrayBuffer>;
}

async function digest(data: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', data));
}

/**
 * Hashing and encryption state of one transfer. The key is held as given (the Worker receives the
 * non-extractable CryptoKey of importTransferKey, never the bytes of K).
 */
export class UploadCryptoCore {
  readonly #key: TransferKey;
  readonly #files = new Map<number, FileEncryption>();
  readonly #digests = new Map<number, ChunkDigests>();

  constructor(key: TransferKey) {
    this.#key = key;
  }

  /**
   * Returns the lowercase hexadecimal SHA-256 of file index, read in HASH_SLICE_SIZE slices, and
   * records the SHA-256 of each of its plaintext chunks of chunkSize bytes (the chunk size of its
   * TTE2 stream), checked later by range. onProgress receives the number of bytes hashed so far
   * after each slice; aborted is checked before each slice (AbortError).
   */
  async hash(
    index: number,
    file: Blob,
    chunkSize: number,
    onProgress: (bytes: number) => void,
    aborted: () => boolean,
  ): Promise<string> {
    this.#digests.delete(index);
    // Every valid chunk size divides HASH_SLICE_SIZE: a slice holds whole chunks.
    if (!validChunkSize(chunkSize)) throw new E2EError('invalid-chunk-size', String(chunkSize));
    const size = file.size;
    const count = Math.max(1, Math.ceil(size / chunkSize));
    const digests = new Uint8Array(count * DIGEST_SIZE);
    if (size === 0) digests.set(await digest(new Uint8Array(0)));
    const hasher = new Sha256();
    for (let at = 0; at < size;) {
      if (aborted()) throw abortError();
      const end = Math.min(at + HASH_SLICE_SIZE, size);
      const slice = new Uint8Array(await file.slice(at, end).arrayBuffer());
      hasher.update(slice);
      for (let o = 0; o < slice.length; o += chunkSize) {
        const chunk = slice.subarray(o, Math.min(o + chunkSize, slice.length));
        digests.set(await digest(chunk), ((at + o) / chunkSize) * DIGEST_SIZE);
      }
      at = end;
      onProgress(at);
      // Let the event loop run between slices: an abort message (Worker) or the page (in-thread
      // fallback) is handled before the next slice.
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    if (aborted()) throw abortError();
    this.#digests.set(index, { chunkSize, size, digests });
    return toHex(hasher.digest());
  }

  /**
   * Derives the key of file index with the given header salt and keeps its range encryptor.
   * Returns the size of the encrypted stream (the size declared to the server). The file must
   * have been hashed with the same chunk size and size; every chunk the encryptor reads is
   * checked against its recorded SHA-256 (FileChangedError on a difference).
   */
  async prepare(index: number, file: Blob, salt: Uint8Array, chunkSize: number): Promise<number> {
    const known = this.#digests.get(index);
    if (known === undefined || known.chunkSize !== chunkSize) {
      throw new Error(`upload crypto: file ${index} not hashed`);
    }
    if (known.size !== file.size) throw new FileChangedError(index, 0);
    const verifyChunk = async (counter: number, plain: Uint8Array<ArrayBuffer>): Promise<void> => {
      const expected = known.digests.subarray(counter * DIGEST_SIZE, (counter + 1) * DIGEST_SIZE);
      const actual = await digest(plain);
      if (expected.length !== DIGEST_SIZE || !actual.every((b, i) => b === expected[i])) {
        throw new FileChangedError(index, counter);
      }
    };
    const enc = await prepareFileEncryption(this.#key, index, file, { chunkSize, salt, verifyChunk });
    this.#files.set(index, enc);
    return enc.size;
  }

  /** Returns the bytes [start, end) of the encrypted stream of file index (prepared first). */
  async range(index: number, start: number, end: number): Promise<Uint8Array<ArrayBuffer>> {
    const enc = this.#files.get(index);
    if (enc === undefined) throw new Error(`upload crypto: file ${index} not prepared`);
    return enc.range(start, end);
  }

  /** Forgets every file (encryptors and chunk digests). */
  clear(): void {
    this.#files.clear();
    this.#digests.clear();
  }
}

// ---- Messages between the page and the Worker --------------------------------------------------

/** Request posted to the Worker; id identifies the answer. */
export type CryptoRequest =
  | { id: number; op: 'init'; key: TransferKey }
  | { id: number; op: 'hash'; index: number; file: Blob; chunkSize: number }
  | { id: number; op: 'prepare'; index: number; file: Blob; salt: Uint8Array; chunkSize: number }
  | { id: number; op: 'range'; index: number; start: number; end: number }
  /** Aborts the hash request target (no answer of its own). */
  | { id: number; op: 'abort'; target: number };

/** Answer of the Worker to the request id. */
export type CryptoResponse =
  | { id: number; kind: 'progress'; bytes: number }
  /** value: SHA-256 hex (hash), stream size (prepare), ArrayBuffer of the range (range). */
  | { id: number; kind: 'ok'; value?: string | number | ArrayBuffer }
  | { id: number; kind: 'error'; name: string; message: string; code?: E2EErrorCode };

/** Serializes an error for postMessage (structured clone loses the class). */
export function errorResponse(id: number, err: unknown): CryptoResponse {
  if (err instanceof E2EError) {
    return { id, kind: 'error', name: err.name, message: err.message, code: err.code };
  }
  const e = err instanceof Error ? err : new Error(String(err));
  return { id, kind: 'error', name: e.name, message: e.message };
}

/** Rebuilds the error of an error response. */
export function responseError(r: { name: string; message: string; code?: E2EErrorCode }): Error {
  if (r.code !== undefined) {
    const err = new E2EError(r.code);
    err.message = r.message;
    return err;
  }
  const err = new Error(r.message);
  err.name = r.name;
  return err;
}
