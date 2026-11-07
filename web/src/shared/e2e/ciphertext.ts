// Fetch and streaming decryption of one ciphertext of an end-to-end encrypted transfer, shared by
// the Service Worker (e2e-sw/handler.ts) and the in-memory fallback of the page (download.ts).
import { createDecryptStream } from './decrypt';
import { isE2EError } from './errors';
import { Sha256, toHex } from './sha256';
import type { FailureCode, SwFile } from './sw-protocol';

/** Failure carrying the stable code reported to the page. */
export class DownloadFailure extends Error {
  readonly code: FailureCode;

  constructor(code: FailureCode, detail: string) {
    super(`e2e download: ${code}: ${detail}`);
    this.name = 'DownloadFailure';
    this.code = code;
  }
}

/** Code of an error: a DownloadFailure its own, TTE2 errors corrupt, anything else network. */
export function failureCode(err: unknown): FailureCode {
  if (err instanceof DownloadFailure) return err.code;
  return isE2EError(err) ? 'corrupt' : 'network';
}

/** The fetch function used (the global one, or a fake in the tests). */
export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

/**
 * Fetches the ciphertext at url: same origin, cookies included (unlock and recipient
 * verification), no redirect, no cache. The answer must be a 200 application/octet-stream with a
 * body. 401, 403, 404 and 410 (expired access, deleted transfer, download limit) are unavailable,
 * a fetch failure or another status network, another media type corrupt.
 */
export async function openCiphertext(url: string, fetchFn: FetchLike): Promise<ReadableStream<Uint8Array>> {
  let resp: Response;
  try {
    resp = await fetchFn(url, { credentials: 'same-origin', redirect: 'error', cache: 'no-store' });
  } catch (err) {
    throw new DownloadFailure('network', String(err));
  }
  if (resp.status !== 200) {
    void resp.body?.cancel().catch(() => undefined);
    const gone = [401, 403, 404, 410].includes(resp.status);
    throw new DownloadFailure(gone ? 'unavailable' : 'network', `status ${resp.status}`);
  }
  const type = (resp.headers.get('Content-Type') ?? '').split(';')[0]!.trim().toLowerCase();
  const body = resp.body;
  if (type === 'application/octet-stream' && body !== null) {
    return body;
  }
  void body?.cancel().catch(() => undefined);
  throw new DownloadFailure('corrupt', `unexpected media type ${type} or no body`);
}

/**
 * Returns a pass-through stream computing the SHA-256 of what crosses it; it errors with corrupt
 * instead of closing when the digest differs from expected (lowercase hexadecimal).
 */
export function sha256Check(expected: string): TransformStream<Uint8Array, Uint8Array> {
  const hash = new Sha256();
  return new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      hash.update(chunk);
      controller.enqueue(chunk);
    },
    flush() {
      if (toHex(hash.digest()) !== expected) {
        throw new DownloadFailure('corrupt', 'plaintext SHA-256 differs from the sealed metadata');
      }
    },
  });
}

/**
 * Decrypts the ciphertext of file chunk by chunk, checking in flight its plaintext size and, at
 * the end, its SHA-256 against the sealed metadata: the stream errors instead of closing on any
 * mismatch, authentication failure or truncation.
 */
export function decryptFile(
  ciphertext: ReadableStream<Uint8Array>,
  file: SwFile,
): ReadableStream<Uint8Array> {
  return ciphertext
    .pipeThrough(createDecryptStream({ key: file.key, index: file.index }, { expectedPlainSize: file.size }))
    .pipeThrough(sha256Check(file.sha256));
}
