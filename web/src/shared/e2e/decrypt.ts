// Decryption of a TTE2 file stream (docs/architecture/e2e-format.md section 2.4), mirroring the Go
// Reader (internal/tte2/reader.go) and its error classification, so that the vectors give the same
// results everywhere.
//
// Key handover to a Service Worker: the file key depends on the salt of the header, which is only
// known once the first 32 bytes of the stream have arrived, so the page cannot derive it in
// advance. The page therefore posts the transfer key as the non-extractable HKDF base CryptoKey of
// importTransferKey, with the file index: { key: baseKey, index }. The Service Worker derives the
// file key itself after reading the header and never holds the bytes of K. A caller with another
// key policy passes a callback receiving the parsed header instead.

import { E2EError } from './errors';
import {
  HEADER_SIZE,
  TAG_SIZE,
  MAX_CHUNKS,
  KEY_SIZE,
  checkIndex,
  chunkNonce,
  concatBytes,
  deriveFileKey,
  parseHeader,
  type TTE2Header,
  type TransferKey,
} from './tte2';

/**
 * Source of the file key of a stream: the transfer key and the file index (the decryptor derives
 * the key once the header is read), or a callback deriving it from the parsed header.
 */
export type FileKeySource =
  { readonly key: TransferKey; readonly index: number } | ((header: TTE2Header) => Promise<CryptoKey>);

/** Options of a decryptor. */
export interface DecryptOptions {
  /**
   * Plaintext size announced by the sealed metadata. When set, the stream fails with
   * size-mismatch as soon as more plaintext would be produced, or at the end if less was.
   */
  expectedPlainSize?: number;
}

/** FIFO of byte arrays, read without copying more than what is taken. */
class ByteQueue {
  private readonly parts: Uint8Array[] = [];
  private head = 0;
  /** Number of bytes queued. */
  length = 0;

  push(b: Uint8Array): void {
    if (b.length === 0) return;
    this.parts.push(b);
    this.length += b.length;
  }

  /** Removes and returns the first n bytes (n <= length). */
  take(n: number): Uint8Array<ArrayBuffer> {
    const out = new Uint8Array(n);
    let o = 0;
    while (o < n) {
      const p = this.parts[0]!;
      const m = Math.min(p.length - this.head, n - o);
      out.set(p.subarray(this.head, this.head + m), o);
      o += m;
      this.head += m;
      if (this.head === p.length) {
        this.parts.shift();
        this.head = 0;
      }
    }
    this.length -= n;
    return out;
  }
}

/**
 * Incremental decryptor of one TTE2 stream. push accepts ciphertext pieces of any size and returns
 * the plaintext of every chunk authenticated so far; finish authenticates the final chunk. Only
 * authenticated plaintext is returned, but a stream is complete and unaltered only once finish has
 * resolved: on any error the caller must discard everything already produced (fail closed). It
 * buffers at most one encrypted chunk, one look-ahead byte and the piece being pushed. Errors are
 * sticky. Not safe for concurrent calls: await each call before the next.
 */
export class StreamDecryptor {
  /** Number of chunks authenticated so far (the counter of the next chunk). */
  counter = 0;
  private readonly queue = new ByteQueue();
  private readonly keySource: (header: TTE2Header) => Promise<CryptoKey>;
  private readonly expected: number | undefined;
  private header: TTE2Header | undefined;
  private fileKey: CryptoKey | undefined;
  private produced = 0;
  private error: unknown;
  private done = false;

  /**
   * Creates a decryptor. A key given as bytes must be 32 bytes and the index in [0, MAX_INDEX]
   * (invalid-key, invalid-index); expectedPlainSize must be a non-negative safe integer.
   */
  constructor(source: FileKeySource, options: DecryptOptions = {}) {
    if (typeof source === 'function') {
      this.keySource = source;
    } else {
      const { key, index } = source;
      checkIndex(index);
      if (key instanceof Uint8Array && key.length !== KEY_SIZE) {
        throw new E2EError('invalid-key', `${key.length} bytes`);
      }
      this.keySource = (h) => deriveFileKey(key, h.salt, index);
    }
    const e = options.expectedPlainSize;
    if (e !== undefined && (!Number.isSafeInteger(e) || e < 0)) {
      throw new RangeError(`tte2: invalid expected plaintext size ${e}`);
    }
    this.expected = e;
  }

  /** The parsed header, once the first 32 bytes have been pushed. */
  get parsedHeader(): TTE2Header | undefined {
    return this.header;
  }

  /**
   * Feeds ciphertext and returns the plaintext of the chunks it completes (middle chunks only).
   * piece is kept by reference until consumed: the caller must not modify it afterwards.
   */
  async push(piece: Uint8Array): Promise<Uint8Array<ArrayBuffer>[]> {
    return this.guard(async () => {
      if (this.done) throw new Error('tte2: decryptor already finished');
      this.queue.push(piece);
      const out: Uint8Array<ArrayBuffer>[] = [];
      if (this.header === undefined) {
        if (this.queue.length < HEADER_SIZE) return out;
        const header = parseHeader(this.queue.take(HEADER_SIZE));
        this.fileKey = await this.keySource(header);
        this.header = header;
      }
      const blockLen = this.header.chunkSize + TAG_SIZE;
      // A full chunk followed by at least one more byte is a middle chunk.
      while (this.queue.length > blockLen) out.push(await this.middle(this.queue.take(blockLen)));
      return out;
    });
  }

  /** Ends the stream: authenticates the final chunk and returns its plaintext. */
  async finish(): Promise<Uint8Array<ArrayBuffer>> {
    return this.guard(async () => {
      if (this.done) throw new Error('tte2: decryptor already finished');
      this.done = true;
      if (this.header === undefined) throw new E2EError('truncated', 'header');
      const plain = await this.final(this.queue.take(this.queue.length));
      if (this.expected !== undefined && this.produced !== this.expected) {
        throw new E2EError('size-mismatch', `${this.produced} bytes, expected ${this.expected}`);
      }
      return plain;
    });
  }

  /** Runs f, making any error sticky. */
  private async guard<T>(f: () => Promise<T>): Promise<T> {
    if (this.error !== undefined) throw this.error;
    try {
      return await f();
    } catch (err) {
      this.error = err;
      throw err;
    }
  }

  /** Opens a chunk followed by more data (Go Reader.next, first branch). */
  private async middle(chunk: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
    if (this.counter === MAX_CHUNKS - 1) throw new E2EError('counter-overflow', `chunk ${this.counter}`);
    const plain = await this.open(chunk, false);
    if (plain === null) {
      if ((await this.open(chunk, true)) !== null) {
        throw new E2EError('trailing-data', `after chunk ${this.counter}`);
      }
      throw new E2EError('auth', `chunk ${this.counter}`);
    }
    this.counter++;
    return this.account(plain);
  }

  /** Opens the chunk ending the stream (Go Reader.next, second branch). */
  private async final(chunk: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
    if (chunk.length < TAG_SIZE) throw new E2EError('truncated', `chunk ${this.counter}`);
    if (chunk.length === TAG_SIZE && this.counter > 0) {
      throw new E2EError('format', `empty final chunk ${this.counter}`);
    }
    const plain = await this.open(chunk, true);
    if (plain === null) {
      if (chunk.length === this.header!.chunkSize + TAG_SIZE && (await this.open(chunk, false)) !== null) {
        throw new E2EError('truncated', `missing final chunk ${this.counter + 1}`);
      }
      throw new E2EError('auth', `chunk ${this.counter}`);
    }
    return this.account(plain);
  }

  /** Counts produced plaintext against the expected size. */
  private account(plain: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
    this.produced += plain.length;
    if (this.expected !== undefined && this.produced > this.expected) {
      throw new E2EError('size-mismatch', `more than ${this.expected} bytes`);
    }
    return plain;
  }

  /** Authenticates and decrypts chunk this.counter with the given last flag, or returns null. */
  private async open(chunk: Uint8Array<ArrayBuffer>, last: boolean): Promise<Uint8Array<ArrayBuffer> | null> {
    try {
      const plain = await globalThis.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: chunkNonce(this.counter, last),
          additionalData: this.header!.bytes,
          tagLength: 128,
        },
        this.fileKey!,
        chunk,
      );
      return new Uint8Array(plain);
    } catch {
      return null;
    }
  }
}

/**
 * Returns a TransformStream decrypting a TTE2 stream: it consumes the raw ciphertext (pieces of
 * any size, e.g. a fetch body) and emits authenticated plaintext, one chunk at a time. Any failure
 * (bad header, authentication, truncation, trailing data, size mismatch) errors the stream with an
 * E2EError; the consumer must then discard what it already received. Constructor errors
 * (invalid key bytes, index or expected size) are thrown synchronously.
 */
export function createDecryptStream(
  source: FileKeySource,
  options: DecryptOptions = {},
): TransformStream<Uint8Array, Uint8Array<ArrayBuffer>> {
  const d = new StreamDecryptor(source, options);
  return new TransformStream<Uint8Array, Uint8Array<ArrayBuffer>>({
    async transform(piece, controller) {
      for (const plain of await d.push(piece)) controller.enqueue(plain);
    },
    async flush(controller) {
      const plain = await d.finish();
      if (plain.length > 0) controller.enqueue(plain);
    },
  });
}

/** Decrypts a whole TTE2 stream held in memory (small files and tests). */
export async function decryptBytes(
  source: FileKeySource,
  ciphertext: Uint8Array,
  options: DecryptOptions = {},
): Promise<Uint8Array<ArrayBuffer>> {
  const d = new StreamDecryptor(source, options);
  const parts = await d.push(ciphertext);
  parts.push(await d.finish());
  return concatBytes(...parts);
}
