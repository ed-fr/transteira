// TTE2, the end-to-end encryption format of a transfer (docs/architecture/e2e-format.md), ported
// byte for byte from the Go reference (internal/tte2) and checked against its vectors
// (internal/tte2/testdata/vectors.json). This module holds the transfer key, the key derivation,
// the file header, the size arithmetic and the encryption of a file; decrypt.ts decrypts a file
// stream and sealed.ts seals the metadata and the message.
//
// Only WebCrypto (crypto.subtle, crypto.getRandomValues) is used, through globalThis, so the code
// runs unchanged in a window, a dedicated Worker and a Service Worker.

import { decodeBase64Url, encodeBase64Url } from './base64url';
import { E2EError } from './errors';

/** Size of the transfer key K, in bytes. */
export const KEY_SIZE = 32;
/** Length of K in base64url without padding, as carried by the link fragment "#k=". */
export const ENCODED_KEY_SIZE = 43;
/** Size of a file stream header. */
export const HEADER_SIZE = 32;
/** Size of the random salt of a file stream header. */
export const SALT_SIZE = 16;
/** Size of an AES-GCM authentication tag. */
export const TAG_SIZE = 16;
/** Size of an AES-GCM nonce. */
export const NONCE_SIZE = 12;
/** Magic bytes starting every file stream. */
export const MAGIC = 'TTE2';
/** Format version recorded in the header. */
export const VERSION = 1;
/** Header kind of a file stream. */
export const KIND_FILE = 1;
/** Smallest plaintext chunk size (64 KiB). */
export const MIN_CHUNK_SIZE = 64 * 1024;
/** Largest plaintext chunk size (8 MiB). */
export const MAX_CHUNK_SIZE = 8 * 1024 * 1024;
/** Plaintext chunk size used when none is given (1 MiB). */
export const DEFAULT_CHUNK_SIZE = 1024 * 1024;
/** Size of the smallest valid stream: the header and the empty final chunk of an empty file. */
export const MIN_FILE_SIZE = HEADER_SIZE + TAG_SIZE;
/** Largest number of chunks of a stream (the chunk counter is a 32-bit integer). */
export const MAX_CHUNKS = 2 ** 32;
/** Largest file index. */
export const MAX_INDEX = 2 ** 32 - 1;
/** Largest decoded size of a sealed metadata blob. */
export const MAX_METADATA_SIZE = 4096;
/** Largest length of a sealed metadata blob, in base64url characters. */
export const MAX_METADATA_ENCODED_SIZE = Math.ceil((MAX_METADATA_SIZE * 4) / 3);
/** Largest number of Unicode code points of a message. */
export const MAX_MESSAGE_RUNES = 5000;
/** Largest length of a sealed message, in base64url characters. */
export const MAX_MESSAGE_ENCODED_SIZE = 32768;

/** HKDF info prefix of a file key, followed by the big-endian 32-bit file index. */
export const INFO_FILE = 'transteira/tte2/v1/file';
/** HKDF info prefix of a metadata key, followed by the big-endian 32-bit file index. */
export const INFO_METADATA = 'transteira/tte2/v1/metadata';
/** HKDF info of the message key. */
export const INFO_MESSAGE = 'transteira/tte2/v1/message';
/** HKDF info reserved for the one-time secrets of V2.1 (not used yet). */
export const INFO_SECRET = 'transteira/tte2/v1/secret';

/**
 * A transfer key: either the 32 raw bytes of K or the non-extractable HKDF base key returned by
 * importTransferKey. Every function deriving a key accepts both; passing the CryptoKey keeps K out
 * of reach of the code that holds it (a Worker or the Service Worker receives only the CryptoKey,
 * structured-cloned by postMessage, never the bytes).
 */
export type TransferKey = CryptoKey | Uint8Array;

const encoder = new TextEncoder();

/** Returns a fresh random transfer key of KEY_SIZE bytes. */
export function generateTransferKey(): Uint8Array<ArrayBuffer> {
  return randomBytes(KEY_SIZE);
}

/** Returns n bytes from the cryptographically secure generator. */
export function randomBytes(n: number): Uint8Array<ArrayBuffer> {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

/** Encodes a transfer key in base64url without padding (the "#k=" form). */
export function encodeKey(key: Uint8Array): string {
  if (key.length !== KEY_SIZE) throw new E2EError('invalid-key', `${key.length} bytes`);
  return encodeBase64Url(key);
}

/** Decodes the fragment form of a key: exactly 43 canonical base64url characters, else invalid-key. */
export function parseKey(s: string): Uint8Array<ArrayBuffer> {
  const key = s.length === ENCODED_KEY_SIZE ? decodeBase64Url(s) : null;
  if (key === null) throw new E2EError('invalid-key', 'not a 43-character base64url key');
  return key;
}

/**
 * Parses a key typed or pasted by a recipient: the bare key, "k=<key>", or a whole download link
 * whose fragment holds "k=<key>" (other fragment parameters, separated by "&", are ignored).
 * Surrounding whitespace is ignored. Anything else is invalid-key.
 */
export function parseKeyInput(text: string): Uint8Array<ArrayBuffer> {
  let s = text.trim();
  const hash = s.indexOf('#');
  if (hash >= 0) {
    const param = s
      .slice(hash + 1)
      .split('&')
      .find((p) => p.startsWith('k='));
    if (param === undefined) throw new E2EError('invalid-key', 'no k= parameter in the link fragment');
    s = param;
  }
  if (s.startsWith('k=')) s = s.slice(2);
  return parseKey(s);
}

/**
 * Imports the transfer key as a non-extractable HKDF base key (usages deriveKey and deriveBits).
 * The result can be posted to a Worker or a Service Worker, which can derive the file, metadata
 * and message keys but never read K.
 */
export async function importTransferKey(key: Uint8Array): Promise<CryptoKey> {
  if (key.length !== KEY_SIZE) throw new E2EError('invalid-key', `${key.length} bytes`);
  return globalThis.crypto.subtle.importKey('raw', new Uint8Array(key), 'HKDF', false, [
    'deriveKey',
    'deriveBits',
  ]);
}

/** Returns the HKDF base key of a TransferKey, importing raw bytes; a foreign CryptoKey is invalid-key. */
export async function toBaseKey(key: TransferKey): Promise<CryptoKey> {
  if (key instanceof Uint8Array) return importTransferKey(key);
  if (key.algorithm.name !== 'HKDF' || !key.usages.includes('deriveKey')) {
    throw new E2EError('invalid-key', 'not an HKDF base key');
  }
  return key;
}

/** Checks a file index: an integer in [0, MAX_INDEX], else invalid-index. */
export function checkIndex(index: number): void {
  if (!Number.isInteger(index) || index < 0 || index > MAX_INDEX) {
    throw new E2EError('invalid-index', String(index));
  }
}

/** Returns the 4-byte big-endian encoding of a 32-bit unsigned integer. */
export function u32(n: number): Uint8Array<ArrayBuffer> {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n);
  return b;
}

/** Concatenates byte arrays. */
export function concatBytes(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** Returns label in ASCII followed by the big-endian 32-bit index. */
export function indexedLabel(label: string, index: number): Uint8Array<ArrayBuffer> {
  return concatBytes(encoder.encode(label), u32(index));
}

/**
 * Derives a non-extractable AES-256-GCM key (usages encrypt and decrypt) from the transfer key
 * with HKDF-SHA-256. An empty salt is the RFC 5869 "no salt" (HashLen zero bytes), as Go's nil salt.
 */
export async function deriveAesKey(key: TransferKey, salt: Uint8Array, info: Uint8Array): Promise<CryptoKey> {
  const base = await toBaseKey(key);
  return globalThis.crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(salt), info: new Uint8Array(info) },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** Derives the key of file index: HKDF(K, header salt, INFO_FILE || u32(index)). */
export async function deriveFileKey(key: TransferKey, salt: Uint8Array, index: number): Promise<CryptoKey> {
  checkIndex(index);
  if (salt.length !== SALT_SIZE) throw new E2EError('bad-header', `salt of ${salt.length} bytes`);
  return deriveAesKey(key, salt, indexedLabel(INFO_FILE, index));
}

/** Derives the key of the metadata of file index: HKDF(K, no salt, INFO_METADATA || u32(index)). */
export async function deriveMetadataKey(key: TransferKey, index: number): Promise<CryptoKey> {
  checkIndex(index);
  return deriveAesKey(key, new Uint8Array(0), indexedLabel(INFO_METADATA, index));
}

/** Derives the key of the transfer message: HKDF(K, no salt, INFO_MESSAGE). */
export async function deriveMessageKey(key: TransferKey): Promise<CryptoKey> {
  return deriveAesKey(key, new Uint8Array(0), encoder.encode(INFO_MESSAGE));
}

/** Reports whether c is an accepted chunk size: a power of two in [MIN_CHUNK_SIZE, MAX_CHUNK_SIZE]. */
export function validChunkSize(c: number): boolean {
  return Number.isInteger(c) && c >= MIN_CHUNK_SIZE && c <= MAX_CHUNK_SIZE && (c & (c - 1)) === 0;
}

/** Decoded 32-byte header of a file stream. */
export interface TTE2Header {
  /** Plaintext chunk size C. */
  readonly chunkSize: number;
  /** Random HKDF salt of the file key (16 bytes). */
  readonly salt: Uint8Array<ArrayBuffer>;
  /** The encoded header, also the AAD of every chunk (32 bytes). */
  readonly bytes: Uint8Array<ArrayBuffer>;
}

/**
 * Builds the header of a new file stream. The salt is drawn at random unless given (tests and
 * vectors); a chunk size outside the accepted values is invalid-chunk-size.
 */
export function newHeader(chunkSize: number = DEFAULT_CHUNK_SIZE, salt?: Uint8Array): TTE2Header {
  if (!validChunkSize(chunkSize)) throw new E2EError('invalid-chunk-size', String(chunkSize));
  const s = salt === undefined ? randomBytes(SALT_SIZE) : new Uint8Array(salt);
  if (s.length !== SALT_SIZE) throw new E2EError('bad-header', `salt of ${s.length} bytes`);
  const bytes = new Uint8Array(HEADER_SIZE);
  bytes.set(encoder.encode(MAGIC), 0);
  bytes[4] = VERSION;
  bytes[5] = KIND_FILE;
  new DataView(bytes.buffer).setUint32(8, chunkSize);
  bytes.set(s, 12);
  return { chunkSize, salt: s, bytes };
}

/**
 * Decodes and strictly validates a header, as Go ParseHeader: exactly 32 bytes, magic "TTE2",
 * version 1, kind 1, zero reserved bytes and a valid chunk size. Any violation is bad-header.
 */
export function parseHeader(b: Uint8Array): TTE2Header {
  if (b.length !== HEADER_SIZE) throw new E2EError('bad-header', `${b.length} bytes`);
  for (let i = 0; i < HEADER_SIZE; i++) {
    if (!headerByteValid(i, b[i]!)) throw new E2EError('bad-header', `byte ${i}`);
  }
  const bytes = new Uint8Array(b);
  return { chunkSize: bytes[9]! << 16, salt: bytes.slice(12, 28), bytes };
}

/**
 * Judges header byte i alone (Go checkHeaderPrefix). Every valid chunk size, 2^16 to 2^23, is
 * 00 xx 00 00 in big-endian with xx a power of two, so each of its bytes is checked on its own.
 */
function headerByteValid(i: number, c: number): boolean {
  if (i < 4) return c === MAGIC.charCodeAt(i);
  if (i === 4) return c === VERSION;
  if (i === 5) return c === KIND_FILE;
  if (i === 9) return c !== 0 && (c & (c - 1)) === 0;
  if (i >= 12 && i < 28) return true; // salt
  return c === 0; // reserved bytes 6, 7, 28 to 31 and chunk size bytes 8, 10, 11
}

/** Returns the nonce of chunk counter: seven zero bytes, the big-endian counter and the last flag. */
export function chunkNonce(counter: number, last: boolean): Uint8Array<ArrayBuffer> {
  const n = new Uint8Array(NONCE_SIZE);
  new DataView(n.buffer).setUint32(7, counter);
  n[11] = last ? 1 : 0;
  return n;
}

/** Number of chunks of a plaintext of plain bytes: max(1, ceil(plain / chunk)). */
function chunkCount(plain: number, chunk: number): number {
  return Math.max(1, Math.ceil(plain / chunk));
}

/**
 * Returns the size of the stream that encrypts plain bytes with chunk size chunk
 * (32 + plain + 16 n), or -1 for a negative or non-integer plain, an invalid chunk size or a
 * plaintext that would need more than MAX_CHUNKS chunks (Go CiphertextSize).
 */
export function ciphertextSize(plain: number, chunk: number): number {
  if (!Number.isSafeInteger(plain) || plain < 0 || !validChunkSize(chunk)) return -1;
  if (plain > MAX_CHUNKS * chunk) return -1;
  return HEADER_SIZE + plain + TAG_SIZE * chunkCount(plain, chunk);
}

/**
 * Returns the plaintext size of a stream of total bytes with chunk size chunk, or -1 when total is
 * not a valid stream size (Go PlaintextSize, section 2.3 of the format).
 */
export function plaintextSize(total: number, chunk: number): number {
  if (!Number.isSafeInteger(total) || total < MIN_FILE_SIZE || !validChunkSize(chunk)) return -1;
  const block = chunk + TAG_SIZE;
  const body = total - HEADER_SIZE;
  const q = Math.floor(body / block);
  const rem = body % block;
  let n: number;
  let plain: number;
  if (rem === 0) {
    n = q;
    plain = q * chunk;
  } else if (rem === TAG_SIZE && q === 0) {
    n = 1;
    plain = 0;
  } else if (rem > TAG_SIZE) {
    n = q + 1;
    plain = q * chunk + rem - TAG_SIZE;
  } else {
    return -1;
  }
  return n > MAX_CHUNKS ? -1 : plain;
}

/** Reports whether total is the size of a valid stream with chunk size chunk. */
export function validSize(total: number, chunk: number): boolean {
  return plaintextSize(total, chunk) >= 0;
}

/** Encrypts chunk counter (plaintext plain) of the stream with the given header. */
export async function encryptChunk(
  fileKey: CryptoKey,
  header: TTE2Header,
  counter: number,
  last: boolean,
  plain: Uint8Array,
): Promise<Uint8Array<ArrayBuffer>> {
  const ct = await globalThis.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: chunkNonce(counter, last), additionalData: header.bytes, tagLength: 128 },
    fileKey,
    new Uint8Array(plain),
  );
  return new Uint8Array(ct);
}

/**
 * Check of the plaintext of chunk counter, called by encryptRange before the chunk is encrypted;
 * a rejection (or a throw) stops the range, so the chunk is never encrypted nor returned.
 */
export type ChunkVerifier = (counter: number, plain: Uint8Array<ArrayBuffer>) => void | Promise<void>;

/**
 * Returns exactly the bytes [start, end) of the TTE2 stream encrypting source (header and
 * chunks). Only the plaintext of the chunks overlapping the range is read, through
 * Blob.slice().arrayBuffer(), so memory stays bounded by the range plus one chunk. The output is
 * deterministic for a given key and header: a tus upload resumed at any offset regenerates
 * identical bytes. source.size must equal plainSize (size-mismatch otherwise); a range outside
 * [0, stream size] is a RangeError. verify, when given, checks the plaintext of every chunk read
 * before it is encrypted (a source whose content changed since it was hashed must never be
 * encrypted again under the same nonces).
 */
export async function encryptRange(
  fileKey: CryptoKey,
  header: TTE2Header,
  source: Blob,
  plainSize: number,
  start: number,
  end: number,
  verify?: ChunkVerifier,
): Promise<Uint8Array<ArrayBuffer>> {
  if (source.size !== plainSize) {
    throw new E2EError('size-mismatch', `source has ${source.size} bytes, expected ${plainSize}`);
  }
  const total = ciphertextSize(plainSize, header.chunkSize);
  if (total < 0) throw new E2EError('counter-overflow', `${plainSize} bytes`);
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || start > end || end > total) {
    throw new RangeError(`tte2: range [${start}, ${end}) outside [0, ${total})`);
  }
  const out = new Uint8Array(end - start);
  if (start < HEADER_SIZE) out.set(header.bytes.subarray(start, Math.min(end, HEADER_SIZE)), 0);
  if (end <= HEADER_SIZE) return out;
  const c = header.chunkSize;
  const block = c + TAG_SIZE;
  const n = chunkCount(plainSize, c);
  const first = Math.floor((Math.max(start, HEADER_SIZE) - HEADER_SIZE) / block);
  const lastIndex = Math.floor((end - 1 - HEADER_SIZE) / block);
  for (let j = first; j <= lastIndex; j++) {
    const plainStart = j * c;
    const plainEnd = Math.min(plainStart + c, plainSize);
    const plain = new Uint8Array(await source.slice(plainStart, plainEnd).arrayBuffer());
    if (verify !== undefined) await verify(j, plain);
    const ct = await encryptChunk(fileKey, header, j, j === n - 1, plain);
    const chunkStart = HEADER_SIZE + j * block;
    const from = Math.max(start, chunkStart);
    const to = Math.min(end, chunkStart + ct.length);
    out.set(ct.subarray(from - chunkStart, to - chunkStart), from - start);
  }
  return out;
}

/** Everything needed to upload one file of an end-to-end encrypted transfer. */
export interface FileEncryption {
  /** 0-based position of the file in the transfer. */
  readonly index: number;
  /** Header of the stream (its salt is new for every file). */
  readonly header: TTE2Header;
  /** Derived file key (non-extractable). */
  readonly fileKey: CryptoKey;
  /** Plaintext size of the file. */
  readonly plainSize: number;
  /** Size of the encrypted stream, the size declared to the server (Upload-Length). */
  readonly size: number;
  /** Returns the stream bytes [start, end), as encryptRange. */
  range(start: number, end: number): Promise<Uint8Array<ArrayBuffer>>;
}

/** Options of prepareFileEncryption. */
export interface FileEncryptionOptions {
  /** Plaintext chunk size (DEFAULT_CHUNK_SIZE when absent). */
  chunkSize?: number;
  /** Fixed header salt: the stored salt of a file when an upload resumes after a reload, or a test vector (random when absent). */
  salt?: Uint8Array;
  /** Check of the plaintext of every chunk before it is encrypted (see encryptRange). */
  verifyChunk?: ChunkVerifier;
}

/**
 * Draws the header of file index, derives its key and returns the stream size and a range
 * encryptor over source. The caller must keep the returned object (header included) for the whole
 * upload, resumes included: a new header would change every byte of the stream.
 */
export async function prepareFileEncryption(
  key: TransferKey,
  index: number,
  source: Blob,
  options: FileEncryptionOptions = {},
): Promise<FileEncryption> {
  checkIndex(index);
  const header = newHeader(options.chunkSize, options.salt);
  const plainSize = source.size;
  const size = ciphertextSize(plainSize, header.chunkSize);
  if (size < 0) throw new E2EError('counter-overflow', `${plainSize} bytes`);
  const fileKey = await deriveFileKey(key, header.salt, index);
  return {
    index,
    header,
    fileKey,
    plainSize,
    size,
    range: (start, end) => encryptRange(fileKey, header, source, plainSize, start, end, options.verifyChunk),
  };
}

/** Generic name declared to the server for file index: "file-<index + 1>.tte2" (as the Go server). */
export function e2eFileName(index: number): string {
  checkIndex(index);
  return `file-${index + 1}.tte2`;
}

/** Reports whether name has the generic form "file-<n>.tte2" with n >= 1 without leading zero. */
export function isE2EFileName(name: string): boolean {
  return /^file-[1-9][0-9]*\.tte2$/.test(name);
}
