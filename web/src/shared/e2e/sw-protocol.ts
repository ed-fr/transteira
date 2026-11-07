// Message protocol between the download page and the Service Worker of the end-to-end encrypted
// downloads (web/src/e2e-sw, served as /e2e-sw.js with the scope /e2e/). Shared by both sides so
// that the shapes cannot drift apart.
//
// Key handover: the page never posts K. It posts the non-extractable HKDF base CryptoKey of K
// (importTransferKey), structured-cloned by postMessage, with the index of each file. The file key
// cannot be derived in advance, because it depends on the salt of the ciphertext header: the
// Service Worker derives it itself once the first 32 bytes of the ciphertext have arrived
// (createDecryptStream({ key, index })). It can derive keys from the base key but never read K.
//
// Exchange, over a MessageChannel whose port2 travels with the message:
//   page -> SW   { type: 'register', id, entry }            (event.ports[0] = the reply port)
//   SW -> page   { type: 'registered' } | { type: 'rejected' }
//   page         navigates to /e2e/<id>
//   SW -> page   { type: 'started' }  once the ciphertext answered and the response is streamed
//   SW -> page   { type: 'done' } | { type: 'failed', code }
// An entry is single use and expires ENTRY_TTL_MS after its registration.

/** URL of the Service Worker script (a fixed name at the root of the build). */
export const SW_URL = '/e2e-sw.js';

/** Scope of the Service Worker: it only ever sees requests under this path. */
export const SW_SCOPE = '/e2e/';

/** Lifetime of a registered entry, in milliseconds. */
export const ENTRY_TTL_MS = 60_000;

/** Maximum number of entries pending at once (older ones are dropped beyond). */
export const MAX_PENDING = 32;

/** Pattern of an entry id: 128 random bits in base64url, without padding (22 characters). */
export const ENTRY_ID = /^[A-Za-z0-9_-]{22}$/;

/** One encrypted file to decrypt. */
export interface SwFile {
  /** Same-origin URL of the ciphertext (the downloadUrl of the API, /api/v1/downloads/...). */
  url: string;
  /** Non-extractable HKDF base key of the transfer (importTransferKey), never the bytes of K. */
  key: CryptoKey;
  /** 0-based index of the file in the transfer (part of the file key derivation). */
  index: number;
  /**
   * File name: for a single file the name to save it under, for an archive member its entry path
   * inside the ZIP (folders separated by "/").
   */
  name: string;
  /** Plaintext size declared by the sealed metadata, checked while streaming. */
  size: number;
  /** Lowercase hexadecimal SHA-256 of the plaintext declared by the metadata, checked at the end. */
  sha256: string;
}

/** What one id serves: a single decrypted file, or a ZIP archive of several. */
export type SwEntry = { kind: 'file'; file: SwFile } | { kind: 'archive'; name: string; files: SwFile[] };

/** Registration message posted by the page. */
export interface RegisterMessage {
  type: 'register';
  id: string;
  entry: SwEntry;
}

/** Stable code of a failure reported by the Service Worker or the in-memory fallback. */
export type FailureCode = 'corrupt' | 'network' | 'unavailable' | 'cancelled';

/** Messages of the Service Worker on the reply port. */
export type SwReply =
  | { type: 'registered' }
  | { type: 'rejected' }
  | { type: 'started' }
  | { type: 'done' }
  | { type: 'failed'; code: FailureCode };

/** URL the page navigates to once the entry id is registered. */
export function entryUrl(id: string): string {
  return `${SW_SCOPE}${id}`;
}
