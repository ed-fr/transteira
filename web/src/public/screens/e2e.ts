// View model of an end-to-end encrypted transfer on the download page (CLAUDE.md section 22): the
// key read from the link fragment or typed by the recipient, and the plaintext names, folders,
// sizes, fingerprints and message opened from the sealed metadata. Pure functions over WebCrypto,
// unit tested.
import { archiveEntries, safeFileName } from '../../shared/e2e/archive-names';
import { isE2EError } from '../../shared/e2e/errors';
import { openMessage, openMetadata, type Metadata } from '../../shared/e2e/sealed';
import { importTransferKey, parseKeyInput } from '../../shared/e2e/tte2';
import { safeApiHref } from '../../shared/safe/href';
import { checkPath } from '../../shared/validation/filepath';
import type { PublicFile, PublicTransfer, ScanStatus } from './outcomes';

/** Whether the transfer is end-to-end encrypted (also known while it is locked). */
export function isEndToEnd(transfer: PublicTransfer): boolean {
  return transfer.endToEndEncrypted === true;
}

/**
 * Parses a key typed or pasted by the recipient (the bare key, "k=<key>" or the whole link):
 * the 32 bytes, or undefined when the text holds no valid key.
 */
export function parseKeyText(text: string): Uint8Array<ArrayBuffer> | undefined {
  try {
    return parseKeyInput(text);
  } catch {
    return undefined;
  }
}

/** Key of the link fragment ("#k=<key>"), undefined when absent or invalid. */
export function keyFromFragment(hash: string): Uint8Array<ArrayBuffer> | undefined {
  return hash.startsWith('#') ? parseKeyText(hash) : undefined;
}

/** The part of window.location read by takeKeyFromLocation. */
export interface LocationLike {
  readonly pathname: string;
  readonly search: string;
  readonly hash: string;
}

/** The part of window.history used by takeKeyFromLocation. */
export interface HistoryLike {
  readonly state: unknown;
  replaceState(data: unknown, unused: string, url: string): void;
}

/**
 * Reads the key of the link fragment, then removes the fragment from the address bar and from
 * the current history entry (replaceState: no navigation, no popstate, the router does not move),
 * so that the key does not linger in the URL, a bookmark or a shared screen. A reload of the page
 * then no longer has the key: the recipient pastes it in the key form. Any fragment is removed,
 * an invalid one included (it may hold a mistyped key).
 */
export function takeKeyFromLocation(
  location: LocationLike,
  history: HistoryLike,
): Uint8Array<ArrayBuffer> | undefined {
  const hash = location.hash;
  if (hash === '') return undefined;
  const key = keyFromFragment(hash);
  history.replaceState(history.state, '', location.pathname + location.search);
  return key;
}

/** One decrypted file of the table. */
export interface E2EFileRow {
  /** Server id of the file. */
  id: string;
  /** 0-based position of the file in the transfer. */
  index: number;
  /** Name from the metadata, validated (the name the file is saved under). */
  name: string;
  /** Folder from the metadata, validated ('' for the root or an invalid folder). */
  path: string;
  /** Entry path of the file in the ZIP archive built in the browser. */
  entryName: string;
  /** Plaintext size declared by the sender. */
  size: number;
  /** Plaintext SHA-256 declared by the sender (checked while decrypting). */
  sha256: string;
  /** SHA-256 of the encrypted file, computed by the server. */
  ciphertextSha256: string;
  scanStatus: ScanStatus;
  /** Filtered ciphertext URL; undefined when the server URL was rejected. */
  url: string | undefined;
}

/** Outcome of opening a transfer with a key. */
export type E2EOpening =
  | {
      kind: 'open';
      /** Non-extractable HKDF base key of K, handed to the Service Worker. */
      key: CryptoKey;
      files: E2EFileRow[];
      totalBytes: number;
      /** Decrypted message (plain text), undefined without message. */
      message: string | undefined;
    }
  | { kind: 'wrong-key' }
  | { kind: 'tampered' }
  /** WebCrypto is missing (insecure context, old browser) or failed outside of the format. */
  | { kind: 'unsupported' };

/** Whether this context offers WebCrypto (crypto.subtle exists in secure contexts only). */
export function webCryptoAvailable(): boolean {
  return globalThis.crypto?.subtle !== undefined;
}

/** Whether a sealed item opens with key. */
async function opens(open: () => Promise<unknown>): Promise<boolean> {
  try {
    await open();
    return true;
  } catch {
    return false;
  }
}

/**
 * Tells a wrong key from a tampered transfer once the metadata of the first file does not
 * authenticate: the key is right if the message, the metadata of another file at its position,
 * or the first metadata at another index (files removed or reordered) opens with it. A server
 * removing several leading files is still refused, as a wrong key: nothing is shown either way.
 */
async function opensAnything(
  key: CryptoKey,
  transfer: PublicTransfer,
  files: readonly PublicFile[],
  first: string,
): Promise<boolean> {
  const message = transfer.encryptedMessage;
  if (message !== undefined && message !== '' && (await opens(() => openMessage(key, message)))) return true;
  for (const [i, f] of files.entries()) {
    const sealed = f.encryptedMetadata;
    if (i > 0 && sealed !== undefined && (await opens(() => openMetadata(key, i, sealed)))) return true;
  }
  for (let j = 1; j <= files.length; j++) {
    if (await opens(() => openMetadata(key, j, first))) return true;
  }
  return false;
}

/**
 * Opens the sealed metadata of every file and the message with keyBytes. A key that opens no
 * sealed item (opensAnything; the message for a transfer without files) is wrong-key; any other
 * format failure (E2EError), a file without metadata, a count different from
 * the number of files or an index different from the position (checked by openMetadata) is
 * tampered: a file was removed, reordered or altered. Without WebCrypto, or when WebCrypto fails
 * with anything but an E2EError (unsupported algorithm), the result is unsupported. Never rejects.
 */
export async function openEndToEnd(transfer: PublicTransfer, keyBytes: Uint8Array): Promise<E2EOpening> {
  if (!webCryptoAvailable()) return { kind: 'unsupported' };
  try {
    return await openWith(transfer, keyBytes);
  } catch (err) {
    return { kind: isE2EError(err) ? 'tampered' : 'unsupported' };
  }
}

async function openWith(transfer: PublicTransfer, keyBytes: Uint8Array): Promise<E2EOpening> {
  const key = await importTransferKey(keyBytes);
  const files = transfer.files ?? [];
  const opened: Metadata[] = [];
  for (const [i, f] of files.entries()) {
    if (f.encryptedMetadata === undefined) return { kind: 'tampered' };
    try {
      const m = await openMetadata(key, i, f.encryptedMetadata);
      if (m.count !== files.length) return { kind: 'tampered' };
      opened.push(m);
    } catch (err) {
      if (!isE2EError(err)) throw err;
      if (
        i === 0 &&
        isE2EError(err, 'auth') &&
        !(await opensAnything(key, transfer, files, f.encryptedMetadata))
      ) {
        return { kind: 'wrong-key' };
      }
      return { kind: 'tampered' };
    }
  }
  let message: string | undefined;
  if (transfer.encryptedMessage !== undefined && transfer.encryptedMessage !== '') {
    try {
      message = await openMessage(key, transfer.encryptedMessage);
    } catch (err) {
      if (!isE2EError(err)) throw err;
      return { kind: files.length === 0 && isE2EError(err, 'auth') ? 'wrong-key' : 'tampered' };
    }
  }
  const items = opened.map((m) => {
    const p = checkPath(m.path);
    return { path: p.ok ? p.value : '', name: safeFileName(m.name) };
  });
  const entries = archiveEntries(items);
  const rows: E2EFileRow[] = files.map((f, i) => ({
    id: f.id,
    index: i,
    name: items[i]!.name,
    path: items[i]!.path,
    entryName: entries[i]!,
    size: opened[i]!.size,
    sha256: opened[i]!.sha256,
    ciphertextSha256: f.sha256,
    scanStatus: f.scanStatus,
    url: safeApiHref(f.downloadUrl),
  }));
  return {
    kind: 'open',
    key,
    files: rows,
    totalBytes: rows.reduce((n, r) => n + r.size, 0),
    message,
  };
}
