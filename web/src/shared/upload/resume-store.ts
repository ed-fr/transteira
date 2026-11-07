// Resume after a page reload (threat model T-160): sessionStorage keeps only the transfer id
// and the fingerprints of its files (name, folder, size, last modification), never their content or
// the CSRF token. The browser cannot reopen a file by itself: the user selects the same files
// again and matchFiles pairs them with the transfer's files.
//
// For an end-to-end encrypted transfer the record also keeps the transfer key K and the header
// salt of each file (decision of 2026-11-07, T-160): the encryption is deterministic once the salt
// is drawn, so the bytes regenerated after a reload match those the server already holds. It
// also keeps the plaintext SHA-256 of each file: a reselected file is matched by its fingerprint
// only, so it is hashed again and refused when its content differs (the same key, salt and
// nonces must never encrypt another plaintext). The record is cleared at the end of the upload
// and on abandon, and dies with the tab.
import { decodeBase64Url } from '../e2e/base64url';
import { KEY_SIZE, SALT_SIZE, validChunkSize } from '../e2e/tte2';

/** Fingerprint of a selected file. */
export interface FileFingerprint {
  name: string;
  size: number;
  lastModified: number;
  /** Relative folder inside the transfer ('' for the root). */
  path?: string | undefined;
}

/** Encryption state of an end-to-end encrypted transfer being uploaded. */
export interface ResumeE2E {
  /** Transfer key K, base64url without padding. */
  key: string;
  /** Header salt of each file, base64url without padding, in the declared order. */
  salts: string[];
  /** Plaintext SHA-256 of each file, lowercase hexadecimal, in the declared order. */
  sha256: string[];
  /** Plaintext chunk size of the streams. */
  chunkSize: number;
}

/** What is kept between reloads. */
export interface ResumeRecord {
  transferId: string;
  /** Fingerprints in the declared order of the transfer's files. */
  files: FileFingerprint[];
  /** Present for an end-to-end encrypted transfer. */
  e2e?: ResumeE2E | undefined;
}

/** Persistent store of the transfer being uploaded. */
export interface ResumeStore {
  save(record: ResumeRecord): void;
  load(): ResumeRecord | undefined;
  clear(): void;
}

/** sessionStorage key. */
export const RESUME_STORAGE_KEY = 'tt.upload';

/** File-like value (File in the browser). */
export interface FileLike {
  name: string;
  size: number;
  lastModified: number;
  /** Relative folder inside the transfer; absent for the root. */
  path?: string | undefined;
}

/** Fingerprint of a file. */
export function fingerprint(file: FileLike): FileFingerprint {
  return { name: file.name, size: file.size, lastModified: file.lastModified, path: file.path ?? '' };
}

function isFingerprint(value: unknown): value is FileFingerprint {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.name === 'string' &&
    (v.path === undefined || typeof v.path === 'string') &&
    Number.isSafeInteger(v.size) &&
    (v.size as number) >= 0 &&
    typeof v.lastModified === 'number' &&
    Number.isFinite(v.lastModified)
  );
}

const SHA256_HEX = /^[0-9a-f]{64}$/;

function hasBytes(value: unknown, size: number): boolean {
  return typeof value === 'string' && decodeBase64Url(value)?.length === size;
}

/** Validates the encryption part of a record holding count files. */
export function isResumeE2E(value: unknown, count: number): value is ResumeE2E {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    hasBytes(v.key, KEY_SIZE) &&
    Array.isArray(v.salts) &&
    v.salts.length === count &&
    v.salts.every((salt) => hasBytes(salt, SALT_SIZE)) &&
    Array.isArray(v.sha256) &&
    v.sha256.length === count &&
    v.sha256.every((h) => typeof h === 'string' && SHA256_HEX.test(h)) &&
    typeof v.chunkSize === 'number' &&
    validChunkSize(v.chunkSize)
  );
}

/** Validates a parsed record (the storage may hold anything). */
export function isResumeRecord(value: unknown): value is ResumeRecord {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.transferId === 'string' &&
    v.transferId !== '' &&
    Array.isArray(v.files) &&
    v.files.length > 0 &&
    v.files.every(isFingerprint) &&
    (v.e2e === undefined || isResumeE2E(v.e2e, v.files.length))
  );
}

/**
 * Creates the resume store. Every storage access is guarded: storage may be missing or throw
 * (private window, blocked site data), the upload then simply cannot resume after a reload.
 */
export function createResumeStore(
  storage: () => Storage | undefined = () => globalThis.sessionStorage,
  key: string = RESUME_STORAGE_KEY,
): ResumeStore {
  return {
    save(record) {
      try {
        const kept: ResumeRecord = { transferId: record.transferId, files: record.files };
        if (record.e2e !== undefined) {
          const { key: k, salts, sha256, chunkSize } = record.e2e;
          kept.e2e = { key: k, salts, sha256, chunkSize };
        }
        storage()?.setItem(key, JSON.stringify(kept));
      } catch {
        // Not persisted: resuming after a reload is a convenience.
      }
    },
    load() {
      try {
        const raw = storage()?.getItem(key);
        if (raw === null || raw === undefined) return undefined;
        const parsed: unknown = JSON.parse(raw);
        if (!isResumeRecord(parsed)) return undefined;
        // Records saved before folders existed have no path: the root.
        const out: ResumeRecord = {
          ...parsed,
          files: parsed.files.map((fp) => ({ ...fp, path: fp.path ?? '' })),
        };
        if (parsed.e2e === undefined) delete out.e2e;
        return out;
      } catch {
        return undefined;
      }
    },
    clear() {
      try {
        storage()?.removeItem(key);
      } catch {
        // Nothing to do.
      }
    },
  };
}

/** Result of matching reselected files against a record. */
export interface FileMatch<F extends FileLike> {
  /** Reselected file for each fingerprint of the record, in the record's order. */
  files: (F | undefined)[];
  /** Fingerprints without a matching selected file. */
  missing: FileFingerprint[];
  /** True when every fingerprint has its file. */
  complete: boolean;
}

/**
 * Pairs reselected files with the record's fingerprints (same folder, name, size and last modification;
 * each selected file is used once).
 */
export function matchFiles<F extends FileLike>(record: ResumeRecord, selected: readonly F[]): FileMatch<F> {
  const available = [...selected];
  const files: (F | undefined)[] = [];
  const missing: FileFingerprint[] = [];
  for (const fp of record.files) {
    const i = available.findIndex(
      (f) =>
        (f.path ?? '') === (fp.path ?? '') &&
        f.name === fp.name &&
        f.size === fp.size &&
        f.lastModified === fp.lastModified,
    );
    if (i === -1) {
      files.push(undefined);
      missing.push(fp);
    } else {
      files.push(available[i]);
      available.splice(i, 1);
    }
  }
  return { files, missing, complete: missing.length === 0 };
}
