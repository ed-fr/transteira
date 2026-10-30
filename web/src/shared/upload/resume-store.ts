// Resume after a page reload (threat model T-160): sessionStorage keeps only the transfer id
// and the fingerprints of its files (name, folder, size, last modification), never their content or
// the CSRF token. The browser cannot reopen a file by itself: the user selects the same files
// again and matchFiles pairs them with the transfer's files.

/** Fingerprint of a selected file. */
export interface FileFingerprint {
  name: string;
  size: number;
  lastModified: number;
  /** Relative folder inside the transfer ('' for the root). */
  path?: string | undefined;
}

/** What is kept between reloads. */
export interface ResumeRecord {
  transferId: string;
  /** Fingerprints in the declared order of the transfer's files. */
  files: FileFingerprint[];
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

/** Validates a parsed record (the storage may hold anything). */
export function isResumeRecord(value: unknown): value is ResumeRecord {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.transferId === 'string' &&
    v.transferId !== '' &&
    Array.isArray(v.files) &&
    v.files.length > 0 &&
    v.files.every(isFingerprint)
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
        storage()?.setItem(key, JSON.stringify({ transferId: record.transferId, files: record.files }));
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
        return { ...parsed, files: parsed.files.map((fp) => ({ ...fp, path: fp.path ?? '' })) };
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
