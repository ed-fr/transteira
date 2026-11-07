// Names of the decrypted files of an end-to-end encrypted transfer, mirror of the server rules of
// internal/filename (archive.go, ArchiveEntries) for the ZIP built in the browser. The names and
// folders come from the sealed metadata, written by the sender and never seen by the server: they
// are revalidated here with the client mirror of the server rules (shared/validation/filepath.ts)
// before being used as a download name or a ZIP entry (threats T-51, T-52, T-227).
import { byteLength, checkPath, checkSegment, SEGMENT_MAX_BYTES } from '../validation/filepath';

/** Name used for a file whose name does not pass the rules (as filename.Fallback). */
export const FALLBACK_NAME = 'file';

/** Name of the ZIP archive of a transfer (as the server archive, internal/api/public). */
export const ARCHIVE_NAME = 'transfer.zip';

// Characters the rules accept but Windows refuses in a file name.
const ARCHIVE_UNSAFE = /[<>"|?*]/g;

/** A file placed in the archive: its relative folder ('' for the root) and its name. */
export interface ArchiveFile {
  path: string;
  name: string;
}

/** Replaces the characters Windows refuses with "_". */
function archiveSafe(s: string): string {
  return s.replace(ARCHIVE_UNSAFE, '_');
}

/** Case-insensitive comparison key (upper then lower case, normalised again, as foldKey). */
function foldKey(s: string): string {
  return s.toUpperCase().toLowerCase().normalize('NFC');
}

/**
 * Returns the name to save a single decrypted file under: the validated name (NFC) with the
 * characters Windows refuses replaced, or FALLBACK_NAME when it breaks the rules.
 */
export function safeFileName(name: string): string {
  const checked = checkSegment(name);
  return checked.ok ? archiveSafe(checked.value) : FALLBACK_NAME;
}

/** Shortens s to at most limit UTF-8 bytes on a code point boundary, then drops trailing spaces and dots. */
function truncate(s: string, limit: number): string {
  if (byteLength(s) <= limit) return s;
  let out = '';
  for (const ch of s) {
    if (byteLength(out + ch) > limit) break;
    out += ch;
  }
  return out.normalize('NFC').replace(/[\s.]+$/u, '');
}

/** Splits a name into stem and extension (from the last dot, ignored in first position). */
function splitExt(name: string): [string, string] {
  const i = name.lastIndexOf('.');
  return i > 0 ? [name.slice(0, i), name.slice(i)] : [name, ''];
}

/** Returns "stem (i)ext", shortened to fit in SEGMENT_MAX_BYTES bytes. */
function numbered(stem: string, ext: string, i: number): string {
  const suffix = ` (${i})`;
  if (suffix.length + byteLength(ext) >= SEGMENT_MAX_BYTES) {
    stem += ext;
    ext = '';
  }
  const cut = truncate(stem, SEGMENT_MAX_BYTES - suffix.length - byteLength(ext)).replace(/\s+$/u, '');
  return cut === '' ? FALLBACK_NAME + suffix : cut + suffix + ext;
}

/** Archive folder of path with the first spelling met for each level (recorded in folders). */
function archiveFolder(path: string, folders: Map<string, string>): string {
  const checked = checkPath(path);
  if (!checked.ok || checked.value === '') return '';
  let dir = '';
  let key = '';
  for (const seg of archiveSafe(checked.value).split('/')) {
    key = key === '' ? foldKey(seg) : `${key}/${foldKey(seg)}`;
    let spelling = folders.get(key);
    if (spelling === undefined) {
      spelling = dir === '' ? seg : `${dir}/${seg}`;
      folders.set(key, spelling);
    }
    dir = spelling;
  }
  return dir;
}

/**
 * Returns the ZIP entry name of each file, in order: invalid names become FALLBACK_NAME, invalid
 * folders the root, the characters Windows refuses "_"; folders are merged case-insensitively
 * (first spelling wins) and names made unique case-insensitively within a folder ("a (2).txt"),
 * never equal to a folder. Every result passes checkPath.
 */
export function archiveEntries(files: readonly ArchiveFile[]): string[] {
  const folders = new Map<string, string>();
  const dirs = files.map((f) => archiveFolder(f.path, folders));
  const names = files.map((f) => safeFileName(f.name));
  const seen = new Map<string, number>();
  return files.map((_, i) => {
    const dir = dirs[i]!;
    const name = names[i]!;
    const prefix = dir === '' ? '' : `${dir}/`;
    const taken = (n: string): boolean => {
      const k = foldKey(prefix + n);
      return seen.has(k) || folders.has(k);
    };
    const key = foldKey(prefix + name);
    if (!taken(name)) {
      seen.set(key, 1);
      return prefix + name;
    }
    const [stem, ext] = splitExt(name);
    for (let n = Math.max(seen.get(key) ?? 1, 1) + 1; ; n++) {
      const candidate = numbered(stem, ext, n);
      if (taken(candidate)) continue;
      seen.set(foldKey(prefix + candidate), 1);
      seen.set(key, n);
      return prefix + candidate;
    }
  });
}

/**
 * Reports whether names can be the entry paths of an archive as they are: every one a valid path
 * already normalised (checkPath leaves it unchanged, so not empty) and no two equal
 * case-insensitively, as the Service Worker checks a registration (e2e-sw/handler.ts).
 */
export function validEntryNames(names: readonly string[]): boolean {
  const seen = new Set<string>();
  for (const name of names) {
    const checked = checkPath(name);
    const key = name.toUpperCase().toLowerCase();
    if (name === '' || !checked.ok || checked.value !== name || seen.has(key)) return false;
    seen.add(key);
  }
  return true;
}
