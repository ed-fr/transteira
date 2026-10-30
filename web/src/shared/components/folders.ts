// Folder handling of the file picker, kept pure (browser objects are injected) so that it is unit
// tested in Node: walking dropped directories, paths of a directory input, and the filtering of
// what is picked (system files, hidden files, paths the server would refuse).
import { checkPath, checkSegment, type PathReason } from '../validation/filepath';

/** A picked file with its relative folder ('' for the root). */
export interface PickedFile<F extends { name: string } = File> {
  file: F;
  path: string;
}

/** Maximum number of files per transfer (kept in step with TransferCreate.files). */
export const PICK_MAX_FILES = 1000;

/** Names of operating system files left out of a folder (compared case-insensitively). */
export const SYSTEM_FILES: readonly string[] = ['.ds_store', 'thumbs.db', 'desktop.ini'];

// ---- Directory entries (webkitGetAsEntry) -------------------------------------------------

/** The part of a FileSystemEntry used here. */
export interface EntryLike {
  readonly isFile: boolean;
  readonly isDirectory: boolean;
  readonly name: string;
}

/** A file entry. */
export interface FileEntryLike<F> extends EntryLike {
  file(success: (file: F) => void, failure: (error: unknown) => void): void;
}

/** A directory entry. */
export interface DirectoryEntryLike extends EntryLike {
  createReader(): {
    readEntries(success: (entries: EntryLike[]) => void, failure: (error: unknown) => void): void;
  };
}

/** The part of a DataTransferItem used here. */
export interface ItemLike {
  readonly kind: string;
  webkitGetAsEntry?: () => EntryLike | null;
  getAsFile?: () => File | null;
}

function readFile<F>(entry: FileEntryLike<F>): Promise<F> {
  return new Promise((resolve, reject) => entry.file(resolve, reject));
}

/** Reads every entry of a directory: readEntries returns batches, until an empty one. */
export async function readAllEntries(dir: DirectoryEntryLike): Promise<EntryLike[]> {
  const reader = dir.createReader();
  const all: EntryLike[] = [];
  for (;;) {
    const batch = await new Promise<EntryLike[]>((resolve, reject) => reader.readEntries(resolve, reject));
    if (batch.length === 0) {
      return all;
    }
    all.push(...batch);
  }
}

/** Safety bound on the depth walked, far above what the server accepts (it refuses the path). */
const MAX_WALK_DEPTH = 64;

/**
 * Walks an entry: a file gives one picked file under parent, a directory is walked recursively
 * (empty directories give nothing). A file that cannot be read is skipped.
 */
export async function walkEntry<F extends { name: string }>(
  entry: EntryLike,
  parent: string,
  out: PickedFile<F>[] = [],
  depth = 0,
): Promise<PickedFile<F>[]> {
  if (entry.isFile) {
    try {
      out.push({ file: await readFile(entry as FileEntryLike<F>), path: parent });
    } catch {
      // Unreadable (removed meanwhile, permission): left out.
    }
  } else if (entry.isDirectory && depth < MAX_WALK_DEPTH) {
    const here = parent === '' ? entry.name : `${parent}/${entry.name}`;
    let children: EntryLike[] = [];
    try {
      children = await readAllEntries(entry as DirectoryEntryLike);
    } catch {
      // Unreadable directory: left out.
    }
    for (const child of children) {
      await walkEntry(child, here, out, depth + 1);
    }
  }
  return out;
}

/**
 * Collects the files of a drop. The entries must be taken synchronously (the browser clears the
 * items after the event), then walked. Without directory support, the plain files are used.
 */
export function collectDrop(
  items: ArrayLike<ItemLike> | null | undefined,
  files: ArrayLike<File> | null | undefined,
  folders: boolean,
): Promise<PickedFile[]> {
  const plain = (): PickedFile[] => Array.from(files ?? []).map((file) => ({ file, path: '' }));
  if (!folders || items == null) {
    return Promise.resolve(plain());
  }
  const entries: EntryLike[] = [];
  const direct: File[] = [];
  let supported = false;
  for (const item of Array.from(items)) {
    if (item.kind !== 'file') continue;
    const entry = typeof item.webkitGetAsEntry === 'function' ? item.webkitGetAsEntry() : null;
    if (entry !== null) {
      supported = true;
      entries.push(entry);
    } else {
      const file = item.getAsFile?.();
      if (file != null) direct.push(file);
    }
  }
  if (!supported) {
    return Promise.resolve(plain());
  }
  return (async () => {
    const out: PickedFile[] = direct.map((file) => ({ file, path: '' }));
    for (const entry of entries) {
      await walkEntry<File>(entry, '', out);
    }
    return out;
  })();
}

/** Picked files of a directory input: the folder is the webkitRelativePath minus the file name. */
export function pickedFromInput(
  files: ArrayLike<File & { webkitRelativePath?: string }> | null | undefined,
): PickedFile[] {
  return Array.from(files ?? []).map((file) => {
    const relative = file.webkitRelativePath ?? '';
    const slash = relative.lastIndexOf('/');
    return { file, path: slash < 0 ? '' : relative.slice(0, slash) };
  });
}

// ---- Filtering --------------------------------------------------------------------------------

/** A picked file set aside, with why. */
export interface RejectedFile {
  /** Relative path of the file, folder included. */
  display: string;
  reason: PathReason | 'too-many';
}

/** A picked file kept, normalised, with the hidden flag. */
export interface AcceptedFile<F extends { name: string } = File> extends PickedFile<F> {
  /** The file or one of its folders has a name starting with ".". */
  hidden: boolean;
}

/** Result of prepareFiles. */
export interface Prepared<F extends { name: string } = File> {
  accepted: AcceptedFile<F>[];
  /** Number of operating system files left out. */
  excluded: number;
  rejected: RejectedFile[];
}

/** What the drop zone reports after a pick: files left out, files refused, or nothing found. */
export interface PickNotice {
  /** Nothing was found (empty or unreadable folder). */
  empty: boolean;
  excluded: number;
  rejected: RejectedFile[];
}

/**
 * Filters a pick and builds the notice to show, if any: an empty pick (empty or unreadable
 * folder) is reported as such instead of staying silent.
 */
export function summarizePick<F extends { name: string }>(
  picked: readonly PickedFile<F>[],
  room: number = PICK_MAX_FILES,
): { accepted: AcceptedFile<F>[]; notice: PickNotice | undefined } {
  if (picked.length === 0) {
    return { accepted: [], notice: { empty: true, excluded: 0, rejected: [] } };
  }
  const result = prepareFiles(picked, room);
  const notice =
    result.excluded > 0 || result.rejected.length > 0
      ? { empty: false, excluded: result.excluded, rejected: result.rejected }
      : undefined;
  return { accepted: result.accepted, notice };
}

/** Reports whether the browser can pick a folder with an input (webkitdirectory). */
export function supportsFolderPicker(
  proto: object | undefined = typeof HTMLInputElement === 'undefined'
    ? undefined
    : HTMLInputElement.prototype,
): boolean {
  return proto !== undefined && 'webkitdirectory' in proto;
}

/** Reports whether a name is an operating system file to leave out. */
export function isSystemFile(name: string): boolean {
  return SYSTEM_FILES.includes(name.toLowerCase());
}

/** Reports whether a file name or one of the folders of its path starts with ".". */
export function isHidden(path: string, name: string): boolean {
  return name.startsWith('.') || path.split('/').some((segment) => segment.startsWith('.'));
}

/**
 * Filters what was picked: system files are left out (and counted), the others are kept with a
 * hidden flag; a file whose name or path the server would refuse is set aside with the reason;
 * at most room files are kept (the rest is set aside as too-many). Paths are normalised to NFC.
 */
export function prepareFiles<F extends { name: string }>(
  picked: readonly PickedFile<F>[],
  room: number = PICK_MAX_FILES,
): Prepared<F> {
  const out: Prepared<F> = { accepted: [], excluded: 0, rejected: [] };
  for (const { file, path } of picked) {
    if (isSystemFile(file.name)) {
      out.excluded++;
      continue;
    }
    const display = fullName(path, file.name);
    const checkedPath = checkPath(path);
    const checkedName = checkSegment(file.name);
    if (!checkedPath.ok) {
      out.rejected.push({ display, reason: checkedPath.reason });
      continue;
    }
    if (!checkedName.ok) {
      out.rejected.push({ display, reason: checkedName.reason });
      continue;
    }
    if (out.accepted.length >= Math.max(0, room)) {
      out.rejected.push({ display, reason: 'too-many' });
      continue;
    }
    out.accepted.push({ file, path: checkedPath.value, hidden: isHidden(path, file.name) });
  }
  return out;
}

/** Full relative name of a file for display: "folder/sub/name". */
export function fullName(path: string | undefined, name: string): string {
  return path === undefined || path === '' ? name : `${path}/${name}`;
}

/**
 * Returns the file itself marked with its folder and hidden flag (the form keeps File objects,
 * which are extensible, so that the browser file stays the one that is read when uploading).
 */
export function withPath<F extends { name: string }>(
  picked: AcceptedFile<F>,
): F & { path: string; hidden: boolean } {
  return Object.assign(picked.file, { path: picked.path, hidden: picked.hidden });
}
