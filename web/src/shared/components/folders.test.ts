import { describe, expect, it } from 'vitest';
import {
  collectDrop,
  fullName,
  isHidden,
  isSystemFile,
  pickedFromInput,
  prepareFiles,
  summarizePick,
  supportsFolderPicker,
  walkEntry,
  withPath,
  type DirectoryEntryLike,
  type EntryLike,
  type FileEntryLike,
  type ItemLike,
} from './folders';

const file = (name: string) => ({ name }) as File;

function fileEntry(name: string, fail = false): FileEntryLike<File> {
  return {
    isFile: true,
    isDirectory: false,
    name,
    file: (ok, ko) => (fail ? ko(new Error('gone')) : ok(file(name))),
  };
}

/** A directory whose readEntries returns the children in batches of batch entries. */
function dirEntry(name: string, children: EntryLike[], batch = 100, fail = false): DirectoryEntryLike {
  return {
    isFile: false,
    isDirectory: true,
    name,
    createReader() {
      let offset = 0;
      return {
        readEntries(ok, ko) {
          if (fail) return ko(new Error('denied'));
          const part = children.slice(offset, offset + batch);
          offset += part.length;
          ok(part);
        },
      };
    },
  };
}

describe('walkEntry', () => {
  it('builds the relative folder from the dropped folder down, reading every batch', async () => {
    const tree = dirEntry(
      'root',
      [fileEntry('a.txt'), dirEntry('sub', [fileEntry('b.txt'), dirEntry('empty', [])]), fileEntry('c.txt')],
      1,
    );
    const out = await walkEntry<File>(tree, '');
    expect(out.map((p) => `${p.path}|${p.file.name}`)).toEqual([
      'root|a.txt',
      'root/sub|b.txt',
      'root|c.txt',
    ]);
  });

  it('puts a plain file at the root and skips unreadable ones', async () => {
    expect(await walkEntry<File>(fileEntry('x.txt'), '')).toEqual([{ file: file('x.txt'), path: '' }]);
    expect(await walkEntry<File>(fileEntry('x.txt', true), '')).toEqual([]);
    expect(await walkEntry<File>(dirEntry('d', [fileEntry('y')], 10, true), '')).toEqual([]);
  });

  it('stops at a safe depth', async () => {
    let entry: EntryLike = fileEntry('deep.txt');
    for (let i = 0; i < 70; i++) entry = dirEntry(`d${i}`, [entry]);
    expect(await walkEntry<File>(entry, '')).toEqual([]);
  });
});

describe('collectDrop', () => {
  const item = (entry: EntryLike | null, direct?: File): ItemLike => ({
    kind: 'file',
    webkitGetAsEntry: () => entry,
    getAsFile: () => direct ?? null,
  });

  it('walks dropped folders and keeps plain files at the root', async () => {
    const items = [item(dirEntry('docs', [fileEntry('a.txt')])), item(fileEntry('b.txt'))];
    const out = await collectDrop(items, [file('docs'), file('b.txt')], true);
    expect(out.map((p) => `${p.path}|${p.file.name}`)).toEqual(['docs|a.txt', '|b.txt']);
  });

  it('keeps files the browser gives without an entry and ignores non-file items', async () => {
    const items: ItemLike[] = [{ kind: 'string' }, item(null, file('c.txt')), item(fileEntry('d.txt'))];
    const out = await collectDrop(items, [], true);
    expect(out.map((p) => p.file.name)).toEqual(['c.txt', 'd.txt']);
  });

  it('falls back to the plain files without entry support or when folders are off', async () => {
    const plain = [file('e.txt')];
    expect(await collectDrop([{ kind: 'file' }], plain, true)).toEqual([{ file: plain[0], path: '' }]);
    expect(await collectDrop([item(fileEntry('f'))], plain, false)).toEqual([{ file: plain[0], path: '' }]);
    expect(await collectDrop(null, null, true)).toEqual([]);
  });
});

describe('pickedFromInput', () => {
  it('removes the file name from webkitRelativePath', () => {
    const f = (name: string, rel?: string) =>
      Object.assign(file(name), rel === undefined ? {} : { webkitRelativePath: rel });
    const out = pickedFromInput([
      f('a.txt', 'top/sub/a.txt'),
      f('b.txt', 'top/b.txt'),
      f('c.txt', 'c.txt'),
      f('d.txt'),
    ]);
    expect(out.map((p) => p.path)).toEqual(['top/sub', 'top', '', '']);
    expect(pickedFromInput(null)).toEqual([]);
  });
});

describe('prepareFiles', () => {
  it('leaves out system files case-insensitively and counts them', () => {
    const out = prepareFiles([
      { file: file('.DS_Store'), path: 'a' },
      { file: file('THUMBS.DB'), path: '' },
      { file: file('Desktop.ini'), path: 'a/b' },
      { file: file('ok.txt'), path: 'a' },
    ]);
    expect(out.excluded).toBe(3);
    expect(out.accepted.map((a) => a.file.name)).toEqual(['ok.txt']);
    expect(isSystemFile('.env')).toBe(false);
  });

  it('flags hidden files and files in hidden folders without removing them', () => {
    const out = prepareFiles([
      { file: file('.env'), path: '' },
      { file: file('a.txt'), path: 'x/.git' },
      { file: file('b.txt'), path: 'x' },
    ]);
    expect(out.accepted.map((a) => a.hidden)).toEqual([true, true, false]);
    expect(isHidden('', 'a')).toBe(false);
  });

  it('sets aside files the server would refuse, with the reason', () => {
    const out = prepareFiles([
      { file: file('nul.txt'), path: '' },
      { file: file('a.txt'), path: 'bad:folder' },
      { file: file('fine.txt'), path: 'é' },
    ]);
    expect(out.rejected).toEqual([
      { display: 'nul.txt', reason: 'reserved-name' },
      { display: 'bad:folder/a.txt', reason: 'path-separator' },
    ]);
    expect(out.accepted).toHaveLength(1);
    expect(out.accepted[0]?.path).toBe('é');
  });

  it('caps the number of files kept', () => {
    const picked = Array.from({ length: 5 }, (_, i) => ({ file: file(`f${i}`), path: '' }));
    const out = prepareFiles(picked, 3);
    expect(out.accepted).toHaveLength(3);
    expect(out.rejected.map((r) => r.reason)).toEqual(['too-many', 'too-many']);
    expect(prepareFiles(picked, -1).accepted).toHaveLength(0);
  });
});

describe('helpers', () => {
  it('fullName joins folder and name', () => {
    expect(fullName('a/b', 'c')).toBe('a/b/c');
    expect(fullName('', 'c')).toBe('c');
    expect(fullName(undefined, 'c')).toBe('c');
  });

  it('withPath marks the browser file itself', () => {
    const f = file('a');
    const marked = withPath({ file: f, path: 'x', hidden: true });
    expect(marked).toBe(f);
    expect(marked.path).toBe('x');
    expect(marked.hidden).toBe(true);
  });
});

describe('summarizePick', () => {
  it('reports an empty pick', () => {
    expect(summarizePick([])).toEqual({
      accepted: [],
      notice: { empty: true, excluded: 0, rejected: [] },
    });
  });

  it('reports left out and refused files, and nothing when all is kept', () => {
    const f = (name: string) => ({ file: { name }, path: '' });
    expect(summarizePick([f('a.txt')]).notice).toBeUndefined();
    const out = summarizePick([f('a.txt'), f('Thumbs.db'), f('a​b')]);
    expect(out.accepted).toHaveLength(1);
    expect(out.notice).toMatchObject({ empty: false, excluded: 1 });
    expect(out.notice?.rejected).toHaveLength(1);
  });
});

describe('supportsFolderPicker', () => {
  it('detects webkitdirectory on the given prototype', () => {
    expect(supportsFolderPicker({ webkitdirectory: true })).toBe(true);
    expect(supportsFolderPicker({})).toBe(false);
    expect(supportsFolderPicker(undefined)).toBe(false);
  });
});
