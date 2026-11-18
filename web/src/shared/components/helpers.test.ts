import { describe, expect, it, vi, afterEach } from 'vitest';
import {
  abbreviateHash,
  copyText,
  describedBy,
  dragHasFiles,
  dropTarget,
  fileExtension,
  filesOf,
  fileTypeLabel,
  helpHref,
  isFocusable,
  languageName,
  percentOf,
  totalBytes,
  volumeState,
  type CopyDocument,
  type CopyTextArea,
  type DropElement,
  type DropEventLike,
} from './helpers';

afterEach(() => {
  vi.unstubAllGlobals();
});

const file = (name: string, size = 1): File => ({ name, size }) as unknown as File;

describe('totalBytes', () => {
  it('sums sizes and ignores negative ones', () => {
    expect(totalBytes([])).toBe(0);
    expect(totalBytes([{ size: 10 }, { size: 32 }, { size: -5 }])).toBe(42);
    expect(totalBytes([{ size: 20 * 2 ** 30 }, { size: 1 }])).toBe(20 * 2 ** 30 + 1);
  });
});

describe('describedBy', () => {
  it('joins present ids', () => {
    expect(describedBy('a', undefined, false, null, '', 'b')).toBe('a b');
  });

  it('returns undefined when there is none', () => {
    expect(describedBy(undefined, false)).toBeUndefined();
  });
});

describe('dragHasFiles / filesOf', () => {
  it('detects file drags', () => {
    expect(dragHasFiles({ types: ['Files'] })).toBe(true);
    expect(dragHasFiles({ types: ['text/plain'] })).toBe(false);
    expect(dragHasFiles(null)).toBe(false);
    expect(dragHasFiles(undefined)).toBe(false);
  });

  it('converts file lists', () => {
    expect(filesOf(null)).toEqual([]);
    expect(filesOf(undefined)).toEqual([]);
    const a = file('a');
    expect(filesOf({ length: 1, 0: a })).toEqual([a]);
  });
});

/** A fake element recording listeners. */
function fakeElement(inside: unknown[] = []): DropElement & {
  listeners: Map<string, (event: DropEventLike) => void>;
  fire(type: string, event: DropEventLike): void;
} {
  const listeners = new Map<string, (event: DropEventLike) => void>();
  return {
    listeners,
    addEventListener: (type, listener) => listeners.set(type, listener),
    removeEventListener: (type, listener) => {
      if (listeners.get(type) === listener) {
        listeners.delete(type);
      }
    },
    contains: (other) => inside.includes(other),
    fire(type, event) {
      listeners.get(type)?.(event);
    },
  };
}

function dragEvent(types: string[], files: File[] = [], relatedTarget: unknown = null) {
  const dataTransfer = { types, files, dropEffect: 'none' };
  return { dataTransfer, relatedTarget, preventDefault: vi.fn() };
}

describe('dropTarget', () => {
  it('activates on file drags and delivers dropped files', () => {
    const onfiles = vi.fn();
    const onactive = vi.fn();
    const el = fakeElement();
    const cleanup = dropTarget({ onfiles, onactive })(el);

    const over = dragEvent(['Files']);
    el.fire('dragover', over);
    expect(over.preventDefault).toHaveBeenCalled();
    expect(over.dataTransfer.dropEffect).toBe('copy');
    expect(onactive).toHaveBeenLastCalledWith(true);

    const a = file('a');
    const drop = dragEvent(['Files'], [a]);
    el.fire('drop', drop);
    expect(drop.preventDefault).toHaveBeenCalled();
    expect(onactive).toHaveBeenLastCalledWith(false);
    expect(onfiles).toHaveBeenCalledWith([a]);

    cleanup();
    expect(el.listeners.size).toBe(0);
  });

  it('hands drops to onpicked when folders are accepted, otherwise to onfiles', async () => {
    const onfiles = vi.fn();
    const onpicked = vi.fn();
    let folders = true;
    const el = fakeElement();
    dropTarget({ onfiles, onpicked, folders: () => folders, onactive: vi.fn() })(el);
    const a = file('a');
    const drop = { ...dragEvent(['Files'], [a]) };
    (drop.dataTransfer as Record<string, unknown>).items = [];
    el.fire('drop', drop);
    expect(onfiles).not.toHaveBeenCalled();
    expect(await (onpicked.mock.calls[0]?.[0] as Promise<unknown>)).toEqual([{ file: a, path: '' }]);

    folders = false;
    el.fire('drop', dragEvent(['Files'], [a]));
    expect(onfiles).toHaveBeenCalledWith([a]);
  });

  it('ignores drags without files', () => {
    const onfiles = vi.fn();
    const onactive = vi.fn();
    const el = fakeElement();
    dropTarget({ onfiles, onactive })(el);
    const text = dragEvent(['text/plain']);
    el.fire('dragenter', text);
    el.fire('drop', text);
    expect(text.preventDefault).not.toHaveBeenCalled();
    expect(onactive).not.toHaveBeenCalled();
    expect(onfiles).not.toHaveBeenCalled();
  });

  it('does not deliver an empty drop', () => {
    const onfiles = vi.fn();
    const el = fakeElement();
    dropTarget({ onfiles, onactive: vi.fn() })(el);
    el.fire('drop', dragEvent(['Files'], []));
    expect(onfiles).not.toHaveBeenCalled();
  });

  it('reports an empty drop to onpicked in folders mode', async () => {
    const onfiles = vi.fn();
    const onpicked = vi.fn();
    const el = fakeElement();
    dropTarget({ onfiles, onpicked, folders: () => true, onactive: vi.fn() })(el);
    el.fire('drop', dragEvent(['Files'], []));
    expect(onfiles).not.toHaveBeenCalled();
    expect(await (onpicked.mock.calls[0]?.[0] as Promise<unknown>)).toEqual([]);
  });

  it('refuses drops while disabled', () => {
    const onfiles = vi.fn();
    const onactive = vi.fn();
    const el = fakeElement();
    dropTarget({ onfiles, onactive, disabled: () => true })(el);
    const over = dragEvent(['Files']);
    el.fire('dragover', over);
    expect(over.dataTransfer.dropEffect).toBe('none');
    expect(onactive).not.toHaveBeenCalled();
    el.fire('drop', dragEvent(['Files'], [file('a')]));
    expect(onfiles).not.toHaveBeenCalled();
  });

  it('handles a null dataTransfer on dragover', () => {
    const onactive = vi.fn();
    const el = fakeElement();
    dropTarget({ onfiles: vi.fn(), onactive })(el);
    el.fire('dragover', { dataTransfer: null, preventDefault: vi.fn() });
    expect(onactive).not.toHaveBeenCalled();
  });

  it('stays active when leaving towards a child', () => {
    const child = {};
    const onactive = vi.fn();
    const el = fakeElement([child]);
    dropTarget({ onfiles: vi.fn(), onactive })(el);
    el.fire('dragleave', dragEvent(['Files'], [], child));
    expect(onactive).not.toHaveBeenCalled();
    el.fire('dragleave', dragEvent(['Files'], [], {}));
    expect(onactive).toHaveBeenLastCalledWith(false);
    el.fire('dragleave', dragEvent(['Files']));
    expect(onactive).toHaveBeenCalledTimes(2);
  });
});

/** A fake document for the copy fallback. */
function fakeDocument(result: boolean | 'throw', active: unknown = null) {
  const areas: CopyTextArea[] = [];
  const attrs = new Map<string, string>();
  const doc: CopyDocument & { appended: CopyTextArea[]; removed: number; selected: number } = {
    appended: areas,
    removed: 0,
    selected: 0,
    activeElement: active,
    createElement: () => ({
      value: '',
      className: '',
      readOnly: false,
      select: () => {
        doc.selected++;
      },
      setAttribute: (name: string, value: string) => attrs.set(name, value),
    }),
    body: {
      appendChild: (node) => areas.push(node),
      removeChild: () => {
        doc.removed++;
      },
    },
    execCommand: () => {
      if (result === 'throw') {
        throw new Error('denied');
      }
      return result;
    },
  };
  return { doc, attrs };
}

describe('copyText', () => {
  it('uses the Clipboard API', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    expect(await copyText('abc', { clipboard: { writeText } })).toBe(true);
    expect(writeText).toHaveBeenCalledWith('abc');
  });

  it('falls back to execCommand when the Clipboard API fails', async () => {
    const writeText = vi.fn().mockRejectedValue(new Error('denied'));
    const focus = vi.fn();
    const { doc, attrs } = fakeDocument(true, { focus });
    expect(await copyText('abc', { clipboard: { writeText }, document: doc })).toBe(true);
    expect(doc.appended[0]?.value).toBe('abc');
    expect(doc.appended[0]?.readOnly).toBe(true);
    expect(doc.appended[0]?.className).toBe('visually-hidden');
    expect(attrs.get('aria-hidden')).toBe('true');
    expect(doc.selected).toBe(1);
    expect(doc.removed).toBe(1);
    expect(focus).toHaveBeenCalled();
  });

  it('reports a failed or throwing fallback', async () => {
    expect(await copyText('x', { document: fakeDocument(false).doc })).toBe(false);
    const throwing = fakeDocument('throw');
    expect(await copyText('x', { document: throwing.doc })).toBe(false);
    expect(throwing.doc.removed).toBe(1);
  });

  it('fails without clipboard nor document', async () => {
    expect(await copyText('x', {})).toBe(false);
  });

  it('reads the browser globals by default', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('navigator', { clipboard: { writeText } });
    expect(await copyText('y')).toBe(true);
    expect(writeText).toHaveBeenCalledWith('y');
  });
});

describe('isFocusable', () => {
  it('detects objects with a focus method', () => {
    expect(isFocusable({ focus: () => undefined })).toBe(true);
    expect(isFocusable({})).toBe(false);
    expect(isFocusable(null)).toBe(false);
    expect(isFocusable('x')).toBe(false);
  });
});

describe('languageName', () => {
  it('names a language in itself, capitalised', () => {
    expect(languageName('fr')).toBe('Français');
    expect(languageName('en')).toBe('English');
  });

  it('falls back to the code', () => {
    expect(languageName('zz')).toBe('zz');
    expect(languageName('not a tag!')).toBe('not a tag!');
  });
});

describe('helpHref', () => {
  it('links to a topic or the index', () => {
    expect(helpHref('deposit')).toBe('/help/deposit');
    expect(helpHref('admin-tenants', '/admin/')).toBe('/admin/help/admin-tenants');
    expect(helpHref(undefined)).toBe('/help');
    expect(helpHref('../x')).toBe('/help');
    expect(helpHref('Deposit', '/admin')).toBe('/admin/help');
  });
});

describe('percentOf', () => {
  it('clamps between 0 and 100', () => {
    expect(percentOf(50, 200)).toBe(25);
    expect(percentOf(300, 200)).toBe(100);
    expect(percentOf(-1, 200)).toBe(0);
    expect(percentOf(1, 0)).toBe(0);
    expect(percentOf(Number.NaN, 10)).toBe(0);
  });
});

describe('fileExtension / fileTypeLabel', () => {
  it.each([
    ['report.pdf', 'pdf', 'PDF'],
    ['Report.PDF', 'pdf', 'PDF'],
    ['archive.tar.gz', 'gz', 'GZ'],
    ['budget-2027.xlsx', 'xlsx', 'XLSX'],
    ['notes.markdown', 'markdown', 'MARK'],
    ['photos/chantier/IMG_0001.jpeg', 'jpeg', 'JPEG'],
    ['dossier\\plan.dwg', 'dwg', 'DWG'],
    ['README', '', ''],
    ['.bashrc', '', ''],
    ['trailing.', '', ''],
    ['folder.d/README', '', ''],
    ['', '', ''],
  ])('reads %j as %j (%j)', (name, ext, label) => {
    expect(fileExtension(name)).toBe(ext);
    expect(fileTypeLabel(name)).toBe(label);
  });

  it('cuts the label to the requested length', () => {
    expect(fileTypeLabel('a.markdown', 2)).toBe('MA');
    expect(fileTypeLabel('a.pdf', 0)).toBe('');
    expect(fileTypeLabel('a.pdf', -1)).toBe('');
  });
});

describe('abbreviateHash', () => {
  const sha = '9f2c1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a377bda41e';

  it('keeps the first and last 8 characters by default', () => {
    expect(abbreviateHash(sha)).toBe('9f2c1a2b…77bda41e');
  });

  it('accepts other lengths', () => {
    expect(abbreviateHash(sha, 4, 4)).toBe('9f2c…a41e');
    expect(abbreviateHash(sha, 6, 0)).toBe('9f2c1a…');
    expect(abbreviateHash(sha, -1, 4)).toBe('…a41e');
  });

  it('returns short values unchanged', () => {
    expect(abbreviateHash('')).toBe('');
    expect(abbreviateHash('abc')).toBe('abc');
    expect(abbreviateHash('0123456789abcdefg')).toBe('0123456789abcdefg');
    expect(abbreviateHash('0123456789abcdefgh')).toBe('01234567…abcdefgh');
  });
});

describe('volumeState', () => {
  const GB = 2 ** 30;

  it('gives the share of the limit', () => {
    expect(volumeState(4.2 * GB, 20 * GB)).toEqual({ value: 4.2 * GB, percent: 21, over: false });
    expect(volumeState(0, 20 * GB)).toEqual({ value: 0, percent: 0, over: false });
    expect(volumeState(20 * GB, 20 * GB)).toEqual({ value: 20 * GB, percent: 100, over: false });
  });

  it('shows at least 1 % when something is used', () => {
    expect(volumeState(1, 20 * GB).percent).toBe(1);
  });

  it('reports a volume over the limit and clamps the meter', () => {
    expect(volumeState(25 * GB, 20 * GB)).toEqual({ value: 20 * GB, percent: 125, over: true });
  });

  it('has no percentage without a positive limit', () => {
    expect(volumeState(5, undefined)).toEqual({ value: 0, percent: undefined, over: false });
    expect(volumeState(5, 0)).toEqual({ value: 0, percent: undefined, over: false });
    expect(volumeState(5, Number.NaN)).toEqual({ value: 0, percent: undefined, over: false });
  });

  it('ignores invalid volumes', () => {
    expect(volumeState(-5, 100)).toEqual({ value: 0, percent: 0, over: false });
    expect(volumeState(Number.NaN, 100)).toEqual({ value: 0, percent: 0, over: false });
  });
});
