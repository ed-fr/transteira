import { describe, expect, it } from 'vitest';
import {
  createResumeStore,
  fingerprint,
  isResumeRecord,
  matchFiles,
  RESUME_STORAGE_KEY,
  type ResumeRecord,
} from './resume-store';

class MemoryStorage implements Storage {
  readonly map = new Map<string, string>();
  get length(): number {
    return this.map.size;
  }
  clear(): void {
    this.map.clear();
  }
  getItem(key: string): string | null {
    return this.map.get(key) ?? null;
  }
  key(index: number): string | null {
    return [...this.map.keys()][index] ?? null;
  }
  removeItem(key: string): void {
    this.map.delete(key);
  }
  setItem(key: string, value: string): void {
    this.map.set(key, value);
  }
}

const throwing = {
  getItem: () => {
    throw new Error('denied');
  },
  setItem: () => {
    throw new Error('denied');
  },
  removeItem: () => {
    throw new Error('denied');
  },
} as unknown as Storage;

const record: ResumeRecord = {
  transferId: 'trf_1',
  files: [
    { name: 'a.bin', size: 10, lastModified: 1, path: '' },
    { name: 'a.bin', size: 10, lastModified: 2, path: '' },
    { name: 'b.bin', size: 0, lastModified: 3, path: '' },
  ],
};

describe('resume store', () => {
  it('saves, loads and clears the record', () => {
    const storage = new MemoryStorage();
    const store = createResumeStore(() => storage);
    expect(store.load()).toBeUndefined();
    store.save({ ...record, extra: 'dropped' } as ResumeRecord);
    expect(JSON.parse(storage.getItem(RESUME_STORAGE_KEY) ?? '')).toEqual(record);
    expect(store.load()).toEqual(record);
    store.clear();
    expect(storage.length).toBe(0);
  });

  it('ignores invalid or corrupted content', () => {
    const storage = new MemoryStorage();
    const store = createResumeStore(() => storage, 'k');
    storage.setItem('k', '{not json');
    expect(store.load()).toBeUndefined();
    storage.setItem(
      'k',
      JSON.stringify({ transferId: 'x', files: [{ name: 'a', size: -1, lastModified: 0 }] }),
    );
    expect(store.load()).toBeUndefined();
  });

  it('survives a missing or throwing storage', () => {
    for (const storage of [() => undefined, () => throwing]) {
      const store = createResumeStore(storage);
      store.save(record);
      expect(store.load()).toBeUndefined();
      store.clear();
    }
  });

  it('uses sessionStorage by default', () => {
    const storage = new MemoryStorage();
    const g = globalThis as Record<string, unknown>;
    const original = g.sessionStorage;
    g.sessionStorage = storage;
    try {
      createResumeStore().save(record);
      expect(storage.getItem(RESUME_STORAGE_KEY)).not.toBeNull();
    } finally {
      g.sessionStorage = original;
    }
  });

  it('validates records', () => {
    expect(isResumeRecord(record)).toBe(true);
    expect(isResumeRecord(null)).toBe(false);
    expect(isResumeRecord('x')).toBe(false);
    expect(isResumeRecord({ transferId: '', files: record.files })).toBe(false);
    expect(isResumeRecord({ transferId: 't', files: [] })).toBe(false);
    expect(isResumeRecord({ transferId: 't', files: 'x' })).toBe(false);
    expect(isResumeRecord({ transferId: 't', files: [null] })).toBe(false);
    expect(isResumeRecord({ transferId: 't', files: [{ name: 'a', size: 1.5, lastModified: 0 }] })).toBe(
      false,
    );
    expect(isResumeRecord({ transferId: 't', files: [{ name: 'a', size: 1, lastModified: NaN }] })).toBe(
      false,
    );
    expect(isResumeRecord({ transferId: 't', files: [{ name: 1, size: 1, lastModified: 0 }] })).toBe(false);
  });
});

describe('fingerprint and matchFiles', () => {
  it('fingerprints a file', () => {
    expect(fingerprint({ name: 'x', size: 3, lastModified: 9, extra: true } as never)).toEqual({
      name: 'x',
      size: 3,
      lastModified: 9,
      path: '',
    });
    expect(fingerprint({ name: 'x', size: 3, lastModified: 9, path: 'a/b' })).toMatchObject({ path: 'a/b' });
  });

  it('reads a record saved before folders existed (no path = root)', () => {
    const storage = new MemoryStorage();
    const store = createResumeStore(() => storage, 'k');
    storage.setItem(
      'k',
      JSON.stringify({ transferId: 't', files: [{ name: 'a', size: 1, lastModified: 2 }] }),
    );
    expect(store.load()?.files).toEqual([{ name: 'a', size: 1, lastModified: 2, path: '' }]);
  });

  it('does not pair files of the same name in different folders', () => {
    const rec: ResumeRecord = {
      transferId: 't',
      files: [{ name: 'a', size: 1, lastModified: 2, path: 'x' }],
    };
    expect(matchFiles(rec, [{ name: 'a', size: 1, lastModified: 2, path: 'y' }]).complete).toBe(false);
    expect(matchFiles(rec, [{ name: 'a', size: 1, lastModified: 2, path: 'x' }]).complete).toBe(true);
  });

  it('pairs reselected files in the record order, each used once', () => {
    const selected = [
      { name: 'b.bin', size: 0, lastModified: 3, id: 'B' },
      { name: 'a.bin', size: 10, lastModified: 2, id: 'A2' },
      { name: 'a.bin', size: 10, lastModified: 1, id: 'A1' },
      { name: 'c.bin', size: 1, lastModified: 4, id: 'C' },
    ];
    const m = matchFiles(record, selected);
    expect(m.files.map((f) => f?.id)).toEqual(['A1', 'A2', 'B']);
    expect(m).toMatchObject({ missing: [], complete: true });
  });

  it('reports missing files (same name but modified)', () => {
    const m = matchFiles(record, [
      { name: 'a.bin', size: 10, lastModified: 1 },
      { name: 'b.bin', size: 1, lastModified: 3 },
    ]);
    expect(m.files.map((f) => f?.lastModified)).toEqual([1, undefined, undefined]);
    expect(m.missing).toEqual([record.files[1], record.files[2]]);
    expect(m.complete).toBe(false);
  });
});
