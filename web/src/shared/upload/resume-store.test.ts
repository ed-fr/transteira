import { describe, expect, it } from 'vitest';
import {
  createResumeStore,
  fingerprint,
  isResumeE2E,
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

const KEY = 'A'.repeat(43);
const SALT = 'B'.repeat(21) + 'A';
const SHA = 'ab'.repeat(32);
const e2eRecord: ResumeRecord = {
  ...record,
  e2e: { key: KEY, salts: [SALT, SALT, SALT], sha256: [SHA, SHA, SHA], chunkSize: 1024 * 1024 },
};

describe('resume store with end-to-end encryption', () => {
  it('saves, loads and clears the key and the salts', () => {
    const storage = new MemoryStorage();
    const store = createResumeStore(() => storage);
    store.save({ ...e2eRecord, e2e: { ...e2eRecord.e2e, extra: 1 } } as ResumeRecord);
    expect(JSON.parse(storage.getItem(RESUME_STORAGE_KEY) ?? '')).toEqual(e2eRecord);
    expect(store.load()).toEqual(e2eRecord);
    store.clear();
    expect(storage.length).toBe(0);
    store.save(record);
    expect(store.load()).not.toHaveProperty('e2e');
  });

  it('validates the encryption part strictly', () => {
    expect(isResumeE2E(e2eRecord.e2e, 3)).toBe(true);
    expect(isResumeRecord(e2eRecord)).toBe(true);
    const bad: unknown[] = [
      null,
      'x',
      { ...e2eRecord.e2e, key: 'A'.repeat(42) },
      { ...e2eRecord.e2e, key: 'A'.repeat(42) + 'B' },
      { ...e2eRecord.e2e, key: 7 },
      { ...e2eRecord.e2e, salts: [SALT, SALT] },
      { ...e2eRecord.e2e, salts: 'x' },
      { ...e2eRecord.e2e, salts: [SALT, SALT, 'AAAA'] },
      { ...e2eRecord.e2e, sha256: [SHA, SHA] },
      { ...e2eRecord.e2e, sha256: 'x' },
      { ...e2eRecord.e2e, sha256: [SHA, SHA, SHA.toUpperCase()] },
      { ...e2eRecord.e2e, sha256: [SHA, SHA, 7] },
      { ...e2eRecord.e2e, sha256: undefined },
      { ...e2eRecord.e2e, chunkSize: 1000 },
      { ...e2eRecord.e2e, chunkSize: '1048576' },
    ];
    for (const e2e of bad) {
      expect(isResumeE2E(e2e, 3)).toBe(false);
      expect(isResumeRecord({ ...record, e2e })).toBe(false);
    }
  });
});

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
