// Unit tests of decrypt.ts beyond the reference vectors: arbitrary input chunking, size checks,
// key sources, sticky errors and the counter limit.

import { describe, expect, it } from 'vitest';
import { StreamDecryptor, createDecryptStream, decryptBytes } from './decrypt';
import { isE2EError, type E2EErrorCode } from './errors';
import {
  HEADER_SIZE,
  MAX_CHUNKS,
  MIN_CHUNK_SIZE,
  TAG_SIZE,
  deriveFileKey,
  importTransferKey,
  prepareFileEncryption,
} from './tte2';
import { firstDifference, pattern, pipe, seededRandom, split } from './tte2-helpers.test-helper';

const key = Uint8Array.from({ length: 32 }, (_, i) => 200 - i);
const c = MIN_CHUNK_SIZE;
const block = c + TAG_SIZE;

/** Encrypts the pattern of n bytes as file index with 64 KiB chunks. */
async function encrypt(n: number, index = 2): Promise<{ plain: Uint8Array; ct: Uint8Array<ArrayBuffer> }> {
  const plain = pattern(n);
  const enc = await prepareFileEncryption(key, index, new Blob([plain]), { chunkSize: c });
  return { plain, ct: await enc.range(0, enc.size) };
}

/** Returns the E2E code a promise rejects with. */
async function codeOf(p: Promise<unknown>): Promise<E2EErrorCode | 'none'> {
  try {
    await p;
    return 'none';
  } catch (err) {
    if (isE2EError(err)) return err.code;
    throw err;
  }
}

describe('stream decryption', () => {
  it('decrypts whatever the piece sizes', async () => {
    const { plain, ct } = await encrypt(3 * c + 123);
    const base = await importTransferKey(key);
    for (const [seed, max] of [
      [1, 1000],
      [2, block + 1],
      [3, 3 * block],
      [4, 40],
    ] as const) {
      const out = await pipe(
        createDecryptStream({ key: base, index: 2 }),
        split(ct, seededRandom(seed), max),
      );
      expect(firstDifference(out, plain)).toBe(-1);
    }
    expect(firstDifference(await pipe(createDecryptStream({ key, index: 2 }), [ct]), plain)).toBe(-1);
  });

  it('decrypts an empty file to nothing', async () => {
    const { ct } = await encrypt(0);
    expect(await pipe(createDecryptStream({ key, index: 2 }, { expectedPlainSize: 0 }), [ct])).toEqual(
      new Uint8Array(0),
    );
  });

  it('accepts a key-derivation callback receiving the header', async () => {
    const { plain, ct } = await encrypt(c + 1);
    const base = await importTransferKey(key);
    const seen: number[] = [];
    const stream = createDecryptStream(async (h) => {
      seen.push(h.chunkSize);
      return deriveFileKey(base, h.salt, 2);
    });
    expect(firstDifference(await pipe(stream, [ct]), plain)).toBe(-1);
    expect(seen).toEqual([c]);
  });

  it('checks the expected plaintext size', async () => {
    const { plain, ct } = await encrypt(2 * c + 5);
    expect(await codeOf(decryptBytes({ key, index: 2 }, ct, { expectedPlainSize: plain.length }))).toBe(
      'none',
    );
    expect(await codeOf(decryptBytes({ key, index: 2 }, ct, { expectedPlainSize: plain.length + 1 }))).toBe(
      'size-mismatch',
    );
    // Too much plaintext fails at the first chunk exceeding the size, before the end.
    const d = new StreamDecryptor({ key, index: 2 }, { expectedPlainSize: 10 });
    expect(await codeOf(d.push(ct))).toBe('size-mismatch');
    expect(await codeOf(decryptBytes({ key, index: 2 }, ct, { expectedPlainSize: 2 * c + 4 }))).toBe(
      'size-mismatch',
    );
  });

  it('refuses invalid construction arguments synchronously', () => {
    expect(() => createDecryptStream({ key: new Uint8Array(31), index: 0 })).toThrow(/invalid-key/);
    expect(() => createDecryptStream({ key, index: -1 })).toThrow(/invalid-index/);
    for (const e of [-1, 1.5, Number.NaN]) {
      expect(() => createDecryptStream({ key, index: 0 }, { expectedPlainSize: e })).toThrow(RangeError);
    }
  });

  it('reports a stream ending inside the header as truncated', async () => {
    const { ct } = await encrypt(10);
    for (const n of [0, 1, HEADER_SIZE - 1]) {
      expect(await codeOf(pipe(createDecryptStream({ key, index: 2 }), [ct.subarray(0, n)]))).toBe(
        'truncated',
      );
    }
  });

  it('detects chunks swapped between two streams of the same file', async () => {
    const a = await encrypt(2 * c);
    const b = await encrypt(2 * c);
    const mixed = new Uint8Array(a.ct);
    mixed.set(b.ct.subarray(HEADER_SIZE, HEADER_SIZE + block), HEADER_SIZE);
    expect(await codeOf(decryptBytes({ key, index: 2 }, mixed))).toBe('auth');
  });
});

describe('StreamDecryptor', () => {
  it('exposes the header and the counter', async () => {
    const { ct } = await encrypt(2 * c + 1);
    const d = new StreamDecryptor({ key, index: 2 });
    expect(d.parsedHeader).toBeUndefined();
    expect(await d.push(ct.subarray(0, 10))).toEqual([]);
    expect(await d.push(ct.subarray(10, HEADER_SIZE + block))).toEqual([]);
    expect(d.parsedHeader?.chunkSize).toBe(c);
    const out = await d.push(ct.subarray(HEADER_SIZE + block));
    expect(out.map((p) => p.length)).toEqual([c, c]);
    expect(d.counter).toBe(2);
    expect((await d.finish()).length).toBe(1);
  });

  it('makes errors sticky and refuses use after finish', async () => {
    const { ct } = await encrypt(2 * c);
    const bad = new Uint8Array(ct);
    bad[HEADER_SIZE + 3]! ^= 1;
    const d = new StreamDecryptor({ key, index: 2 });
    expect(await codeOf(d.push(bad))).toBe('auth');
    expect(await codeOf(d.push(new Uint8Array(1)))).toBe('auth');
    expect(await codeOf(d.finish())).toBe('auth');

    const ok = new StreamDecryptor({ key, index: 2 });
    await ok.push(ct);
    await ok.finish();
    await expect(ok.finish()).rejects.toThrow(/already finished/);
    const again = new StreamDecryptor({ key, index: 2 });
    await again.push(ct);
    await again.finish();
    await expect(again.push(ct)).rejects.toThrow(/already finished/);
  });

  it('refuses a middle chunk at the last counter value', async () => {
    const { ct } = await encrypt(2 * c);
    const d = new StreamDecryptor({ key, index: 2 });
    d.counter = MAX_CHUNKS - 1;
    expect(await codeOf(d.push(ct))).toBe('counter-overflow');
  });
});
