// Unit tests of tte2.ts beyond the reference vectors: key handling, derivation, header, sizes and
// range encryption.

import { describe, expect, it } from 'vitest';
import { decryptBytes } from './decrypt';
import { isE2EError, type E2EErrorCode } from './errors';
import {
  DEFAULT_CHUNK_SIZE,
  ENCODED_KEY_SIZE,
  HEADER_SIZE,
  KEY_SIZE,
  MAX_CHUNKS,
  MAX_CHUNK_SIZE,
  MAX_INDEX,
  MAX_METADATA_ENCODED_SIZE,
  MIN_CHUNK_SIZE,
  MIN_FILE_SIZE,
  checkIndex,
  chunkNonce,
  ciphertextSize,
  deriveFileKey,
  deriveMessageKey,
  deriveMetadataKey,
  e2eFileName,
  encodeKey,
  encryptRange,
  generateTransferKey,
  importTransferKey,
  isE2EFileName,
  newHeader,
  parseHeader,
  parseKey,
  parseKeyInput,
  plaintextSize,
  prepareFileEncryption,
  toBaseKey,
  validChunkSize,
} from './tte2';
import { firstDifference, pattern, seededRandom } from './tte2-helpers.test-helper';

/** Asserts that f throws (or rejects with) an E2EError of the given code. */
async function expectCode(f: () => unknown, code: E2EErrorCode): Promise<void> {
  let caught: unknown;
  try {
    await f();
  } catch (err) {
    caught = err;
  }
  expect(isE2EError(caught, code), String(caught)).toBe(true);
}

const fixedKey = Uint8Array.from({ length: KEY_SIZE }, (_, i) => i);

describe('constants', () => {
  it('match the Go reference', () => {
    expect([HEADER_SIZE, MIN_FILE_SIZE, DEFAULT_CHUNK_SIZE]).toEqual([32, 48, 1 << 20]);
    expect([MIN_CHUNK_SIZE, MAX_CHUNK_SIZE, MAX_CHUNKS, MAX_INDEX]).toEqual([
      1 << 16,
      1 << 23,
      2 ** 32,
      2 ** 32 - 1,
    ]);
    expect(MAX_METADATA_ENCODED_SIZE).toBe(5462);
  });
});

describe('transfer key', () => {
  it('is 32 fresh random bytes', () => {
    const a = generateTransferKey();
    expect(a.length).toBe(KEY_SIZE);
    expect(a).not.toEqual(generateTransferKey());
    expect(encodeKey(a)).toHaveLength(ENCODED_KEY_SIZE);
    expect(parseKey(encodeKey(a))).toEqual(a);
  });

  it('refuses keys of the wrong size', async () => {
    await expectCode(() => encodeKey(new Uint8Array(31)), 'invalid-key');
    await expectCode(() => importTransferKey(new Uint8Array(33)), 'invalid-key');
  });

  it('parses strictly', async () => {
    const s = encodeKey(fixedKey);
    expect(s.endsWith('8')).toBe(true); // last value a multiple of 4: canonical
    for (const bad of [
      s.slice(1),
      s + 'A',
      s.slice(0, 42) + '9',
      s.slice(0, 42) + '=',
      '+' + s.slice(1),
      '',
    ]) {
      await expectCode(() => parseKey(bad), 'invalid-key');
    }
  });

  it('accepts a bare key, k=, or a whole link, with whitespace', async () => {
    const s = encodeKey(fixedKey);
    for (const input of [
      s,
      `  ${s}\n`,
      `k=${s}`,
      `https://transfer.entity-a.example.com/d/tok#k=${s}`,
      ` https://transfer.entity-a.example.com/d/tok#x=1&k=${s}&y=2 `,
    ]) {
      expect(parseKeyInput(input)).toEqual(fixedKey);
    }
    await expectCode(() => parseKeyInput('https://transfer.example.com/d/tok#x=1'), 'invalid-key');
    await expectCode(() => parseKeyInput('https://transfer.example.com/d/tok#k=abc'), 'invalid-key');
    await expectCode(() => parseKeyInput('https://transfer.example.com/d/tok'), 'invalid-key');
  });

  it('imports a non-extractable HKDF base key', async () => {
    const base = await importTransferKey(fixedKey);
    expect(base.extractable).toBe(false);
    expect(base.algorithm.name).toBe('HKDF');
    expect([...base.usages].sort()).toEqual(['deriveBits', 'deriveKey']);
    expect(await toBaseKey(base)).toBe(base);
  });

  it('refuses a CryptoKey that is not an HKDF base key', async () => {
    const aes = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt']);
    await expectCode(() => toBaseKey(aes), 'invalid-key');
    const bitsOnly = await crypto.subtle.importKey('raw', fixedKey, 'HKDF', false, ['deriveBits']);
    await expectCode(() => toBaseKey(bitsOnly), 'invalid-key');
  });
});

describe('key derivation', () => {
  it('gives the same keys from bytes and from the base key', async () => {
    const base = await importTransferKey(fixedKey);
    const salt = new Uint8Array(16).fill(7);
    const header = newHeader(MIN_CHUNK_SIZE, salt);
    const blob = new Blob([pattern(10)]);
    const fromBytes = await deriveFileKey(fixedKey, salt, 3);
    const fromBase = await deriveFileKey(base, salt, 3);
    expect(fromBase.extractable).toBe(false);
    expect([...fromBase.usages].sort()).toEqual(['decrypt', 'encrypt']);
    expect(await encryptRange(fromBytes, header, blob, 10, 0, 58)).toEqual(
      await encryptRange(fromBase, header, blob, 10, 0, 58),
    );
    expect((await deriveMetadataKey(base, 0)).algorithm.name).toBe('AES-GCM');
    expect((await deriveMessageKey(base)).algorithm.name).toBe('AES-GCM');
  });

  it('checks the index and the salt', async () => {
    for (const bad of [-1, 1.5, MAX_INDEX + 1, Number.NaN]) {
      await expectCode(() => checkIndex(bad), 'invalid-index');
      await expectCode(() => deriveMetadataKey(fixedKey, bad), 'invalid-index');
    }
    checkIndex(MAX_INDEX);
    await expectCode(() => deriveFileKey(fixedKey, new Uint8Array(15), 0), 'bad-header');
  });
});

describe('header', () => {
  it('validates the chunk size', async () => {
    expect(newHeader().chunkSize).toBe(DEFAULT_CHUNK_SIZE);
    for (const c of [MIN_CHUNK_SIZE, 1 << 17, 1 << 20, MAX_CHUNK_SIZE]) {
      expect(validChunkSize(c)).toBe(true);
      expect(parseHeader(newHeader(c).bytes).chunkSize).toBe(c);
    }
    for (const c of [0, MIN_CHUNK_SIZE - 1, MIN_CHUNK_SIZE / 2, 3 << 16, MAX_CHUNK_SIZE * 2, 65536.5]) {
      expect(validChunkSize(c)).toBe(false);
      await expectCode(() => newHeader(c), 'invalid-chunk-size');
    }
  });

  it('draws a fresh salt unless given', async () => {
    expect(newHeader().salt).not.toEqual(newHeader().salt);
    const salt = Uint8Array.from({ length: 16 }, (_, i) => 100 + i);
    const h = newHeader(MIN_CHUNK_SIZE, salt);
    expect(Array.from(h.bytes.subarray(0, 12))).toEqual([0x54, 0x54, 0x45, 0x32, 1, 1, 0, 0, 0, 1, 0, 0]);
    expect(h.bytes.subarray(12, 28)).toEqual(salt);
    expect(Array.from(h.bytes.subarray(28))).toEqual([0, 0, 0, 0]);
    const parsed = parseHeader(h.bytes);
    expect(parsed.salt).toEqual(salt);
    expect(parsed.bytes).toEqual(h.bytes);
    await expectCode(() => newHeader(MIN_CHUNK_SIZE, new Uint8Array(17)), 'bad-header');
  });

  it('refuses every wrong byte', async () => {
    const good = newHeader(MIN_CHUNK_SIZE, new Uint8Array(16).fill(0xff)).bytes;
    await expectCode(() => parseHeader(good.subarray(0, 31)), 'bad-header');
    for (let i = 0; i < HEADER_SIZE; i++) {
      if (i >= 12 && i < 28) continue;
      const b = good.slice();
      b[i] = i === 9 ? 3 : b[i]! ^ 0x01;
      await expectCode(() => parseHeader(b), 'bad-header');
    }
    const zero = good.slice();
    zero[9] = 0;
    await expectCode(() => parseHeader(zero), 'bad-header');
  });

  it('builds STREAM nonces', () => {
    expect(Array.from(chunkNonce(0x01020304, true))).toEqual([0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 1]);
    expect(Array.from(chunkNonce(MAX_INDEX, false))).toEqual([0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0]);
  });
});

describe('sizes', () => {
  it('refuses impossible inputs', () => {
    expect(ciphertextSize(-1, MIN_CHUNK_SIZE)).toBe(-1);
    expect(ciphertextSize(1.5, MIN_CHUNK_SIZE)).toBe(-1);
    expect(ciphertextSize(1, MIN_CHUNK_SIZE + 1)).toBe(-1);
    expect(ciphertextSize(MAX_CHUNKS * MIN_CHUNK_SIZE, MIN_CHUNK_SIZE)).toBe(
      32 + MAX_CHUNKS * (MIN_CHUNK_SIZE + 16),
    );
    expect(ciphertextSize(MAX_CHUNKS * MIN_CHUNK_SIZE + 1, MIN_CHUNK_SIZE)).toBe(-1);
    expect(plaintextSize(48.5, MIN_CHUNK_SIZE)).toBe(-1);
    expect(plaintextSize(100, MIN_CHUNK_SIZE + 1)).toBe(-1);
  });

  it('round-trips every small size', () => {
    for (let p = 0; p < 3 * MIN_CHUNK_SIZE + 40; p += 997) {
      expect(plaintextSize(ciphertextSize(p, MIN_CHUNK_SIZE), MIN_CHUNK_SIZE)).toBe(p);
    }
  });
});

describe('range encryption', () => {
  const c = MIN_CHUNK_SIZE;

  it('regenerates any range of the stream identically', async () => {
    const rand = seededRandom(42);
    for (const n of [0, 1, c - 1, c, c + 1, 3 * c, 3 * c + 5]) {
      const plain = pattern(n);
      const blob = new Blob([plain]);
      const enc = await prepareFileEncryption(fixedKey, 5, blob, { chunkSize: c });
      expect(enc.size).toBe(ciphertextSize(n, c));
      expect(enc.plainSize).toBe(n);
      expect(enc.index).toBe(5);
      const full = await enc.range(0, enc.size);
      expect(firstDifference(await decryptBytes({ key: fixedKey, index: 5 }, full), plain)).toBe(-1);
      // Cut the stream at random offsets, header and chunk boundaries included.
      const cuts = new Set([0, enc.size, 16, HEADER_SIZE, HEADER_SIZE + c + 16, HEADER_SIZE + c + 15]);
      for (let k = 0; k < 6; k++) cuts.add(rand(enc.size + 1));
      const offsets = [...cuts].filter((o) => o <= enc.size).sort((a, b) => a - b);
      const parts: Uint8Array[] = [];
      for (let k = 0; k + 1 < offsets.length; k++) parts.push(await enc.range(offsets[k]!, offsets[k + 1]!));
      const joined = new Uint8Array(enc.size);
      let o = 0;
      for (const p of parts) {
        joined.set(p, o);
        o += p.length;
      }
      expect(firstDifference(joined, full)).toBe(-1);
      expect(await enc.range(7, 7)).toEqual(new Uint8Array(0));
    }
  });

  it('uses the default chunk size and a random salt', async () => {
    const blob = new Blob([pattern(10)]);
    const a = await prepareFileEncryption(fixedKey, 0, blob);
    const b = await prepareFileEncryption(fixedKey, 0, blob);
    expect(a.header.chunkSize).toBe(DEFAULT_CHUNK_SIZE);
    expect(await a.range(0, a.size)).not.toEqual(await b.range(0, b.size));
  });

  it('refuses bad ranges, sizes and indexes', async () => {
    const plain = pattern(100);
    const blob = new Blob([plain]);
    const header = newHeader(c);
    const fileKey = await deriveFileKey(fixedKey, header.salt, 0);
    const total = ciphertextSize(100, c);
    for (const [s, e] of [
      [-1, 10],
      [10, 9],
      [0, total + 1],
      [0.5, 10],
      [0, Number.POSITIVE_INFINITY],
    ] as const) {
      await expect(encryptRange(fileKey, header, blob, 100, s, e)).rejects.toThrow(RangeError);
    }
    await expectCode(() => encryptRange(fileKey, header, blob, 99, 0, 10), 'size-mismatch');
    const huge = MAX_CHUNKS * c + 1;
    const fake = { size: huge } as Blob;
    await expectCode(() => encryptRange(fileKey, header, fake, huge, 0, 10), 'counter-overflow');
    await expectCode(() => prepareFileEncryption(fixedKey, 0, fake, { chunkSize: c }), 'counter-overflow');
    await expectCode(() => prepareFileEncryption(fixedKey, -1, blob), 'invalid-index');
  });
});

describe('generic file names', () => {
  it('names file i "file-<i+1>.tte2"', async () => {
    expect(e2eFileName(0)).toBe('file-1.tte2');
    expect(e2eFileName(41)).toBe('file-42.tte2');
    await expectCode(() => e2eFileName(-1), 'invalid-index');
    expect(isE2EFileName('file-1.tte2')).toBe(true);
    for (const bad of [
      'file-0.tte2',
      'file-01.tte2',
      'file-1.tte',
      'File-1.tte2',
      'file-.tte2',
      'xfile-1.tte2',
    ]) {
      expect(isE2EFileName(bad)).toBe(false);
    }
  });
});
