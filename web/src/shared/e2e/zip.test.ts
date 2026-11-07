import { randomBytes } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import zlib from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { createZipStream, dosTime, ZIP64_ALWAYS, zipSize, type ZipEntry, type ZipOptions } from './zip';

/** A stream yielding `data` cut in chunks of `chunk` bytes (an empty chunk is injected between). */
function streamOf(data: Uint8Array, chunk = 7): ReadableStream<Uint8Array> {
  let pos = 0;
  let injected = false;
  return new ReadableStream<Uint8Array>({
    pull(c) {
      if (pos >= data.length) return c.close();
      if (!injected) {
        injected = true;
        return c.enqueue(new Uint8Array(0));
      }
      c.enqueue(data.slice(pos, pos + chunk));
      pos += chunk;
    },
  });
}

const text = (s: string): Uint8Array => new TextEncoder().encode(s);

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

async function collect(s: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  const r = s.getReader();
  for (;;) {
    const { done, value } = await r.read();
    if (done) return concat(parts);
    parts.push(value);
  }
}

function indexOfBytes(hay: Uint8Array, needle: number[]): number {
  outer: for (let i = 0; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

const u16 = (b: Uint8Array, at: number): number => new DataView(b.buffer, b.byteOffset).getUint16(at, true);
const u32 = (b: Uint8Array, at: number): number => new DataView(b.buffer, b.byteOffset).getUint32(at, true);
const same = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((v, i) => v === b[i]);

/** Reads a store-mode archive through its central directory (ZIP64 aware) and checks CRC-32 values. */
function readZip(buf: Uint8Array): { name: string; data: Uint8Array }[] {
  const v = new DataView(buf.buffer, buf.byteOffset, buf.length);
  const u64 = (at: number): number => v.getUint32(at, true) + v.getUint32(at + 4, true) * 2 ** 32;
  const eocd = buf.length - 22;
  expect(v.getUint32(eocd, true)).toBe(0x06054b50);
  let count = v.getUint16(eocd + 10, true);
  let p = v.getUint32(eocd + 16, true);
  if (count === 0xffff || p === 0xffffffff) {
    expect(v.getUint32(eocd - 20, true)).toBe(0x07064b50);
    const record = u64(eocd - 20 + 8);
    expect(v.getUint32(record, true)).toBe(0x06064b50);
    count = u64(record + 32);
    p = u64(record + 48);
  }
  const out: { name: string; data: Uint8Array }[] = [];
  for (let i = 0; i < count; i++) {
    expect(v.getUint32(p, true)).toBe(0x02014b50);
    expect(v.getUint16(p + 10, true)).toBe(0);
    const crc = v.getUint32(p + 16, true);
    let size = v.getUint32(p + 24, true);
    const nameLen = v.getUint16(p + 28, true);
    const extraLen = v.getUint16(p + 30, true);
    let local = v.getUint32(p + 42, true);
    const name = new TextDecoder().decode(buf.subarray(p + 46, p + 46 + nameLen));
    const extra = p + 46 + nameLen;
    if (extraLen > 0) {
      expect(v.getUint16(extra, true)).toBe(1);
      let q = extra + 4;
      if (size === 0xffffffff) {
        size = u64(q);
        q += 16;
      }
      if (local === 0xffffffff) local = u64(q);
    }
    expect(v.getUint32(local, true)).toBe(0x04034b50);
    const start = local + 30 + v.getUint16(local + 26, true) + v.getUint16(local + 28, true);
    const data = buf.subarray(start, start + size);
    expect(zlib.crc32(data)).toBe(crc);
    out.push({ name, data });
    p = extra + extraLen + v.getUint16(p + 32, true);
  }
  return out;
}

interface Spec {
  name: string;
  data: Uint8Array;
  modified?: Date;
}

function specs(): Spec[] {
  return [
    { name: 'a.txt', data: text('hello'), modified: new Date('2024-05-06T07:08:10Z') },
    { name: 'dir/sub/b.bin', data: randomBytes(1000) },
    { name: 'empty', data: new Uint8Array(0) },
    { name: 'dossier/é €.txt', data: randomBytes(33), modified: new Date('1970-01-01') },
    { name: 'far/future', data: text('x'), modified: new Date('2200-01-01') },
  ];
}

function toEntries(list: Spec[], withSize: boolean): ZipEntry[] {
  return list.map((s) => ({
    name: s.name,
    size: withSize ? s.data.length : undefined,
    modified: s.modified,
    data: streamOf(s.data),
  }));
}

function check(archive: Uint8Array, list: Spec[]): void {
  const got = readZip(archive);
  expect(got.map((e) => e.name)).toEqual(list.map((s) => s.name));
  got.forEach((e, i) => {
    expect(same(e.data, list[i]!.data)).toBe(true);
    expect(zlib.crc32(e.data)).toBe(zlib.crc32(list[i]!.data));
  });
}

const hasUnzip = spawnSync('unzip', ['-v']).status === 0;

function unzipTest(archive: Uint8Array): void {
  const dir = mkdtempSync(join(tmpdir(), 'zip-'));
  try {
    const file = join(dir, 'a.zip');
    writeFileSync(file, archive);
    expect(execFileSync('unzip', ['-t', file]).toString()).toContain('No errors detected');
  } finally {
    rmSync(dir, { recursive: true });
  }
}

const variants: [string, ZipOptions, boolean][] = [
  ['default, known sizes', {}, true],
  ['default, unknown sizes (ZIP64)', {}, false],
  ['forced ZIP64 for every entry', { zip64Threshold: ZIP64_ALWAYS }, true],
  ['threshold 500 bytes (mixed)', { zip64Threshold: 500 }, true],
];

describe('createZipStream', () => {
  it.each(variants)('writes a readable archive: %s', async (_, options, withSize) => {
    const list = specs();
    const archive = await collect(createZipStream(toEntries(list, withSize), options));
    check(archive, list);
    if (hasUnzip) unzipTest(archive);
  });

  it('accepts an async iterable of entries and an empty archive', async () => {
    const list = specs();
    async function* gen(): AsyncGenerator<ZipEntry> {
      for (const e of toEntries(list, true)) yield e;
    }
    check(await collect(createZipStream(gen())), list);
    const empty = await collect(createZipStream([]));
    expect(empty.length).toBe(22);
    expect(readZip(empty)).toEqual([]);
  });

  it('stores the UTF-8 name flag, data descriptor flag and DOS timestamps', async () => {
    const archive = await collect(
      createZipStream([
        { name: 'é', size: 1, modified: new Date('2024-05-06T07:08:10Z'), data: streamOf(text('x')) },
      ]),
    );
    expect(u16(archive, 6)).toBe((1 << 3) | (1 << 11));
    expect(u16(archive, 10)).toBe((7 << 11) | (8 << 5) | 5);
    expect(u16(archive, 12)).toBe((44 << 9) | (5 << 5) | 6);
    expect(u16(archive, 4)).toBe(20); // classic entry
  });

  it('uses ZIP64 records only where needed by default, and always when announced size is absent', async () => {
    const known = await collect(createZipStream([{ name: 'a', size: 1, data: streamOf(text('x')) }]));
    expect(u16(known, 4)).toBe(20);
    expect(u32(known, known.length - 22)).toBe(0x06054b50);
    const unknown = await collect(createZipStream([{ name: 'a', data: streamOf(text('x')) }]));
    expect(u16(unknown, 4)).toBe(45);
    expect(u32(unknown, 18)).toBe(0xffffffff);
  });

  it('writes the offset-only ZIP64 extra and end records when offsets are large (simulated)', async () => {
    // A threshold of 1 byte puts every entry in ZIP64, so the offset-only path is exercised by the
    // archive layout test below through zipSize; here the data path with several ZIP64 entries.
    const list = specs();
    const archive = await collect(createZipStream(toEntries(list, true), { zip64Threshold: 1 }));
    check(archive, list);
  });

  it.each(variants)('zipSize is the exact length: %s', async (_, options, withSize) => {
    const list = specs();
    const archive = await collect(createZipStream(toEntries(list, withSize), options));
    const sizes = list.map((s) => ({ name: s.name, size: s.data.length }));
    if (withSize) expect(zipSize(sizes, options)).toBe(archive.length);
    else expect(zipSize(sizes, { zip64Threshold: ZIP64_ALWAYS })).toBeGreaterThan(0);
  });

  it('computes the layout of archives beyond 4 GiB and 65535 entries', () => {
    const huge = 5 * 2 ** 30;
    const two = zipSize([
      { name: 'a', size: huge },
      { name: 'b', size: 10 },
    ]);
    // a: ZIP64 local 30+1+20+24, data; b starts beyond 4 GiB: classic local, offset-only central.
    const localA = 30 + 1 + 20 + 24;
    const localB = 30 + 1 + 16;
    const centralA = 46 + 1 + 28;
    const centralB = 46 + 1 + 12;
    expect(two).toBe(localA + huge + localB + 10 + centralA + centralB + 56 + 20 + 22);
    const many = Array.from({ length: 65535 }, (_, i) => ({ name: `f${i}`, size: 0 }));
    expect(zipSize(many) - zipSize(many.slice(1))).toBeGreaterThan(0);
    expect(zipSize(many.slice(0, 3))).toBeLessThan(500);
    expect(zipSize(many)).toBeGreaterThan(zipSize(many.slice(0, 65534)));
  });

  it('writes offset-only ZIP64 central records and ZIP64 end records beyond 4 GiB', async () => {
    const options = { testStartOffset: 5 * 2 ** 30 };
    const entries = [{ name: 'small', size: 3, data: streamOf(text('abc')) }];
    const archive = await collect(createZipStream(entries, options));
    expect(archive.length).toBe(zipSize([{ name: 'small', size: 3 }], options));
    const central = indexOfBytes(archive, [0x50, 0x4b, 0x01, 0x02]);
    expect(u32(archive, central + 42)).toBe(0xffffffff);
    expect(u16(archive, central + 30)).toBe(12); // offset-only extra field
    expect(u32(archive, central + 46 + 5 + 4)).toBe(0x40000000); // 5 GiB offset, low word
    expect(u32(archive, central + 46 + 5 + 4 + 4)).toBe(1); // high word
    expect(indexOfBytes(archive, [0x50, 0x4b, 0x06, 0x06])).toBeGreaterThan(0);
    expect(indexOfBytes(archive, [0x50, 0x4b, 0x06, 0x07])).toBeGreaterThan(0);
  });

  it('errors when an entry stream errors', async () => {
    const bad = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(new Uint8Array([1, 2, 3]));
        c.error(new Error('boom'));
      },
    });
    await expect(collect(createZipStream([{ name: 'a', data: bad }]))).rejects.toThrow('boom');
  });

  it('errors when the entries iterable fails', async () => {
    async function* gen(): AsyncGenerator<ZipEntry> {
      yield { name: 'a', data: streamOf(text('x')) };
      throw new Error('listing failed');
    }
    await expect(collect(createZipStream(gen()))).rejects.toThrow('listing failed');
  });

  it('errors when the announced size is not respected', async () => {
    await expect(
      collect(createZipStream([{ name: 'a', size: 2, data: streamOf(text('xyz')) }])),
    ).rejects.toThrow('more than');
    await expect(
      collect(createZipStream([{ name: 'a', size: 5, data: streamOf(text('xyz')) }])),
    ).rejects.toThrow('instead of');
  });

  it('errors on a name longer than 65535 bytes', async () => {
    await expect(
      collect(createZipStream([{ name: 'a'.repeat(65536), data: streamOf(new Uint8Array(0)) }])),
    ).rejects.toThrow('too long');
  });

  it('is pull-based: reads at most one chunk ahead and cancels the entry on cancel', async () => {
    let pulled = 0;
    let cancelled = false;
    const source = new ReadableStream<Uint8Array>(
      {
        pull(c) {
          pulled++;
          c.enqueue(new Uint8Array(10));
        },
        cancel() {
          cancelled = true;
        },
      },
      { highWaterMark: 0 },
    );
    const r = createZipStream([{ name: 'a', data: source }]).getReader();
    await r.read(); // local header
    expect(pulled).toBe(0);
    await r.read(); // first data chunk
    expect(pulled).toBe(1);
    await r.cancel();
    expect(cancelled).toBe(true);
  });
});

describe('dosTime', () => {
  it('clamps to the MS-DOS range', () => {
    expect(dosTime(new Date('1970-01-01'))).toEqual({ date: 33, time: 0 });
    expect(dosTime(new Date('2300-01-01'))).toEqual({
      date: (127 << 9) | (12 << 5) | 31,
      time: (23 << 11) | (59 << 5) | 29,
    });
  });
});
