// Streaming ZIP writer for the browser (end-to-end encrypted downloads: a Service Worker streams
// the decrypted files into one archive). It mirrors the server writer internal/zipstream:
//
//   - store mode (no compression), entries written in order as local header, data, data descriptor,
//     then the central directory and the end records;
//   - general purpose flags always bit 3 (data descriptor, the CRC-32 is computed while streaming)
//     and bit 11 (UTF-8 names); MS-DOS timestamps taken in UTC and clamped to 1980-2107;
//   - ZIP64 records follow APPNOTE 6.3.x as the Go writer does: a ZIP64 local header carries the
//     ZIP64 extra field (two zero sizes) and 0xFFFFFFFF in the 32-bit size fields, its data
//     descriptor has 8-byte sizes, its central header carries real sizes and offset in the extra
//     field, and the end of central directory holds the ZIP64 end record and locator.
//
// Choice for sizes: like the server (archiveFormat), ZIP64 is used only where needed
// (ZIP64_WHEN_NEEDED), which keeps small archives readable by the macOS Archive Utility. An entry
// whose size is not announced cannot be classified when its local header is written, so it always
// uses ZIP64 (the server never faces this case: it always knows the sizes). When every size is
// known, zipSize() returns the exact archive length for a Content-Length header.
//
// The writer is pull-based: an entry is read only as fast as the consumer reads the archive, and
// never buffered. If an entry stream fails, the archive stream errors (it is never closed cleanly,
// so a truncated archive cannot pass for a complete one).
//
// No DOM or Node API is used: it runs in a window, a dedicated Worker and a Service Worker.
import { Crc32 } from './crc32';

/** Threshold meaning "use ZIP64 only where a 32-bit field cannot hold the value" (default). */
export const ZIP64_WHEN_NEEDED = 0xffffffff;
/** Threshold meaning "ZIP64 records for every entry and always the ZIP64 end records". */
export const ZIP64_ALWAYS = 0;

/** One file of the archive. */
export interface ZipEntry {
  /** UTF-8 path with "/" separators; validated by the caller (no "..", control characters...). */
  name: string;
  /**
   * Expected plain size in bytes. When given, the data stream must yield exactly that many bytes
   * (otherwise the archive errors) and the entry only uses ZIP64 if needed; when absent, the entry
   * always uses ZIP64.
   */
  size?: number;
  /** Modification time (defaults to 1980-01-01, the MS-DOS epoch). */
  modified?: Date;
  /** Content of the file. */
  data: ReadableStream<Uint8Array>;
}

/** Options of the writer. */
export interface ZipOptions {
  /**
   * Entries of at least this size use ZIP64 (values above ZIP64_WHEN_NEEDED act as such; 0 or less
   * selects ZIP64_ALWAYS). Default ZIP64_WHEN_NEEDED. Lowering it exists for tests.
   */
  zip64Threshold?: number;
  /**
   * Tests only: pretend the archive starts this many bytes into a larger stream, so that the
   * offsets beyond 4 GiB can be exercised without writing 4 GiB. Offsets and sizes computed by
   * zipSize() take it into account. Default 0.
   */
  testStartOffset?: number;
}

/** Name and size of an entry, as far as the exact archive length is concerned. */
export interface ZipEntrySize {
  name: string;
  size: number;
}

const SIG_LOCAL = 0x04034b50;
const SIG_DESCRIPTOR = 0x08074b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_ZIP64_END = 0x06064b50;
const SIG_ZIP64_LOCATOR = 0x07064b50;
const SIG_END = 0x06054b50;

const LOCAL_LEN = 30;
const CENTRAL_LEN = 46;
const DESCRIPTOR_LEN = 16;
const DESCRIPTOR64_LEN = 24;
const LOCAL_EXTRA64 = 20;
const CENTRAL_EXTRA64 = 28;
const OFFSET_EXTRA = 12;
const ZIP64_END_LEN = 56;
const ZIP64_LOCATOR_LEN = 20;
const END_LEN = 22;
const ZIP64_ENDS = ZIP64_END_LEN + ZIP64_LOCATOR_LEN + END_LEN;

const MAX16 = 0xffff;
const MAX32 = 0xffffffff;
const TWO32 = 0x100000000;
const FLAGS = (1 << 3) | (1 << 11);
const VERSION_CLASSIC = 20;
const VERSION_ZIP64 = 45;
const VERSION_MADE_BY = (3 << 8) | VERSION_ZIP64;
const EXTERNAL_ATTRS = 0o100644 * 0x10000; // regular file rw-r--r-- in the high 16 bits (as unsigned)

const encoder = new TextEncoder();

/** Whether an entry of this (possibly unknown) size uses ZIP64 records. */
function useZip64(size: number | undefined, threshold: number): boolean {
  return size === undefined || threshold <= 0 || size >= Math.min(threshold, MAX32);
}

/** MS-DOS date and time of `d` in UTC, clamped to 1980-01-01 .. 2107-12-31 23:59:58. */
export function dosTime(d: Date): { date: number; time: number } {
  const year = d.getUTCFullYear();
  if (year < 1980) return { date: (1 << 5) | 1, time: 0 };
  if (year > 2107) return { date: (127 << 9) | (12 << 5) | 31, time: (23 << 11) | (59 << 5) | 29 };
  return {
    date: ((year - 1980) << 9) | ((d.getUTCMonth() + 1) << 5) | d.getUTCDate(),
    time: (d.getUTCHours() << 11) | (d.getUTCMinutes() << 5) | (d.getUTCSeconds() >> 1),
  };
}

/** Little-endian record builder over a fixed-size buffer. */
class Record {
  readonly bytes: Uint8Array;
  private readonly view: DataView;
  private at = 0;

  constructor(length: number) {
    this.bytes = new Uint8Array(length);
    this.view = new DataView(this.bytes.buffer);
  }

  u16(v: number): void {
    this.view.setUint16(this.at, v, true);
    this.at += 2;
  }

  u32(v: number): void {
    this.view.setUint32(this.at, v, true);
    this.at += 4;
  }

  /** Writes a non-negative integer (below 2^53) as 8 bytes. */
  u64(v: number): void {
    this.view.setUint32(this.at, v % TWO32, true);
    this.view.setUint32(this.at + 4, Math.floor(v / TWO32), true);
    this.at += 8;
  }

  raw(b: Uint8Array): void {
    this.bytes.set(b, this.at);
    this.at += b.length;
  }
}

/** Length of the local header plus data descriptor (without the data). */
function localOverhead(nameLen: number, zip64: boolean): number {
  return zip64
    ? LOCAL_LEN + nameLen + LOCAL_EXTRA64 + DESCRIPTOR64_LEN
    : LOCAL_LEN + nameLen + DESCRIPTOR_LEN;
}

/** Length of a central header whose entry starts at `offset`. */
function centralLength(nameLen: number, zip64: boolean, offset: number): number {
  if (zip64) return CENTRAL_LEN + nameLen + CENTRAL_EXTRA64;
  return CENTRAL_LEN + nameLen + (offset >= MAX32 ? OFFSET_EXTRA : 0);
}

/** Whether the archive ends with ZIP64 end records. */
function useZip64End(threshold: number, count: number, cdOffset: number, cdSize: number): boolean {
  return threshold <= 0 || count >= MAX16 || cdOffset >= MAX32 || cdSize >= MAX32;
}

/**
 * Exact byte length of the archive createZipStream() produces for entries of these names and
 * (known) sizes, with the same options. Use it for the Content-Length header.
 */
export function zipSize(entries: Iterable<ZipEntrySize>, options: ZipOptions = {}): number {
  const threshold = options.zip64Threshold ?? ZIP64_WHEN_NEEDED;
  const base = options.testStartOffset ?? 0;
  let offset = base;
  let cdSize = 0;
  let count = 0;
  for (const e of entries) {
    const nameLen = encoder.encode(e.name).length;
    const zip64 = useZip64(e.size, threshold);
    cdSize += centralLength(nameLen, zip64, offset);
    offset += localOverhead(nameLen, zip64) + e.size;
    count++;
  }
  return offset - base + cdSize + (useZip64End(threshold, count, offset, cdSize) ? ZIP64_ENDS : END_LEN);
}

/** What the central directory needs to remember of a written entry. */
interface Written {
  name: Uint8Array;
  crc: number;
  size: number;
  offset: number;
  zip64: boolean;
  date: number;
  time: number;
}

function localHeader(name: Uint8Array, zip64: boolean, date: number, time: number): Uint8Array {
  const r = new Record(LOCAL_LEN + name.length + (zip64 ? LOCAL_EXTRA64 : 0));
  const size = zip64 ? MAX32 : 0;
  r.u32(SIG_LOCAL);
  r.u16(zip64 ? VERSION_ZIP64 : VERSION_CLASSIC);
  r.u16(FLAGS);
  r.u16(0); // store
  r.u16(time);
  r.u16(date);
  r.u32(0); // CRC-32, in the data descriptor
  r.u32(size);
  r.u32(size);
  r.u16(name.length);
  r.u16(zip64 ? LOCAL_EXTRA64 : 0);
  r.raw(name);
  if (zip64) {
    r.u16(1);
    r.u16(16);
    r.u64(0);
    r.u64(0);
  }
  return r.bytes;
}

function descriptor(crc: number, size: number, zip64: boolean): Uint8Array {
  const r = new Record(zip64 ? DESCRIPTOR64_LEN : DESCRIPTOR_LEN);
  r.u32(SIG_DESCRIPTOR);
  r.u32(crc);
  if (zip64) {
    r.u64(size);
    r.u64(size);
  } else {
    r.u32(size);
    r.u32(size);
  }
  return r.bytes;
}

function centralHeader(w: Written): Uint8Array {
  const offsetOnly = !w.zip64 && w.offset >= MAX32;
  const extra = w.zip64 ? CENTRAL_EXTRA64 : offsetOnly ? OFFSET_EXTRA : 0;
  const r = new Record(CENTRAL_LEN + w.name.length + extra);
  const size = w.zip64 ? MAX32 : w.size;
  r.u32(SIG_CENTRAL);
  r.u16(VERSION_MADE_BY);
  r.u16(w.zip64 ? VERSION_ZIP64 : VERSION_CLASSIC);
  r.u16(FLAGS);
  r.u16(0);
  r.u16(w.time);
  r.u16(w.date);
  r.u32(w.crc);
  r.u32(size);
  r.u32(size);
  r.u16(w.name.length);
  r.u16(extra);
  r.u16(0); // comment length
  r.u16(0); // disk number start
  r.u16(0); // internal attributes
  r.u32(EXTERNAL_ATTRS);
  r.u32(w.zip64 || offsetOnly ? MAX32 : w.offset);
  r.raw(w.name);
  if (w.zip64) {
    r.u16(1);
    r.u16(24);
    r.u64(w.size);
    r.u64(w.size);
    r.u64(w.offset);
  } else if (offsetOnly) {
    r.u16(1);
    r.u16(8);
    r.u64(w.offset);
  }
  return r.bytes;
}

function endRecords(zip64End: boolean, count: number, cdOffset: number, cdSize: number): Uint8Array {
  const r = new Record(zip64End ? ZIP64_ENDS : END_LEN);
  if (zip64End) {
    r.u32(SIG_ZIP64_END);
    r.u64(ZIP64_END_LEN - 12);
    r.u16(VERSION_MADE_BY);
    r.u16(VERSION_ZIP64);
    r.u32(0);
    r.u32(0);
    r.u64(count);
    r.u64(count);
    r.u64(cdSize);
    r.u64(cdOffset);
    r.u32(SIG_ZIP64_LOCATOR);
    r.u32(0);
    r.u64(cdOffset + cdSize);
    r.u32(1);
  }
  r.u32(SIG_END);
  r.u16(0);
  r.u16(0);
  r.u16(zip64End ? MAX16 : count);
  r.u16(zip64End ? MAX16 : count);
  r.u32(zip64End ? MAX32 : cdSize);
  r.u32(zip64End ? MAX32 : cdOffset);
  r.u16(0);
  return r.bytes;
}

/** Generator behind the archive stream: yields the archive chunk by chunk. */
async function* archiveChunks(
  entries: AsyncIterable<ZipEntry> | Iterable<ZipEntry>,
  threshold: number,
  startOffset: number,
): AsyncGenerator<Uint8Array, void, undefined> {
  const written: Written[] = [];
  let offset = startOffset;
  for await (const e of entries) {
    const name = encoder.encode(e.name);
    if (name.length > MAX16) throw new RangeError(`zip: entry name too long (${name.length} bytes)`);
    const zip64 = useZip64(e.size, threshold);
    const { date, time } = dosTime(e.modified ?? new Date(0));
    const header = localHeader(name, zip64, date, time);
    const start = offset;
    offset += header.length;
    yield header;

    const crc = new Crc32();
    let size = 0;
    const reader = e.data.getReader();
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value.length === 0) continue;
        size += value.length;
        if (e.size !== undefined && size > e.size) {
          throw new Error(`zip: entry ${e.name} yields more than its announced ${e.size} bytes`);
        }
        crc.update(value);
        offset += value.length;
        yield value;
      }
    } finally {
      // Reached on completion, error or consumer cancellation: free the source either way.
      await reader.cancel().catch(() => undefined);
    }
    if (e.size !== undefined && size < e.size) {
      throw new Error(`zip: entry ${e.name} yields ${size} bytes instead of its announced ${e.size}`);
    }
    const crcValue = crc.value();
    const tail = descriptor(crcValue, size, zip64);
    offset += tail.length;
    yield tail;
    written.push({ name, crc: crcValue, size, offset: start, zip64, date, time });
  }

  const cdOffset = offset;
  let cdSize = 0;
  for (const w of written) {
    const record = centralHeader(w);
    cdSize += record.length;
    yield record;
  }
  yield endRecords(
    useZip64End(threshold, written.length, cdOffset, cdSize),
    written.length,
    cdOffset,
    cdSize,
  );
}

/**
 * Streams a store-mode ZIP archive of `entries`. Entries are consumed one at a time, and only as
 * the consumer pulls. The returned stream errors (instead of closing) when an entry stream
 * errors, when an announced size is not respected, or when `entries` itself fails; cancelling it
 * cancels the entry being read.
 */
export function createZipStream(
  entries: AsyncIterable<ZipEntry> | Iterable<ZipEntry>,
  options: ZipOptions = {},
): ReadableStream<Uint8Array> {
  const chunks = archiveChunks(
    entries,
    options.zip64Threshold ?? ZIP64_WHEN_NEEDED,
    options.testStartOffset ?? 0,
  );
  return new ReadableStream<Uint8Array>(
    {
      async pull(controller) {
        const next = await chunks.next();
        if (next.done) controller.close();
        else controller.enqueue(next.value);
      },
      async cancel() {
        await chunks.return();
      },
    },
    { highWaterMark: 0 },
  );
}
