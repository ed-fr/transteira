// Minimal ZIP reader for the archives the server streams in store mode (no compression,
// CLAUDE.md section 10): entries are located through the central directory (the local headers
// of a streamed archive carry zero sizes and a data descriptor), ZIP64 records are honoured, and
// each entry's CRC-32 is checked. Compressed entries are refused: the server must never deflate.
import zlib from 'node:zlib';

/** One entry of an archive. */
export interface ZipEntry {
  name: string;
  data: Buffer;
}

const SIG_EOCD = 0x06054b50;
const SIG_ZIP64_LOCATOR = 0x07064b50;
const SIG_ZIP64_EOCD = 0x06064b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_LOCAL = 0x04034b50;
const U32_MAX = 0xffffffff;
const U16_MAX = 0xffff;

function readU64(buf: Buffer, at: number): number {
  const v = buf.readBigUInt64LE(at);
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('zip: 64-bit value too large');
  return Number(v);
}

function findEocd(buf: Buffer): number {
  const lowest = Math.max(0, buf.length - 22 - U16_MAX);
  for (let i = buf.length - 22; i >= lowest; i--) {
    if (buf.readUInt32LE(i) === SIG_EOCD) return i;
  }
  throw new Error('zip: end of central directory not found');
}

/** Parses a store-mode archive and returns its entries in central-directory order. */
export function readStoredZip(buf: Buffer): ZipEntry[] {
  const eocd = findEocd(buf);
  let count = buf.readUInt16LE(eocd + 10);
  let cdOffset = buf.readUInt32LE(eocd + 16);
  if (count === U16_MAX || cdOffset === U32_MAX) {
    const locator = eocd - 20;
    if (locator < 0 || buf.readUInt32LE(locator) !== SIG_ZIP64_LOCATOR)
      throw new Error('zip: ZIP64 locator missing');
    const record = readU64(buf, locator + 8);
    if (buf.readUInt32LE(record) !== SIG_ZIP64_EOCD) throw new Error('zip: ZIP64 end record missing');
    count = readU64(buf, record + 32);
    cdOffset = readU64(buf, record + 48);
  }

  const entries: ZipEntry[] = [];
  let p = cdOffset;
  for (let i = 0; i < count; i++) {
    if (buf.readUInt32LE(p) !== SIG_CENTRAL) throw new Error(`zip: bad central header at ${p}`);
    const method = buf.readUInt16LE(p + 10);
    const crc = buf.readUInt32LE(p + 16);
    let compressed = buf.readUInt32LE(p + 20);
    let size = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    let local = buf.readUInt32LE(p + 42);
    const name = buf.subarray(p + 46, p + 46 + nameLen).toString('utf8');

    // ZIP64 extended information (header id 1): only the fields saturated in the header.
    let e = p + 46 + nameLen;
    const extraEnd = e + extraLen;
    while (e + 4 <= extraEnd) {
      const id = buf.readUInt16LE(e);
      const len = buf.readUInt16LE(e + 2);
      if (id === 1) {
        let q = e + 4;
        if (size === U32_MAX) {
          size = readU64(buf, q);
          q += 8;
        }
        if (compressed === U32_MAX) {
          compressed = readU64(buf, q);
          q += 8;
        }
        if (local === U32_MAX) local = readU64(buf, q);
      }
      e += 4 + len;
    }

    if (method !== 0) throw new Error(`zip: entry ${name} uses method ${method}, expected 0 (store)`);
    if (compressed !== size) throw new Error(`zip: entry ${name} has different stored and real sizes`);
    if (buf.readUInt32LE(local) !== SIG_LOCAL) throw new Error(`zip: bad local header for ${name}`);
    const start = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
    const data = buf.subarray(start, start + size);
    if (data.length !== size) throw new Error(`zip: entry ${name} is truncated`);
    if (zlib.crc32(data) !== crc) throw new Error(`zip: CRC-32 mismatch for ${name}`);
    entries.push({ name, data });
    p = extraEnd + commentLen;
  }
  return entries;
}
