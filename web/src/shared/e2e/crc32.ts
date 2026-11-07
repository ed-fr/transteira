// Incremental CRC-32 (IEEE 802.3, polynomial 0xEDB88320 reflected), slicing-by-4, pure TypeScript.
// Used by the ZIP writer; runs in a window, a Worker and a Service Worker.

/** Slicing tables: TABLE[k * 256 + b] is the CRC of byte b followed by k zero bytes. */
const TABLE = (() => {
  const t = new Int32Array(4 * 256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  for (let n = 0; n < 256; n++) {
    for (let k = 1; k < 4; k++) {
      const prev = t[(k - 1) * 256 + n]!;
      t[k * 256 + n] = t[prev & 0xff]! ^ (prev >>> 8);
    }
  }
  return t;
})();

/** Incremental CRC-32 accumulator. */
export class Crc32 {
  private crc = -1;

  /** Absorbs `data`. */
  update(data: Uint8Array): this {
    let c = this.crc;
    let i = 0;
    const n = data.length;
    for (const end = n - 3; i < end; i += 4) {
      c ^= data[i]! | (data[i + 1]! << 8) | (data[i + 2]! << 16) | (data[i + 3]! << 24);
      c =
        TABLE[768 + (c & 0xff)]! ^
        TABLE[512 + ((c >>> 8) & 0xff)]! ^
        TABLE[256 + ((c >>> 16) & 0xff)]! ^
        TABLE[c >>> 24]!;
    }
    for (; i < n; i++) c = TABLE[(c ^ data[i]!) & 0xff]! ^ (c >>> 8);
    this.crc = c;
    return this;
  }

  /** The CRC-32 of the data so far, as an unsigned 32-bit number. Updating may continue afterwards. */
  value(): number {
    return (this.crc ^ -1) >>> 0;
  }
}
