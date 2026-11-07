// Incremental SHA-256 (FIPS 180-4) in pure TypeScript. WebCrypto only offers one-shot digests,
// but the browser must hash multi-gigabyte files chunk by chunk. The code uses no DOM or Node API,
// so it runs in a window, a dedicated Worker and a Service Worker (the CSP forbids WebAssembly).

const BLOCK = 64;

/** Round constants K (first 32 bits of the fractional parts of the cube roots of the first 64 primes). */
const K = new Int32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
  0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
  0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
  0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
  0xc67178f2,
]);

/** Initial hash value H0 (square roots of the first 8 primes). */
const H0 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

/** 2^29: a byte count divided by this gives the high 32 bits of its bit count. */
const TWO_29 = 0x20000000;

/**
 * Writes the SHA-256 message length field: the bit length of `bytes` bytes as a 64-bit big-endian
 * integer at `out[at..at+8)`. The bit count is split without ever forming `bytes * 8`, so it stays
 * exact for any byte count up to 2^53 (well beyond 4 GiB).
 */
export function encodeBitLength(bytes: number, out: Uint8Array, at: number): void {
  const high = Math.floor(bytes / TWO_29);
  const low = (bytes % TWO_29) * 8;
  out[at] = high >>> 24;
  out[at + 1] = high >>> 16;
  out[at + 2] = high >>> 8;
  out[at + 3] = high;
  out[at + 4] = low >>> 24;
  out[at + 5] = low >>> 16;
  out[at + 6] = low >>> 8;
  out[at + 7] = low;
}

/** Lowercase hexadecimal form of a byte array. */
export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += (b < 16 ? '0' : '') + b.toString(16);
  return out;
}

/** Incremental SHA-256 hasher. Feed it with update(), then call digest() once. */
export class Sha256 {
  private readonly state = new Int32Array(H0);
  private readonly schedule = new Int32Array(64);
  private readonly pending = new Uint8Array(BLOCK);
  private pendingLen = 0;
  /** Total bytes fed so far (exact up to 2^53). */
  private total = 0;
  private done = false;

  /** Absorbs `data`; the array is read, never retained or modified. */
  update(data: Uint8Array): this {
    if (this.done) throw new Error('sha256: update after digest');
    let pos = 0;
    let rest = data.length;
    this.total += rest;
    if (this.pendingLen > 0) {
      const take = Math.min(BLOCK - this.pendingLen, rest);
      this.pending.set(data.subarray(0, take), this.pendingLen);
      this.pendingLen += take;
      pos = take;
      rest -= take;
      if (this.pendingLen < BLOCK) return this;
      this.compress(this.pending, 0, 1);
      this.pendingLen = 0;
    }
    const blocks = rest >>> 6;
    if (blocks > 0) {
      this.compress(data, pos, blocks);
      pos += blocks * BLOCK;
      rest -= blocks * BLOCK;
    }
    if (rest > 0) {
      this.pending.set(data.subarray(pos, pos + rest));
      this.pendingLen = rest;
    }
    return this;
  }

  /** Finishes the hash and returns the 32-byte digest. The hasher cannot be used afterwards. */
  digest(): Uint8Array {
    if (this.done) throw new Error('sha256: digest called twice');
    this.done = true;
    const length = this.total;
    const padded = this.pendingLen < 56 ? BLOCK : 2 * BLOCK;
    const tail = new Uint8Array(padded);
    tail.set(this.pending.subarray(0, this.pendingLen));
    tail[this.pendingLen] = 0x80;
    encodeBitLength(length, tail, padded - 8);
    this.compress(tail, 0, padded / BLOCK);
    const out = new Uint8Array(32);
    for (let i = 0; i < 8; i++) {
      const v = this.state[i]!;
      out[i * 4] = v >>> 24;
      out[i * 4 + 1] = v >>> 16;
      out[i * 4 + 2] = v >>> 8;
      out[i * 4 + 3] = v;
    }
    return out;
  }

  /** Runs the compression function over `blocks` consecutive 64-byte blocks of `d` from `p`. */
  private compress(data: Uint8Array, p: number, blocks: number): void {
    const w = this.schedule;
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const s = this.state;
    let h0 = s[0]!;
    let h1 = s[1]!;
    let h2 = s[2]!;
    let h3 = s[3]!;
    let h4 = s[4]!;
    let h5 = s[5]!;
    let h6 = s[6]!;
    let h7 = s[7]!;
    for (let blk = 0; blk < blocks; blk++, p += BLOCK) {
      for (let i = 0; i < 16; i++) w[i] = view.getInt32(p + i * 4);
      for (let i = 16; i < 64; i++) {
        const x = w[i - 15]!;
        const y = w[i - 2]!;
        const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
        const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
        w[i] = (w[i - 16]! + s0 + w[i - 7]! + s1) | 0;
      }
      let a = h0;
      let b = h1;
      let c = h2;
      let d = h3;
      let e = h4;
      let f = h5;
      let g = h6;
      let h = h7;
      let t = 0;
      // 64 rounds, unrolled by 8 with rotating roles instead of shifting eight variables.
      for (let i = 0; i < 64; i += 8) {
        t =
          (h +
            (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) +
            (g ^ (e & (f ^ g))) +
            K[i + 0]! +
            w[i + 0]!) |
          0;
        d = (d + t) | 0;
        h =
          (t +
            (((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) +
            ((a & b) | (c & (a | b)))) |
          0;
        t =
          (g +
            (((d >>> 6) | (d << 26)) ^ ((d >>> 11) | (d << 21)) ^ ((d >>> 25) | (d << 7))) +
            (f ^ (d & (e ^ f))) +
            K[i + 1]! +
            w[i + 1]!) |
          0;
        c = (c + t) | 0;
        g =
          (t +
            (((h >>> 2) | (h << 30)) ^ ((h >>> 13) | (h << 19)) ^ ((h >>> 22) | (h << 10))) +
            ((h & a) | (b & (h | a)))) |
          0;
        t =
          (f +
            (((c >>> 6) | (c << 26)) ^ ((c >>> 11) | (c << 21)) ^ ((c >>> 25) | (c << 7))) +
            (e ^ (c & (d ^ e))) +
            K[i + 2]! +
            w[i + 2]!) |
          0;
        b = (b + t) | 0;
        f =
          (t +
            (((g >>> 2) | (g << 30)) ^ ((g >>> 13) | (g << 19)) ^ ((g >>> 22) | (g << 10))) +
            ((g & h) | (a & (g | h)))) |
          0;
        t =
          (e +
            (((b >>> 6) | (b << 26)) ^ ((b >>> 11) | (b << 21)) ^ ((b >>> 25) | (b << 7))) +
            (d ^ (b & (c ^ d))) +
            K[i + 3]! +
            w[i + 3]!) |
          0;
        a = (a + t) | 0;
        e =
          (t +
            (((f >>> 2) | (f << 30)) ^ ((f >>> 13) | (f << 19)) ^ ((f >>> 22) | (f << 10))) +
            ((f & g) | (h & (f | g)))) |
          0;
        t =
          (d +
            (((a >>> 6) | (a << 26)) ^ ((a >>> 11) | (a << 21)) ^ ((a >>> 25) | (a << 7))) +
            (c ^ (a & (b ^ c))) +
            K[i + 4]! +
            w[i + 4]!) |
          0;
        h = (h + t) | 0;
        d =
          (t +
            (((e >>> 2) | (e << 30)) ^ ((e >>> 13) | (e << 19)) ^ ((e >>> 22) | (e << 10))) +
            ((e & f) | (g & (e | f)))) |
          0;
        t =
          (c +
            (((h >>> 6) | (h << 26)) ^ ((h >>> 11) | (h << 21)) ^ ((h >>> 25) | (h << 7))) +
            (b ^ (h & (a ^ b))) +
            K[i + 5]! +
            w[i + 5]!) |
          0;
        g = (g + t) | 0;
        c =
          (t +
            (((d >>> 2) | (d << 30)) ^ ((d >>> 13) | (d << 19)) ^ ((d >>> 22) | (d << 10))) +
            ((d & e) | (f & (d | e)))) |
          0;
        t =
          (b +
            (((g >>> 6) | (g << 26)) ^ ((g >>> 11) | (g << 21)) ^ ((g >>> 25) | (g << 7))) +
            (a ^ (g & (h ^ a))) +
            K[i + 6]! +
            w[i + 6]!) |
          0;
        f = (f + t) | 0;
        b =
          (t +
            (((c >>> 2) | (c << 30)) ^ ((c >>> 13) | (c << 19)) ^ ((c >>> 22) | (c << 10))) +
            ((c & d) | (e & (c | d)))) |
          0;
        t =
          (a +
            (((f >>> 6) | (f << 26)) ^ ((f >>> 11) | (f << 21)) ^ ((f >>> 25) | (f << 7))) +
            (h ^ (f & (g ^ h))) +
            K[i + 7]! +
            w[i + 7]!) |
          0;
        e = (e + t) | 0;
        a =
          (t +
            (((b >>> 2) | (b << 30)) ^ ((b >>> 13) | (b << 19)) ^ ((b >>> 22) | (b << 10))) +
            ((b & c) | (d & (b | c)))) |
          0;
      }
      h0 = (h0 + a) | 0;
      h1 = (h1 + b) | 0;
      h2 = (h2 + c) | 0;
      h3 = (h3 + d) | 0;
      h4 = (h4 + e) | 0;
      h5 = (h5 + f) | 0;
      h6 = (h6 + g) | 0;
      h7 = (h7 + h) | 0;
    }
    s[0] = h0;
    s[1] = h1;
    s[2] = h2;
    s[3] = h3;
    s[4] = h4;
    s[5] = h5;
    s[6] = h6;
    s[7] = h7;
  }
}
