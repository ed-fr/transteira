// Helpers of the TTE2 tests: hexadecimal and base64 codecs, the vector plaintext pattern, a seeded
// pseudo-random generator and stream utilities.

import { E2EError, GO_ERROR_NAMES } from './errors';

/** Decodes lowercase or uppercase hexadecimal. */
export function fromHex(h: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** Encodes lowercase hexadecimal. */
export function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

/** Decodes standard base64 with padding. */
export function fromBase64(s: string): Uint8Array<ArrayBuffer> {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Encodes base64url without padding with the platform encoder (reference for the tests). */
export function referenceBase64Url(b: Uint8Array): string {
  let bin = '';
  for (const x of b) bin += String.fromCharCode(x);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Returns the vector plaintext: n bytes where byte k is k mod 251. */
export function pattern(n: number): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(n);
  for (let k = 0; k < n; k++) out[k] = k % 251;
  return out;
}

/** Returns the lowercase hexadecimal SHA-256 of b. */
export async function sha256Hex(b: Uint8Array): Promise<string> {
  return toHex(new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', new Uint8Array(b))));
}

/** Seeded pseudo-random generator (mulberry32) returning integers in [0, n). */
export function seededRandom(seed: number): (n: number) => number {
  let a = seed >>> 0;
  return (n: number) => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return Math.floor((((t ^ (t >>> 14)) >>> 0) / 4294967296) * n);
  };
}

/** Splits b into pieces whose sizes are drawn from rand in [0, max] (empty pieces included). */
export function split(b: Uint8Array, rand: (n: number) => number, max: number): Uint8Array[] {
  const parts: Uint8Array[] = [];
  let o = 0;
  while (o < b.length) {
    const n = rand(max + 1);
    parts.push(b.subarray(o, o + n));
    o += n;
  }
  return parts;
}

/** Pipes pieces through a TransformStream and returns the concatenated output. */
export async function pipe(
  stream: TransformStream<Uint8Array, Uint8Array>,
  pieces: Uint8Array[],
): Promise<Uint8Array<ArrayBuffer>> {
  const source = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const p of pieces) controller.enqueue(p);
      controller.close();
    },
  });
  const chunks: Uint8Array[] = [];
  const reader = source.pipeThrough(stream).getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let o = 0;
  for (const c of chunks) {
    out.set(c, o);
    o += c.length;
  }
  return out;
}

/** Runs f and returns the Go sentinel name of the E2EError it raises, '' when it succeeds. */
export async function goErrorName(f: () => Promise<unknown>): Promise<string> {
  try {
    await f();
    return '';
  } catch (err) {
    if (err instanceof E2EError) return GO_ERROR_NAMES[err.code];
    throw err;
  }
}

/**
 * Returns the index of the first byte where a and b differ, -1 when they are equal (fast: the
 * generic deep equality of the test runner is slow on large arrays).
 */
export function firstDifference(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return i;
  return a.length === b.length ? -1 : n;
}
