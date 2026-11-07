// Strict base64url without padding (RFC 4648 section 5), as Go base64.RawURLEncoding.Strict():
// only the URL alphabet, no padding, whitespace or line break, and canonical (the unused low bits
// of the last character are zero). Used for the transfer key and the sealed blobs.

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/** Value of each character code of the alphabet, -1 for any other code below 128. */
const VALUES: Int8Array = (() => {
  const v = new Int8Array(128).fill(-1);
  for (let i = 0; i < ALPHABET.length; i++) v[ALPHABET.charCodeAt(i)] = i;
  return v;
})();

/** Encodes bytes in base64url without padding. */
export function encodeBase64Url(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 3 <= bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out += ALPHABET[n >>> 18]! + ALPHABET[(n >>> 12) & 63]! + ALPHABET[(n >>> 6) & 63]! + ALPHABET[n & 63]!;
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i]!;
    out += ALPHABET[n >>> 2]! + ALPHABET[(n << 4) & 63]!;
  } else if (rest === 2) {
    const n = (bytes[i]! << 8) | bytes[i + 1]!;
    out += ALPHABET[n >>> 10]! + ALPHABET[(n >>> 4) & 63]! + ALPHABET[(n << 2) & 63]!;
  }
  return out;
}

/**
 * Decodes strict, canonical base64url without padding. It returns null for any other input
 * (foreign character, padding, impossible length, non-zero unused bits).
 */
export function decodeBase64Url(s: string): Uint8Array<ArrayBuffer> | null {
  if (s.length % 4 === 1) return null;
  const out = new Uint8Array(Math.floor((s.length * 3) / 4));
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const v = c < 128 ? VALUES[c]! : -1;
    if (v < 0) return null;
    acc = ((acc << 6) | v) & 0xffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >>> bits) & 0xff;
    }
  }
  // The bits left over (2 or 4) must be zero for the encoding to be canonical.
  if ((acc & ((1 << bits) - 1)) !== 0) return null;
  return out;
}
