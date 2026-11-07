// Sealed blobs of TTE2 (docs/architecture/e2e-format.md section 3): the metadata of each file and
// the transfer message, mirroring internal/tte2/sealed.go. A blob is
//
//   0x01 || 12-byte random nonce || AES-256-GCM ciphertext and tag,  sent as base64url without padding.
//
// Metadata parsing reproduces Go's decodeMetadata exactly (including how encoding/json treats
// repeated fields, null values and escaped surrogates), with one documented restriction: integers
// beyond Number.MAX_SAFE_INTEGER, accepted by Go, are refused here as invalid-metadata because they
// cannot be represented exactly (no real index, count or size comes near 2^53).

import { decodeBase64Url, encodeBase64Url } from './base64url';
import { E2EError } from './errors';
import {
  MAX_MESSAGE_ENCODED_SIZE,
  MAX_MESSAGE_RUNES,
  MAX_METADATA_ENCODED_SIZE,
  MAX_METADATA_SIZE,
  NONCE_SIZE,
  TAG_SIZE,
  checkIndex,
  concatBytes,
  deriveMessageKey,
  deriveMetadataKey,
  randomBytes,
  u32,
  type TransferKey,
} from './tte2';

/** First byte of a sealed blob. */
const SEALED_VERSION = 1;
/** Size of a sealed blob without its plaintext. */
const SEALED_OVERHEAD = 1 + NONCE_SIZE + TAG_SIZE;

const encoder = new TextEncoder();
// fatal: invalid UTF-8 is an error, as Go utf8.Valid; ignoreBOM: a leading U+FEFF is kept, as Go
// keeps it (and then refuses it in JSON).
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/** Plaintext description of one file of an end-to-end encrypted transfer. */
export interface Metadata {
  /** 0-based position of the file in the transfer. */
  index: number;
  /** Number of files of the transfer (detects a file removed by the server). */
  count: number;
  /** Original file name, non-empty and unsanitized: clients must sanitize it before use. */
  name: string;
  /** Relative folder path, '' when none (omitted from the JSON), unsanitized. */
  path: string;
  /** Media type, possibly empty. */
  type: string;
  /** Plaintext size in bytes, checked by the recipient after decryption. */
  size: number;
  /** Lowercase hexadecimal SHA-256 of the plaintext, checked by the recipient after decryption. */
  sha256: string;
}

/** Options of the seal functions. */
export interface SealOptions {
  /** Fixed 12-byte nonce, for tests and vectors only (random when absent). */
  nonce?: Uint8Array;
}

/**
 * Encrypts m, the metadata of file index, under HKDF(K, no salt, INFO_METADATA || u32(index)) with
 * AAD "TTE2M" || u32(index). m must satisfy the rules openMetadata enforces with m.index equal to
 * index, and the blob must not exceed MAX_METADATA_SIZE bytes; otherwise invalid-metadata.
 */
export async function sealMetadata(
  key: TransferKey,
  index: number,
  m: Metadata,
  options: SealOptions = {},
): Promise<string> {
  checkIndex(index);
  validateMetadata(m, index);
  for (const s of [m.name, m.path, m.type]) {
    if (!wellFormed(s)) throw new E2EError('invalid-metadata', 'lone surrogate');
  }
  return sealMetadataRaw(key, index, encoder.encode(encodeMetadata(m)), options);
}

/** Seals an already encoded metadata plaintext, without checking its content. */
export async function sealMetadataRaw(
  key: TransferKey,
  index: number,
  plain: Uint8Array,
  options: SealOptions = {},
): Promise<string> {
  if (plain.length + SEALED_OVERHEAD > MAX_METADATA_SIZE) {
    throw new E2EError('invalid-metadata', `larger than ${MAX_METADATA_SIZE} bytes`);
  }
  checkIndex(index);
  return seal(await deriveMetadataKey(key, index), metadataAAD(index), plain, options);
}

/**
 * Decrypts and strictly validates the sealed metadata s of file index: encoding for a blob that
 * is not canonical base64url of at most MAX_METADATA_SIZE bytes with version 1, auth when it does
 * not authenticate, invalid-metadata when the JSON breaks the rules of the format.
 */
export async function openMetadata(key: TransferKey, index: number, s: string): Promise<Metadata> {
  checkIndex(index);
  const plain = await open(
    await deriveMetadataKey(key, index),
    metadataAAD(index),
    s,
    MAX_METADATA_ENCODED_SIZE,
  );
  const m = decodeMetadata(plain);
  validateMetadata(m, index);
  return m;
}

/**
 * Encrypts the transfer message under HKDF(K, no salt, INFO_MESSAGE) with AAD "TTE2T". text must
 * be well-formed (no lone surrogate) and at most MAX_MESSAGE_RUNES code points (invalid-message).
 */
export async function sealMessage(
  key: TransferKey,
  text: string,
  options: SealOptions = {},
): Promise<string> {
  if (!wellFormed(text)) throw new E2EError('invalid-message', 'lone surrogate');
  checkMessageLength(text);
  return sealMessageRaw(key, encoder.encode(text), options);
}

/** Seals a message plaintext without checking it. */
export async function sealMessageRaw(
  key: TransferKey,
  plain: Uint8Array,
  options: SealOptions = {},
): Promise<string> {
  return seal(await deriveMessageKey(key), messageAAD(), plain, options);
}

/**
 * Decrypts the sealed message s: encoding for a blob that is not canonical base64url of at most
 * MAX_MESSAGE_ENCODED_SIZE characters with version 1, auth when it does not authenticate,
 * invalid-message when the plaintext is not valid UTF-8 of at most MAX_MESSAGE_RUNES code points.
 */
export async function openMessage(key: TransferKey, s: string): Promise<string> {
  const plain = await open(await deriveMessageKey(key), messageAAD(), s, MAX_MESSAGE_ENCODED_SIZE);
  let text: string;
  try {
    text = decoder.decode(plain);
  } catch {
    throw new E2EError('invalid-message', 'not valid UTF-8');
  }
  checkMessageLength(text);
  return text;
}

/** Checks the framing of sealed metadata without the key (the checks before decryption). */
export function checkMetadataFraming(s: string): void {
  decodeSealed(s, MAX_METADATA_ENCODED_SIZE);
}

/** Checks the framing of a sealed message without the key. */
export function checkMessageFraming(s: string): void {
  decodeSealed(s, MAX_MESSAGE_ENCODED_SIZE);
}

/** AAD of the metadata of file index: "TTE2M" || u32(index). */
function metadataAAD(index: number): Uint8Array<ArrayBuffer> {
  return concatBytes(encoder.encode('TTE2M'), u32(index));
}

/** AAD of the message: "TTE2T". */
function messageAAD(): Uint8Array<ArrayBuffer> {
  return encoder.encode('TTE2T');
}

/** Rejects a message of more than MAX_MESSAGE_RUNES code points. */
function checkMessageLength(text: string): void {
  if ([...text].length > MAX_MESSAGE_RUNES) {
    throw new E2EError('invalid-message', `longer than ${MAX_MESSAGE_RUNES} characters`);
  }
}

/** Reports whether s holds no lone surrogate (so that it has an exact UTF-8 form). */
function wellFormed(s: string): boolean {
  return !/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(s);
}

/** Encrypts plain into a sealed blob. */
async function seal(
  aesKey: CryptoKey,
  aad: Uint8Array<ArrayBuffer>,
  plain: Uint8Array,
  options: SealOptions,
): Promise<string> {
  const nonce = options.nonce === undefined ? randomBytes(NONCE_SIZE) : new Uint8Array(options.nonce);
  if (nonce.length !== NONCE_SIZE) throw new RangeError(`tte2: nonce of ${nonce.length} bytes`);
  const ct = await globalThis.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
    aesKey,
    new Uint8Array(plain),
  );
  return encodeBase64Url(concatBytes(Uint8Array.of(SEALED_VERSION), nonce, new Uint8Array(ct)));
}

/** Decodes and decrypts a sealed blob of at most maxEncoded characters. */
async function open(
  aesKey: CryptoKey,
  aad: Uint8Array<ArrayBuffer>,
  s: string,
  maxEncoded: number,
): Promise<Uint8Array<ArrayBuffer>> {
  const b = decodeSealed(s, maxEncoded);
  try {
    const plain = await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b.subarray(1, 1 + NONCE_SIZE), additionalData: aad, tagLength: 128 },
      aesKey,
      b.subarray(1 + NONCE_SIZE),
    );
    return new Uint8Array(plain);
  } catch {
    throw new E2EError('auth', 'sealed blob');
  }
}

/** Decodes the framing of a sealed blob: canonical base64url, version byte, room for nonce and tag. */
function decodeSealed(s: string, maxEncoded: number): Uint8Array<ArrayBuffer> {
  const b = s.length > maxEncoded ? null : decodeBase64Url(s);
  if (b === null) throw new E2EError('encoding', 'not base64url or too long');
  if (b.length < SEALED_OVERHEAD || b[0] !== SEALED_VERSION) {
    throw new E2EError('encoding', 'bad length or version');
  }
  return b;
}

/** Checks the metadata rules for file index (Go Metadata.validate, plus exact integers). */
function validateMetadata(m: Metadata, index: number): void {
  const fail = (detail: string) => new E2EError('invalid-metadata', detail);
  if (!Number.isSafeInteger(m.count) || !Number.isSafeInteger(m.size) || !Number.isSafeInteger(m.index)) {
    throw fail('not an integer');
  }
  if (m.index !== index) throw fail(`index ${m.index}, expected ${index}`);
  if (m.count < 1 || m.index >= m.count) throw fail(`count ${m.count} for index ${m.index}`);
  if (m.name === '') throw fail('empty name');
  if (m.size < 0) throw fail('negative size');
  if (!/^[0-9a-f]{64}$/.test(m.sha256)) throw fail('sha256 is not 64 lowercase hexadecimal characters');
}

/**
 * Encodes metadata as the Go reference writer: fields in the format order, "path" omitted when
 * empty, no HTML escaping, U+2028 and U+2029 escaped as Go encoding/json does.
 */
export function encodeMetadata(m: Metadata): string {
  const str = (s: string) =>
    JSON.stringify(s)
      .replace(/\u2028/g, '\\u2028')
      .replace(/\u2029/g, '\\u2029');
  const path = m.path === '' ? '' : `"path":${str(m.path)},`;
  return (
    `{"v":1,"index":${m.index},"count":${m.count},"name":${str(m.name)},${path}` +
    `"type":${str(m.type)},"size":${m.size},"sha256":${str(m.sha256)}}`
  );
}

/** Value kinds the metadata fields accept. */
type FieldKind = 'int' | 'string';

/** Fields of the metadata JSON, their kind and whether they are required. */
const FIELDS: ReadonlyMap<string, { kind: FieldKind; required: boolean }> = new Map([
  ['v', { kind: 'int', required: true }],
  ['index', { kind: 'int', required: true }],
  ['count', { kind: 'int', required: true }],
  ['name', { kind: 'string', required: true }],
  ['path', { kind: 'string', required: false }],
  ['type', { kind: 'string', required: true }],
  ['size', { kind: 'int', required: true }],
  ['sha256', { kind: 'string', required: true }],
]);

/** A scalar JSON value of a metadata field; null is represented by null. */
type FieldValue = string | number | null;

/**
 * Parses the strict JSON form of metadata exactly as Go decodeMetadata: valid UTF-8, a single
 * object (whitespace around it allowed, nothing else), no unknown field (case-sensitive), every
 * required field present, the last occurrence of a repeated field not null and every occurrence
 * null or of the field's type (Go's struct decoding reports a wrong type even when overwritten),
 * integers without fraction or exponent, v equal to 1. Escaped lone surrogates become U+FFFD, as
 * in Go. Any violation is invalid-metadata.
 */
export function decodeMetadata(plain: Uint8Array): Metadata {
  let text: string;
  try {
    text = decoder.decode(plain);
  } catch {
    throw new E2EError('invalid-metadata', 'not valid UTF-8');
  }
  const fields = new JsonObjectParser(text).parse();
  for (const [name, spec] of FIELDS) {
    if (spec.required && !fields.has(name)) throw new E2EError('invalid-metadata', `missing field "${name}"`);
  }
  if (fields.get('v') !== 1) throw new E2EError('invalid-metadata', 'version');
  return {
    index: fields.get('index') as number,
    count: fields.get('count') as number,
    name: fields.get('name') as string,
    path: (fields.get('path') as string | undefined) ?? '',
    type: fields.get('type') as string,
    size: fields.get('size') as number,
    sha256: fields.get('sha256') as string,
  };
}

/** Minimal strict JSON parser for the metadata object (only strings, integers and null values). */
class JsonObjectParser {
  private pos = 0;

  constructor(private readonly s: string) {}

  /** Parses the whole text and returns the last value of each field. */
  parse(): Map<string, FieldValue> {
    const fields = new Map<string, FieldValue>();
    this.ws();
    this.expect('{');
    this.ws();
    if (this.peek() === '}') {
      this.pos++;
    } else {
      for (;;) {
        this.ws();
        const name = this.string();
        this.ws();
        this.expect(':');
        this.ws();
        const spec = FIELDS.get(name);
        if (spec === undefined) throw this.fail(`unknown field "${name}"`);
        const value = this.value(spec.kind);
        fields.set(name, value);
        this.ws();
        if (this.peek() === ',') {
          this.pos++;
          continue;
        }
        this.expect('}');
        break;
      }
    }
    this.ws();
    if (this.pos !== this.s.length) throw this.fail('data after the object');
    for (const [name, value] of fields) {
      if (value === null) throw this.fail(`null field "${name}"`);
    }
    return fields;
  }

  /** Parses a value that must be null or of the given kind. */
  private value(kind: FieldKind): FieldValue {
    const c = this.peek();
    if (c === 'n') {
      if (this.s.startsWith('null', this.pos)) {
        this.pos += 4;
        return null;
      }
      throw this.fail('bad literal');
    }
    if (kind === 'string') return this.string();
    return this.integer();
  }

  /** Parses an integer literal, -?(0|[1-9][0-9]*), without fraction or exponent. */
  private integer(): number {
    const m = /^-?(?:0|[1-9][0-9]*)/.exec(this.s.slice(this.pos, this.pos + 40));
    if (m === null) throw this.fail('not an integer');
    this.pos += m[0].length;
    const c = this.peek();
    if (c === '.' || c === 'e' || c === 'E' || (c >= '0' && c <= '9')) {
      throw this.fail('not an integer');
    }
    const n = Number(m[0]);
    if (!Number.isSafeInteger(n)) throw this.fail('integer out of range');
    return n + 0; // -0 is 0
  }

  /** Parses a JSON string with Go's unquoting rules. */
  private string(): string {
    this.expect('"');
    let out = '';
    for (;;) {
      if (this.pos >= this.s.length) throw this.fail('unterminated string');
      const c = this.s.charCodeAt(this.pos);
      if (c === 0x22) {
        this.pos++;
        return out;
      }
      if (c < 0x20) throw this.fail('control character in string');
      if (c !== 0x5c) {
        out += this.s[this.pos];
        this.pos++;
        continue;
      }
      const e = this.s[this.pos + 1];
      const simple = e === undefined ? undefined : ESCAPES[e];
      if (simple !== undefined) {
        out += simple;
        this.pos += 2;
        continue;
      }
      if (e !== 'u') throw this.fail('bad escape');
      const r = this.hex4(this.pos + 2);
      if (r >= 0xd800 && r < 0xe000) {
        // Go: a high surrogate followed by an escaped low surrogate is one code point; any other
        // surrogate becomes U+FFFD and the following escape is read on its own.
        const r2 = this.s.startsWith('\\u', this.pos + 6) ? this.hex4(this.pos + 8) : -1;
        if (r < 0xdc00 && r2 >= 0xdc00 && r2 < 0xe000) {
          out += String.fromCharCode(r, r2);
          this.pos += 12;
          continue;
        }
        out += '\ufffd';
      } else {
        out += String.fromCharCode(r);
      }
      this.pos += 6;
    }
  }

  /** Reads four hexadecimal digits at i. */
  private hex4(i: number): number {
    const h = this.s.slice(i, i + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(h)) throw this.fail('bad \\u escape');
    return parseInt(h, 16);
  }

  /** Skips JSON whitespace (space, tab, line feed, carriage return). */
  private ws(): void {
    while (/^[ \t\n\r]$/.test(this.peek())) this.pos++;
  }

  /** Returns the next character, '' at the end. */
  private peek(): string {
    return this.s.charAt(this.pos);
  }

  /** Consumes c or fails. */
  private expect(c: string): void {
    if (this.peek() !== c) throw this.fail(`expected "${c}"`);
    this.pos++;
  }

  private fail(detail: string): E2EError {
    return new E2EError('invalid-metadata', detail);
  }
}

/** Simple JSON escapes and the character each one stands for. */
const ESCAPES: Readonly<Record<string, string>> = {
  '"': '"',
  '\\': '\\',
  '/': '/',
  b: '\b',
  f: '\f',
  n: '\n',
  r: '\r',
  t: '\t',
};
