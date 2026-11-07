// Unit tests of sealed.ts beyond the reference vectors: metadata rules, the strict JSON parser
// (mirroring Go's encoding/json behaviour on repeated fields, nulls and surrogates) and messages.

import { describe, expect, it } from 'vitest';
import { isE2EError, type E2EErrorCode } from './errors';
import {
  checkMessageFraming,
  checkMetadataFraming,
  decodeMetadata,
  encodeMetadata,
  openMessage,
  openMetadata,
  sealMessage,
  sealMessageRaw,
  sealMetadata,
  sealMetadataRaw,
  type Metadata,
} from './sealed';
import { MAX_MESSAGE_RUNES, MAX_METADATA_SIZE, importTransferKey } from './tte2';

const key = Uint8Array.from({ length: 32 }, (_, i) => i * 3);
const sha = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const meta: Metadata = {
  index: 1,
  count: 2,
  name: 'a.txt',
  path: '',
  type: 'text/plain',
  size: 3,
  sha256: sha,
};

/** Returns the E2E code f throws or rejects with. */
async function codeOf(f: () => unknown): Promise<E2EErrorCode | 'none'> {
  try {
    await f();
    return 'none';
  } catch (err) {
    if (isE2EError(err)) return err.code;
    throw err;
  }
}

/** Decodes a JSON text as metadata. */
function decode(json: string): Metadata {
  return decodeMetadata(new TextEncoder().encode(json));
}

/** Code of decoding a JSON text as metadata. */
function decodeCode(json: string): Promise<E2EErrorCode | 'none'> {
  return codeOf(() => decode(json));
}

/** The JSON object of meta with extra text inserted before the closing brace. */
const obj = (extra = '') =>
  `{"v":1,"index":1,"count":2,"name":"a","type":"","size":0,"sha256":"${sha}"${extra}}`;

describe('metadata sealing', () => {
  it('round-trips with a random nonce', async () => {
    const base = await importTransferKey(key);
    const withPath = { ...meta, path: 'docs/2026' };
    const a = await sealMetadata(base, 1, withPath);
    expect(a).not.toBe(await sealMetadata(base, 1, withPath));
    expect(await openMetadata(base, 1, a)).toEqual(withPath);
    checkMetadataFraming(a);
  });

  it('enforces the metadata rules before sealing', async () => {
    const bad: Partial<Metadata>[] = [
      { index: 0 },
      { count: 0 },
      { count: 1 },
      { name: '' },
      { size: -1 },
      { size: 1.5 },
      { count: Number.MAX_SAFE_INTEGER + 1 },
      { index: 0.5 },
      { sha256: sha.toUpperCase() },
      { sha256: sha.slice(1) },
      { name: 'a\ud800' },
      { path: '\udc00' },
      { type: 'x\ud83d' },
    ];
    for (const change of bad) {
      expect(await codeOf(() => sealMetadata(key, 1, { ...meta, ...change })), JSON.stringify(change)).toBe(
        'invalid-metadata',
      );
    }
    expect(await codeOf(() => sealMetadata(key, -1, meta))).toBe('invalid-index');
    expect(await codeOf(() => sealMetadata(key, 1, { ...meta, name: 'é😀' }))).toBe('none');
  });

  it('limits the sealed size', async () => {
    const limit = MAX_METADATA_SIZE - 29;
    expect(await codeOf(() => sealMetadataRaw(key, 0, new Uint8Array(limit)))).toBe('none');
    expect(await codeOf(() => sealMetadataRaw(key, 0, new Uint8Array(limit + 1)))).toBe('invalid-metadata');
    expect(await codeOf(() => sealMetadataRaw(key, -1, new Uint8Array(1)))).toBe('invalid-index');
    expect(await codeOf(() => sealMetadata(key, 1, { ...meta, name: 'x'.repeat(limit) }))).toBe(
      'invalid-metadata',
    );
  });

  it('refuses a nonce of the wrong size', async () => {
    await expect(sealMetadata(key, 1, meta, { nonce: new Uint8Array(11) })).rejects.toThrow(RangeError);
  });

  it('opens only with a valid index', async () => {
    expect(await codeOf(() => openMetadata(key, 2 ** 32, 'AA'))).toBe('invalid-index');
  });

  it('encodes like the Go writer', () => {
    expect(encodeMetadata({ ...meta, name: '<a>&\u2028\u2029"\\\n\u0001', path: 'p' })).toBe(
      `{"v":1,"index":1,"count":2,"name":"<a>&\\u2028\\u2029\\"\\\\\\n\\u0001","path":"p",` +
        `"type":"text/plain","size":3,"sha256":"${sha}"}`,
    );
  });
});

describe('metadata JSON parsing', () => {
  it('accepts the strict form with whitespace and escapes', () => {
    expect(decode(` \t\r\n${obj()} \n`).name).toBe('a');
    expect(decode(obj(`,"path":"x/y"`)).path).toBe('x/y');
    expect(
      decode(
        `{ "v" : 1 , "index" : 1 , "count" : 2 , "name" : "a" , "type" : "" , "size" : 0 , "sha256" : "${sha}" }`,
      ).count,
    ).toBe(2);
    const escaped = decode(obj(`,"path":"\\"\\\\\\/\\b\\f\\n\\r\\t\\u00e9\\u00E9\\ud83d\\ude00"`));
    expect(escaped.path).toBe('"\\/\b\f\n\r\t\u00e9\u00e9\u{1f600}');
    expect(decode(obj(`,"path":"é😀"`)).path).toBe('é😀');
    expect(decode(obj(`,"\\u0070ath":"k"`)).path).toBe('k');
  });

  it('replaces escaped lone surrogates by U+FFFD as Go does', () => {
    expect(decode(obj(`,"path":"\\ud800x"`)).path).toBe('\ufffdx');
    expect(decode(obj(`,"path":"\\udc00"`)).path).toBe('\ufffd');
    expect(decode(obj(`,"path":"\\ud800\\u0041"`)).path).toBe('\ufffdA');
    expect(decode(obj(`,"path":"\\ud800\\ud800\\udc00"`)).path).toBe('\ufffd\u{10000}');
    expect(decode(obj(`,"path":"\\udc00\\udc00"`)).path).toBe('\ufffd\ufffd');
  });

  it('keeps the last value of a repeated field, as Go and JSON.parse', () => {
    expect(decode(obj(`,"name":"b"`)).name).toBe('b');
    expect(decode(obj(`,"path":null,"path":"p"`)).path).toBe('p');
    expect(decode(`{"index":-0,"v":1,"count":1,"name":"a","type":"","size":0,"sha256":"${sha}"}`).index).toBe(
      0,
    );
  });

  it('refuses everything else', async () => {
    const cases = [
      '',
      'null',
      '[]',
      '"x"',
      '{}',
      '\ufeff' + obj(),
      obj() + 'x',
      obj() + '{}',
      obj(',"extra":1'),
      obj(',"Path":"x"'),
      obj(',"path":null'),
      obj(',"name":null'),
      obj(',"path":"p","path":null'),
      obj(',"size":"0"'),
      obj(',"size":"1","size":1'),
      obj(',"name":1'),
      obj(',"name":true'),
      obj(',"size":true'),
      obj(',"size":1.0'),
      obj(',"size":1e2'),
      obj(',"size":1E2'),
      obj(',"size":01'),
      obj(',"size":-'),
      obj(',"size":9007199254740992'),
      obj(',"size":' + '9'.repeat(50)),
      obj(',"size":nul'),
      obj(',"size":[1]'),
      obj(',"size":{}'),
      obj(',"path":"a\\x"'),
      obj(',"path":"a\\u12"'),
      obj(',"path":"\\ud800\\u12g4"'),
      obj(',"path":"a\\'),
      obj(',"path":"a\u0001"'),
      obj(',"path":"unterminated'),
      obj(','),
      obj(',"path" "x"'),
      obj(' "path":"x"'),
      `{"v":2,"index":1,"count":2,"name":"a","type":"","size":0,"sha256":"${sha}"}`,
      `{"v":1,"index":1,"count":2,"name":"a","type":"","sha256":"${sha}"}`,
      `{"v":1,"index":1,"count":2,"name":"a","size":0,"sha256":"${sha}"}`,
      `{v:1}`,
      `{"v":1`,
      '{"a\\',
    ];
    for (const json of cases) expect(await decodeCode(json), json).toBe('invalid-metadata');
    expect(await codeOf(() => decodeMetadata(Uint8Array.of(0x7b, 0xff, 0x7d)))).toBe('invalid-metadata');
  });

  it('applies the rules after parsing', async () => {
    const sealed = await sealMetadataRaw(
      key,
      1,
      new TextEncoder().encode(obj().replace('"count":2', '"count":1')),
    );
    expect(await codeOf(() => openMetadata(key, 1, sealed))).toBe('invalid-metadata');
  });
});

describe('messages', () => {
  it('round-trips and checks the length in code points', async () => {
    const base = await importTransferKey(key);
    const longest = '😀'.repeat(MAX_MESSAGE_RUNES);
    const s = await sealMessage(base, longest);
    expect(await openMessage(base, s)).toBe(longest);
    checkMessageFraming(s);
    expect(await codeOf(() => sealMessage(base, longest + 'a'))).toBe('invalid-message');
    expect(await codeOf(() => sealMessage(base, 'a\ud800'))).toBe('invalid-message');
    const tooLong = await sealMessageRaw(base, new TextEncoder().encode('a'.repeat(MAX_MESSAGE_RUNES + 1)));
    expect(await codeOf(() => openMessage(base, tooLong))).toBe('invalid-message');
  });

  it('keeps a leading byte order mark', async () => {
    const s = await sealMessageRaw(key, Uint8Array.of(0xef, 0xbb, 0xbf, 0x61));
    expect(await openMessage(key, s)).toBe('\ufeffa');
  });

  it('checks the framing without the key', async () => {
    for (const bad of ['', 'AA', 'A'.repeat(40) + '=', 'Ag' + 'A'.repeat(40)]) {
      expect(await codeOf(() => checkMessageFraming(bad))).toBe('encoding');
      expect(await codeOf(() => checkMetadataFraming(bad))).toBe('encoding');
    }
    expect(await codeOf(() => checkMetadataFraming('AQ' + 'A'.repeat(5461)))).toBe('encoding');
  });
});
