import { expect, it } from 'vitest';
import { decodeBase64Url, encodeBase64Url } from './base64url';
import { referenceBase64Url, seededRandom } from './tte2-helpers.test-helper';

it('encodes and decodes every length like the platform encoder', () => {
  const rand = seededRandom(7);
  for (let n = 0; n < 70; n++) {
    const b = Uint8Array.from({ length: n }, () => rand(256));
    const s = encodeBase64Url(b);
    expect(s).toBe(referenceBase64Url(b));
    expect(decodeBase64Url(s)).toEqual(b);
  }
});

it('refuses non-canonical or foreign input', () => {
  expect(decodeBase64Url('')).toEqual(new Uint8Array(0));
  expect(decodeBase64Url('A')).toBeNull(); // impossible length
  expect(decodeBase64Url('QR')).toBeNull(); // non-zero unused bits
  expect(decodeBase64Url('QQ=')).toBeNull(); // padding
  expect(decodeBase64Url('QQ==')).toBeNull();
  expect(decodeBase64Url('a+b/')).toBeNull(); // standard alphabet
  expect(decodeBase64Url('ab\ncd')).toBeNull();
  expect(decodeBase64Url('abé')).toBeNull(); // beyond ASCII
  expect(decodeBase64Url('QQ')).toEqual(Uint8Array.of(0x41));
});
