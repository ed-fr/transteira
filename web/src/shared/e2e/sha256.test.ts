import { createHash, randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { encodeBitLength, Sha256, toHex } from './sha256';

function hashOf(data: Uint8Array): string {
  return toHex(new Sha256().update(data).digest());
}

describe('Sha256', () => {
  const enc = new TextEncoder();
  it.each([
    ['', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
    ['abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
    [
      'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
      '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
    ],
    [
      'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu',
      'cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1',
    ],
  ])('NIST vector %j', (text, hex) => {
    expect(hashOf(enc.encode(text))).toBe(hex);
  });

  it('hashes one million "a" in one go and in 1-byte updates', () => {
    const million = new Uint8Array(1_000_000).fill(0x61);
    const expected = 'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0';
    expect(hashOf(million)).toBe(expected);
    const h = new Sha256();
    for (let i = 0; i < 100_000; i++) h.update(million.subarray(i, i + 1));
    h.update(million.subarray(100_000));
    expect(toHex(h.digest())).toBe(expected);
  });

  it('matches node:crypto for random lengths and random splits', () => {
    for (let n = 0; n < 300; n++) {
      const len = n < 200 ? n : Math.floor(Math.random() * 5000);
      const data = randomBytes(len);
      const h = new Sha256();
      let pos = 0;
      while (pos < len) {
        const step = Math.floor(Math.random() * 150);
        h.update(data.subarray(pos, pos + step));
        pos += step;
      }
      expect(toHex(h.digest())).toBe(createHash('sha256').update(data).digest('hex'));
    }
  });

  it('handles data views that do not start at offset zero', () => {
    const big = randomBytes(1000);
    expect(hashOf(big.subarray(13, 700))).toBe(
      createHash('sha256').update(big.subarray(13, 700)).digest('hex'),
    );
  });

  it('refuses use after digest', () => {
    const h = new Sha256();
    h.digest();
    expect(() => h.update(new Uint8Array(1))).toThrow('after digest');
    expect(() => h.digest()).toThrow('twice');
  });
});

describe('encodeBitLength', () => {
  it('encodes the bit count as 64-bit big-endian, beyond 4 GiB', () => {
    const values = [0, 1, 55, 2 ** 29 - 1, 2 ** 29, 2 ** 32, 2 ** 32 + 3, 20 * 2 ** 30 + 12345, 2 ** 50 + 7];
    for (const bytes of values) {
      const out = new Uint8Array(10);
      encodeBitLength(bytes, out, 1);
      const expected = BigInt(bytes) * 8n;
      expect(new DataView(out.buffer).getBigUint64(1)).toBe(expected);
      expect(out[0]).toBe(0);
      expect(out[8]).toBe(Number(expected & 0xffn));
    }
  });
});

describe('toHex', () => {
  it('pads single digits', () => {
    expect(toHex(new Uint8Array([0, 1, 15, 16, 255]))).toBe('00010f10ff');
  });
});
