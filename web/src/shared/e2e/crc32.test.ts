import { randomBytes } from 'node:crypto';
import zlib from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { Crc32 } from './crc32';

describe('Crc32', () => {
  it('matches the known check values', () => {
    expect(new Crc32().value()).toBe(0);
    expect(new Crc32().update(new TextEncoder().encode('123456789')).value()).toBe(0xcbf43926);
    expect(
      new Crc32().update(new TextEncoder().encode('The quick brown fox jumps over the lazy dog')).value(),
    ).toBe(0x414fa339);
  });

  it('matches zlib.crc32 for random lengths and random splits', () => {
    for (let n = 0; n < 300; n++) {
      const len = n < 100 ? n : Math.floor(Math.random() * 20000);
      const data = randomBytes(len);
      const c = new Crc32();
      let pos = 0;
      while (pos < len) {
        const step = Math.floor(Math.random() * 40);
        c.update(data.subarray(pos, pos + step));
        pos += step;
      }
      expect(c.value()).toBe(zlib.crc32(data));
    }
  });

  it('can be read between updates', () => {
    const data = randomBytes(100);
    const c = new Crc32().update(data.subarray(0, 50));
    expect(c.value()).toBe(zlib.crc32(data.subarray(0, 50)));
    expect(c.update(data.subarray(50)).value()).toBe(zlib.crc32(data));
  });
});
