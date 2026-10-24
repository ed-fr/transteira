import { describe, expect, it } from 'vitest';
import { MAX_TRANSFER_BYTES, formatBytes, parseByteSize, toFieldValue, withinCeiling } from './bytes';

describe('bytes', () => {
  it('uses the 20 GiB ceiling of the API', () => {
    expect(MAX_TRANSFER_BYTES).toBe(21474836480);
  });

  it('parses amounts with a binary unit', () => {
    expect(parseByteSize('20', 'GiB')).toEqual({ ok: true, bytes: MAX_TRANSFER_BYTES });
    expect(parseByteSize('1.5', 'GiB')).toEqual({ ok: true, bytes: 1610612736 });
    expect(parseByteSize(' 1,5 ', 'MiB')).toEqual({ ok: true, bytes: 1572864 });
    expect(parseByteSize('2', 'TiB')).toEqual({ ok: true, bytes: 2 * 2 ** 40 });
  });

  it('refuses malformed, zero and too large amounts', () => {
    expect(parseByteSize('', 'MiB')).toEqual({ ok: false, error: 'invalid' });
    expect(parseByteSize('-1', 'MiB')).toEqual({ ok: false, error: 'invalid' });
    expect(parseByteSize('1e3', 'MiB')).toEqual({ ok: false, error: 'invalid' });
    expect(parseByteSize('1.2345', 'MiB')).toEqual({ ok: false, error: 'invalid' });
    expect(parseByteSize('0', 'GiB')).toEqual({ ok: false, error: 'not-positive' });
    expect(parseByteSize('20.001', 'GiB', MAX_TRANSFER_BYTES)).toEqual({ ok: false, error: 'too-large' });
    expect(parseByteSize('999999999999999', 'TiB')).toEqual({ ok: false, error: 'too-large' });
    expect(parseByteSize('20', 'GiB', MAX_TRANSFER_BYTES)).toEqual({ ok: true, bytes: MAX_TRANSFER_BYTES });
  });

  it('checks the ceiling', () => {
    expect(withinCeiling(MAX_TRANSFER_BYTES)).toBe(true);
    expect(withinCeiling(MAX_TRANSFER_BYTES + 1)).toBe(false);
    expect(withinCeiling(10, 5)).toBe(false);
  });

  it('splits bytes into a field value', () => {
    expect(toFieldValue(MAX_TRANSFER_BYTES)).toEqual({ amount: '20', unit: 'GiB' });
    expect(toFieldValue(2 ** 40)).toEqual({ amount: '1', unit: 'TiB' });
    expect(toFieldValue(1536 * 2 ** 20)).toEqual({ amount: '1536', unit: 'MiB' });
    expect(toFieldValue(1610612737)).toEqual({ amount: '1.5', unit: 'GiB' });
    expect(toFieldValue(512)).toEqual({ amount: '0', unit: 'MiB' });
  });

  it('formats bytes for display', () => {
    expect(formatBytes(MAX_TRANSFER_BYTES)).toBe('20 GiB');
    expect(formatBytes(1.5 * 2 ** 20)).toBe('1.5 MiB');
    expect(formatBytes(1.5 * 2 ** 20, 'fr')).toBe('1,5 MiB');
    expect(formatBytes(3 * 2 ** 40)).toBe('3 TiB');
    expect(formatBytes(2048)).toBe('2 KiB');
    expect(formatBytes(512)).toBe('512 B');
  });
});
