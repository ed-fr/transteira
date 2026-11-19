import { describe, expect, it } from 'vitest';
import { swatchColor } from './swatch';

describe('swatchColor', () => {
  it.each(['#1d4ed8', '#B45309', '#000000', '#FfFfFf'])('keeps %s', (value) => {
    expect(swatchColor(value)).toBe(value);
  });

  it.each([
    null,
    undefined,
    42,
    '',
    '1d4ed8',
    '#1d4ed',
    '#1d4ed80',
    '#1d4ed8ff',
    '#ggg000',
    'red',
    'rgb(0 0 0)',
    '#1d4ed8;background:url(x)',
    ' #1d4ed8',
    '#1d4ed8\n',
    'url(#a)',
  ])('rejects %s', (value) => {
    expect(swatchColor(value)).toBeNull();
  });
});
