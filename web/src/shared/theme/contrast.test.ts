import { describe, expect, it } from 'vitest';
import {
  DARK_BACKGROUND,
  LIGHT_BACKGROUND,
  MIN_RATIO_AA,
  MIN_RATIO_AAA,
  TEXT_ON_PRIMARY,
  checkContrast,
  contrastRatio,
  levelFor,
  parseHexColor,
  relativeLuminance,
  toHex,
  truncateRatio,
  type Rgb,
} from './contrast';

function color(hex: string): Rgb {
  const c = parseHexColor(hex);
  if (c === null) {
    throw new Error(`invalid test colour ${hex}`);
  }
  return c;
}

// The expected values are those of internal/branding/contrast_test.go.
describe('contrast (mirror of internal/branding)', () => {
  it('uses the same constants as the Go package', () => {
    expect(LIGHT_BACKGROUND).toEqual({ r: 255, g: 255, b: 255 });
    expect(DARK_BACKGROUND).toEqual({ r: 0x11, g: 0x18, b: 0x27 });
    expect(TEXT_ON_PRIMARY).toEqual({ r: 255, g: 255, b: 255 });
    expect(MIN_RATIO_AAA).toBe(7);
    expect(MIN_RATIO_AA).toBe(4.5);
  });

  it('parses #RRGGBB in either case', () => {
    expect(parseHexColor('#000000')).toEqual({ r: 0, g: 0, b: 0 });
    expect(parseHexColor('#FFFFFF')).toEqual({ r: 255, g: 255, b: 255 });
    expect(parseHexColor('#1a2B3c')).toEqual({ r: 0x1a, g: 0x2b, b: 0x3c });
  });

  it.each(['', '#FFF', 'FFFFFFF', '#FFFFFFF', '#GGGGGG', '#12345', ' #123456', 'rgb(0,0,0)', '#123456;'])(
    'rejects %j',
    (value) => {
      expect(parseHexColor(value)).toBeNull();
    },
  );

  it('formats colours uppercase', () => {
    expect(toHex(color('#1a2b3c'))).toBe('#1A2B3C');
    expect(toHex({ r: 0, g: 5, b: 255 })).toBe('#0005FF');
  });

  it.each([
    ['#000000', 0],
    ['#FFFFFF', 1],
    ['#FF0000', 0.2126],
    ['#00FF00', 0.7152],
    ['#0000FF', 0.0722],
    ['#0A0A0A', 0.0030352698],
    ['#777777', 0.18447565544],
  ])('relative luminance of %s is %f', (hex, want) => {
    expect(relativeLuminance(color(hex))).toBeCloseTo(want, 5);
  });

  it.each([
    ['#000000', '#FFFFFF', 21],
    ['#FFFFFF', '#000000', 21],
    ['#777777', '#FFFFFF', 4.478],
    ['#767676', '#FFFFFF', 4.542],
    ['#595959', '#FFFFFF', 7.0],
    ['#123456', '#123456', 1],
  ])('contrast of %s on %s is %f', (a, b, want) => {
    expect(Math.abs(contrastRatio(color(a), color(b)) - want)).toBeLessThan(0.005);
  });

  it.each([
    [21, 'AAA'],
    [7, 'AAA'],
    [6.99, 'AA'],
    [4.5, 'AA'],
    [4.49, 'fail'],
    [1, 'fail'],
  ] as const)('level of %f is %s', (ratio, level) => {
    expect(levelFor(ratio)).toBe(level);
  });

  it('truncates ratios without rounding up', () => {
    expect(truncateRatio(4.4789)).toBe(4.47);
    expect(truncateRatio(20.9999999999999)).toBe(21);
  });

  it('checks the same pairs as branding.Check', () => {
    expect(checkContrast(color('#000000'), color('#777777'))).toEqual([
      { pair: 'primary-on-light', ratio: 21, level: 'AAA' },
      { pair: 'accent-on-light', ratio: 4.47, level: 'fail' },
      { pair: 'text-on-primary', ratio: 21, level: 'AAA' },
      { pair: 'primary-on-dark', ratio: 1.18, level: 'fail' },
      { pair: 'accent-on-dark', ratio: 3.96, level: 'fail' },
    ]);
    const mid = checkContrast(color('#767676'), color('#FFFFFF'));
    expect(mid[0]).toEqual({ pair: 'primary-on-light', ratio: 4.54, level: 'AA' });
    expect(mid[1]).toEqual({ pair: 'accent-on-light', ratio: 1, level: 'fail' });
    expect(mid[2]).toEqual({ pair: 'text-on-primary', ratio: 4.54, level: 'AA' });
    expect(mid[3]).toEqual({ pair: 'primary-on-dark', ratio: 3.9, level: 'fail' });
    expect(mid[4]).toEqual({ pair: 'accent-on-dark', ratio: 17.73, level: 'AAA' });
  });
});
