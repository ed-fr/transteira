import { describe, expect, it } from 'vitest';
import { gaugeLevel, markerPercent } from './gauge';

describe('markerPercent', () => {
  it.each([
    [85, 0, 100, 85],
    [0.85, 0, 1, 85],
    [50, 0, 200, 25],
    [1, 0, 3, 33.33],
    [150, 0, 100, 100],
    [-5, 0, 100, 0],
    [60, 50, 150, 10],
  ])('places %s on %s..%s at %s %', (threshold, min, max, expected) => {
    expect(markerPercent(threshold, min, max)).toBe(expected);
  });

  it.each([
    [undefined, 0, 100],
    [Number.NaN, 0, 100],
    [50, 0, 0],
    [50, 10, 5],
    [50, 0, Number.POSITIVE_INFINITY],
    [50, Number.NaN, 100],
  ])('draws no marker for %s on %s..%s', (threshold, min, max) => {
    expect(markerPercent(threshold, min, max)).toBeUndefined();
  });
});

describe('gaugeLevel', () => {
  it('is danger from the maximum, warning from the threshold', () => {
    expect(gaugeLevel(100, 100, 85)).toBe('danger');
    expect(gaugeLevel(120, 100)).toBe('danger');
    expect(gaugeLevel(85, 100, 85)).toBe('warning');
    expect(gaugeLevel(84, 100, 85)).toBe('default');
    expect(gaugeLevel(90, 100)).toBe('default');
    expect(gaugeLevel(90, 100, Number.NaN)).toBe('default');
  });

  it('stays default on an empty or invalid range', () => {
    expect(gaugeLevel(5, 0, 1)).toBe('default');
    expect(gaugeLevel(Number.NaN, 100, 1)).toBe('default');
    expect(gaugeLevel(5, Number.POSITIVE_INFINITY)).toBe('default');
  });
});
