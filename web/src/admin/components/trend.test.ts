import { describe, expect, it } from 'vitest';
import en from '../../locales/en/adminComponents.json';
import fr from '../../locales/fr/adminComponents.json';
import { sumPeriods, trend, trendText } from './trend';

const t = (key: string, params?: Record<string, string | number>): string =>
  `${key}${params === undefined ? '' : ` ${JSON.stringify(params)}`}`;
const percent = (ratio: number): string => `${Math.round(ratio * 100)} %`;

describe('trend', () => {
  it.each([
    [118, 100, { kind: 'up', percent: 18 }],
    [50, 100, { kind: 'down', percent: 50 }],
    [100, 100, { kind: 'flat', percent: 0 }],
    [1001, 1000, { kind: 'flat', percent: 0 }],
    [0, 0, { kind: 'flat', percent: 0 }],
    [3, 0, { kind: 'new' }],
    [0, 4, { kind: 'down', percent: 100 }],
    [5, null, { kind: 'none' }],
    [5, undefined, { kind: 'none' }],
    [5, Number.NaN, { kind: 'none' }],
    [Number.POSITIVE_INFINITY, 4, { kind: 'none' }],
    [-1, 4, { kind: 'none' }],
    [1, -4, { kind: 'none' }],
  ])('%s against %s', (current, previous, expected) => {
    expect(trend(current, previous)).toEqual(expected);
  });
});

describe('trendText', () => {
  it('writes a rise and a fall with their percentage and period', () => {
    expect(trendText({ kind: 'up', percent: 18 }, 30, t, percent)).toBe(
      'adminComponents.trend.up {"percent":"18 %","days":30}',
    );
    expect(trendText({ kind: 'down', percent: 5 }, 7, t, percent)).toBe(
      'adminComponents.trend.down {"percent":"5 %","days":7}',
    );
  });

  it('writes a flat trend and a new activity without percentage', () => {
    expect(trendText({ kind: 'flat', percent: 0 }, 7, t, percent)).toBe(
      'adminComponents.trend.flat {"days":7}',
    );
    expect(trendText({ kind: 'new' }, 30, t, percent)).toBe('adminComponents.trend.new {"days":30}');
  });

  it('shows nothing without a previous period', () => {
    expect(trendText({ kind: 'none' }, 30, t, percent)).toBeUndefined();
  });

  it('has the four texts in every language', () => {
    for (const bundle of [en, fr]) {
      for (const kind of ['up', 'down', 'flat', 'new'] as const) {
        expect(bundle.trend[kind]).toContain('{days}');
      }
      expect(bundle.trend.up).toContain('{percent}');
      expect(bundle.trend.down).toContain('{percent}');
    }
  });
});

describe('sumPeriods', () => {
  type Row = { a: number; b?: number; previous?: { a: number; b?: number } | undefined };
  const keys = ['a', 'b'] as const;
  const pick = (c: Row | NonNullable<Row['previous']>) => ({ a: c.a, b: c.b });

  it('sums the period and the previous period when every row carries it', () => {
    const rows: Row[] = [
      { a: 1, b: 2, previous: { a: 10, b: 20 } },
      { a: 3, previous: { a: 30, b: 40 } },
    ];
    expect(sumPeriods(rows, keys, pick)).toEqual({ current: { a: 4, b: 2 }, previous: { a: 40, b: 60 } });
  });

  it('drops the previous period when a row has none, or without any row', () => {
    expect(
      sumPeriods<'a' | 'b', Row>([{ a: 1, previous: { a: 1 } }, { a: 2 }], keys, pick).previous,
    ).toBeUndefined();
    expect(sumPeriods<'a' | 'b', Row>([], keys, pick)).toEqual({
      current: { a: 0, b: 0 },
      previous: undefined,
    });
  });

  it('counts missing, negative or not finite counters as 0', () => {
    const rows: Row[] = [
      { a: -5, b: Number.NaN },
      { a: Number.POSITIVE_INFINITY, b: 7 },
    ];
    expect(sumPeriods(rows, keys, pick).current).toEqual({ a: 0, b: 7 });
  });

  it('treats a null previous period as absent', () => {
    const rows = [{ a: 1, previous: null }];
    expect(sumPeriods(rows, ['a'], (c) => ({ a: (c as { a: number }).a })).previous).toBeUndefined();
  });
});
