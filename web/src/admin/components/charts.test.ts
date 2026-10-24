import { describe, expect, it } from 'vitest';
import en from '../../locales/en/adminComponents.json';
import fr from '../../locales/fr/adminComponents.json';
import {
  barLayout,
  chartSummaryText,
  labelIndexes,
  niceCeil,
  summarizeSeries,
  type Translate,
} from './charts';

const fakeT: Translate = (key, params) => (params === undefined ? key : `${key} ${JSON.stringify(params)}`);

describe('niceCeil', () => {
  it('keeps at least 1 for empty, zero, negative or invalid maxima', () => {
    expect(niceCeil(0)).toBe(1);
    expect(niceCeil(-5)).toBe(1);
    expect(niceCeil(0.3)).toBe(1);
    expect(niceCeil(1)).toBe(1);
    expect(niceCeil(Number.NaN)).toBe(1);
    expect(niceCeil(Number.POSITIVE_INFINITY)).toBe(1);
  });

  it('rounds up to 1, 2, 2.5, 5 or 10 times a power of ten', () => {
    expect(niceCeil(1.5)).toBe(2);
    expect(niceCeil(2)).toBe(2);
    expect(niceCeil(2.2)).toBe(2.5);
    expect(niceCeil(3)).toBe(5);
    expect(niceCeil(7)).toBe(10);
    expect(niceCeil(10)).toBe(10);
    expect(niceCeil(11)).toBe(20);
    expect(niceCeil(240)).toBe(250);
    expect(niceCeil(999)).toBe(1000);
    expect(niceCeil(1000)).toBe(1000);
    expect(niceCeil(30 * 2 ** 30)).toBe(5e10);
  });
});

describe('barLayout', () => {
  const dims = { width: 200, height: 120, left: 40, bottom: 20, top: 0, right: 0, gap: 0.5 };

  it('lays out bars proportionally against the nice maximum', () => {
    const layout = barLayout(
      [
        { label: 'a', value: 50 },
        { label: 'b', value: 100 },
      ],
      dims,
    );
    expect(layout.max).toBe(100);
    expect(layout.plot).toEqual({ x: 40, y: 0, width: 160, height: 100 });
    expect(layout.bars).toEqual([
      { x: 60, y: 50, width: 40, height: 50, cx: 80, label: 'a', value: 50 },
      { x: 140, y: 0, width: 40, height: 100, cx: 160, label: 'b', value: 100 },
    ]);
    expect(layout.ticks).toEqual([
      { value: 0, y: 100 },
      { value: 50, y: 50 },
      { value: 100, y: 0 },
    ]);
  });

  it('handles an empty series', () => {
    const layout = barLayout([], dims);
    expect(layout.bars).toEqual([]);
    expect(layout.max).toBe(1);
    expect(layout.ticks.map((tick) => tick.value)).toEqual([0, 1]);
  });

  it('draws zero, negative and invalid values as empty bars', () => {
    const layout = barLayout(
      [
        { label: 'a', value: 0 },
        { label: 'b', value: -3 },
        { label: 'c', value: Number.NaN },
      ],
      dims,
    );
    expect(layout.max).toBe(1);
    for (const bar of layout.bars) {
      expect(bar.height).toBe(0);
      expect(bar.y).toBe(100);
    }
    expect(layout.bars[1]?.value).toBe(-3);
  });

  it('skips a middle tick that is not a whole number', () => {
    expect(barLayout([{ label: 'a', value: 2.3 }], dims).ticks.map((tick) => tick.value)).toEqual([0, 2.5]);
  });

  it('applies the default margins and clamps the gap and the plot', () => {
    const layout = barLayout([{ label: 'a', value: 1 }], { width: 100, height: 50, gap: 5 });
    expect(layout.plot).toEqual({ x: 56, y: 8, width: 36, height: 18 });
    expect(layout.bars[0]?.width).toBeCloseTo(3.6);
    const tiny = barLayout([{ label: 'a', value: 1 }], { width: 10, height: 10, gap: -1 });
    expect(tiny.plot.width).toBe(0);
    expect(tiny.plot.height).toBe(0);
    expect(barLayout([{ label: 'a', value: 1 }], { width: 164, height: 50 }).bars[0]?.width).toBeCloseTo(80);
  });
});

describe('summarizeSeries', () => {
  it('summarises an empty series', () => {
    expect(summarizeSeries([])).toEqual({ count: 0, min: 0, max: 0, total: 0, minLabel: '', maxLabel: '' });
  });

  it('finds the first minimum and maximum and the total', () => {
    expect(
      summarizeSeries([
        { label: 'mon', value: 3 },
        { label: 'tue', value: 1 },
        { label: 'wed', value: 7 },
        { label: 'thu', value: 1 },
        { label: 'fri', value: -2 },
      ]),
    ).toEqual({ count: 5, min: 0, max: 7, total: 12, minLabel: 'fri', maxLabel: 'wed' });
  });
});

describe('chartSummaryText', () => {
  const fmt = (n: number): string => `${n}u`;

  it('states the empty series', () => {
    expect(chartSummaryText('Daily', [], fmt, fakeT)).toBe('Daily. adminComponents.chart.empty');
  });

  it('summarises with formatted values and labels', () => {
    const text = chartSummaryText(
      'Daily',
      [
        { label: 'a', value: 1 },
        { label: 'b', value: 4 },
      ],
      fmt,
      fakeT,
      (l) => l.toUpperCase(),
    );
    expect(text).toBe(
      'Daily. adminComponents.chart.summary {"count":2,"min":"1u","minLabel":"A","max":"4u","maxLabel":"B","total":"5u"}',
    );
    expect(chartSummaryText('D', [{ label: 'x', value: 2 }], fmt, fakeT)).toContain('"maxLabel":"x"');
  });

  it('has the summary messages in every language', () => {
    for (const bundle of [en, fr]) {
      expect(bundle.chart.summary.one).toContain('{max}');
      expect(bundle.chart.summary.other).toContain('{total}');
      expect(bundle.chart.empty).toBeTruthy();
    }
  });
});

describe('labelIndexes', () => {
  it('returns nothing for an empty series', () => {
    expect(labelIndexes(0, 5)).toEqual([]);
  });

  it('labels every bar when they fit', () => {
    expect(labelIndexes(3, 5)).toEqual([0, 1, 2]);
    expect(labelIndexes(2, 0)).toEqual([0, 1]);
  });

  it('labels one bar in every n, first and last included', () => {
    expect(labelIndexes(10, 4)).toEqual([0, 3, 6, 9]);
    expect(labelIndexes(30, 7)).toEqual([0, 5, 10, 15, 20, 25, 29]);
    expect(labelIndexes(5, 1)).toEqual([0, 4]);
  });

  it('drops a label too close to the last one', () => {
    expect(labelIndexes(14, 5)).toEqual([0, 4, 8, 13]);
  });
});
