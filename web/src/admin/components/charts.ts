// Logic of BarChart, kept out of the component so that it is unit tested in Node: the geometry
// of a vertical bar chart (bars, y-axis ticks) is computed here and applied by SVG attributes
// (x, y, width, height), never by inline styles (CSP style-src 'self').
import type { Translate } from '../../shared/i18n/messages';

/** Translation function (the t of the i18n module). */
export type { Translate };

/** One point of a series. */
export interface ChartPoint {
  label: string;
  value: number;
}

/** Dimensions of the chart, in SVG user units (the viewBox). */
export interface ChartDimensions {
  width: number;
  height: number;
  /** Space left of the plot for the y-axis labels (default 56). */
  left?: number;
  /** Space under the plot for the x-axis labels (default 24). */
  bottom?: number;
  /** Space above the plot (default 8). */
  top?: number;
  /** Space right of the plot (default 8). */
  right?: number;
  /** Fraction of each slot left empty between bars, from 0 to 0.9 (default 0.2). */
  gap?: number;
}

/** A computed bar. */
export interface ChartBar {
  x: number;
  y: number;
  width: number;
  height: number;
  /** Centre of the bar, for its x-axis label. */
  cx: number;
  label: string;
  value: number;
}

/** A tick of the y axis. */
export interface ChartTick {
  value: number;
  /** Vertical position of the tick. */
  y: number;
}

/** Computed layout of a chart. */
export interface ChartLayout {
  bars: ChartBar[];
  ticks: ChartTick[];
  /** Top of the y axis (a "nice" number, at least 1). */
  max: number;
  /** Plot area. */
  plot: { x: number; y: number; width: number; height: number };
}

/** Summary of a series, for the accessible name of the chart. */
export interface ChartSummary {
  count: number;
  min: number;
  max: number;
  total: number;
  /** Labels of the first minimum and maximum points (empty for an empty series). */
  minLabel: string;
  maxLabel: string;
}

/** Keeps finite, non-negative values; anything else counts as 0. */
function clean(value: number): number {
  return Number.isFinite(value) && value > 0 ? value : 0;
}

/**
 * Rounds n up to a "nice" number: 1, 2, 2.5, 5 or 10 times a power of ten (at least 1). A
 * value of 0 or less (or not finite) yields 1, so that an all-zero series keeps a usable axis.
 */
export function niceCeil(n: number): number {
  if (!Number.isFinite(n) || n <= 1) {
    return 1;
  }
  const power = 10 ** Math.floor(Math.log10(n));
  for (const step of [1, 2, 2.5, 5]) {
    const candidate = step * power;
    if (candidate >= n) {
      return candidate;
    }
  }
  // n < 10 * power by definition of power.
  return 10 * power;
}

/**
 * Computes the bars and the y-axis ticks (0, middle, max) of a vertical bar chart. Negative or
 * non-finite values are drawn as 0 (the bar keeps its original value for the table).
 */
export function barLayout(series: readonly ChartPoint[], dims: ChartDimensions): ChartLayout {
  const left = dims.left ?? 56;
  const bottom = dims.bottom ?? 24;
  const top = dims.top ?? 8;
  const right = dims.right ?? 8;
  const gap = Math.min(Math.max(dims.gap ?? 0.2, 0), 0.9);
  const plot = {
    x: left,
    y: top,
    width: Math.max(dims.width - left - right, 0),
    height: Math.max(dims.height - top - bottom, 0),
  };
  const max = niceCeil(Math.max(0, ...series.map((p) => clean(p.value))));
  const baseline = plot.y + plot.height;
  const slot = series.length === 0 ? 0 : plot.width / series.length;
  const barWidth = slot * (1 - gap);
  const bars = series.map((point, index) => {
    const value = clean(point.value);
    const height = (value / max) * plot.height;
    const x = plot.x + index * slot + (slot - barWidth) / 2;
    return {
      x,
      y: baseline - height,
      width: barWidth,
      height,
      cx: x + barWidth / 2,
      label: point.label,
      value: point.value,
    };
  });
  // The middle tick is drawn only when it is a whole number (counts never show "0.5").
  const values = Number.isInteger(max / 2) ? [0, max / 2, max] : [0, max];
  const ticks = values.map((value) => ({ value, y: baseline - (value / max) * plot.height }));
  return { bars, ticks, max, plot };
}

/** Summarises a series (count, minimum, maximum, total), for the accessible name of the chart. */
export function summarizeSeries(series: readonly ChartPoint[]): ChartSummary {
  const first = series[0];
  if (first === undefined) {
    return { count: 0, min: 0, max: 0, total: 0, minLabel: '', maxLabel: '' };
  }
  let min = first;
  let max = first;
  let total = 0;
  for (const point of series) {
    total += clean(point.value);
    if (clean(point.value) < clean(min.value)) {
      min = point;
    }
    if (clean(point.value) > clean(max.value)) {
      max = point;
    }
  }
  return {
    count: series.length,
    min: clean(min.value),
    max: clean(max.value),
    total,
    minLabel: min.label,
    maxLabel: max.label,
  };
}

/**
 * Accessible name of a chart: its title followed by the summary of the series ("Title. 7
 * values, from 0 (Mon) to 12 GiB (Fri), total 30 GiB."), or the empty notice.
 */
export function chartSummaryText(
  title: string,
  series: readonly ChartPoint[],
  formatValue: (n: number) => string,
  t: Translate,
  formatLabel: (label: string) => string = (label) => label,
): string {
  const s = summarizeSeries(series);
  if (s.count === 0) {
    return `${title}. ${t('adminComponents.chart.empty')}`;
  }
  return `${title}. ${t('adminComponents.chart.summary', {
    count: s.count,
    min: formatValue(s.min),
    minLabel: formatLabel(s.minLabel),
    max: formatValue(s.max),
    maxLabel: formatLabel(s.maxLabel),
    total: formatValue(s.total),
  })}`;
}

/**
 * Indexes of the bars whose x-axis label is drawn: all of them up to maxLabels, otherwise one in
 * every n (the first and the last included), so that labels do not overlap. The table view
 * always lists every point.
 */
export function labelIndexes(count: number, maxLabels: number): number[] {
  if (count <= 0) {
    return [];
  }
  const limit = Math.max(Math.floor(maxLabels), 2);
  if (count <= limit) {
    return Array.from({ length: count }, (_, i) => i);
  }
  const step = Math.ceil((count - 1) / (limit - 1));
  const out: number[] = [];
  let last = 0;
  for (let i = 0; i < count - 1; i += step) {
    out.push(i);
    last = i;
  }
  if (count - 1 - last < step / 2 && out.length > 1) {
    out.pop();
  }
  out.push(count - 1);
  return out;
}
