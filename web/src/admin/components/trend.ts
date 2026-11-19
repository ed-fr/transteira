// Trend of a key figure against the previous period, for the KPI tiles (StatCard) of the home
// page and of the statistics (CLAUDE.md section 13.2; plan of step 3c, deviation 10): for example
// "+18 % vs the previous 30 days". The text is neutral (never green or red): a rise is neither good
// nor bad. Periods of 7 and 30 days have a previous period (TenantStats.previous,
// GlobalStats.tenants[].previous); 12 months has none (daily counters are purged after 13 months),
// so no trend is shown there.
import type { Translate } from '../../shared/i18n/messages';

/**
 * Direction of a trend: up or down by a rounded percentage, flat (rounded to 0 %), new (nothing in
 * the previous period, something now) or none (no previous period, or values not usable).
 */
export type TrendKind = 'up' | 'down' | 'flat' | 'new' | 'none';

/** A trend; percent (whole number, never negative) for up, down and flat. */
export interface Trend {
  kind: TrendKind;
  percent?: number;
}

/**
 * Trend of current against previous. previous undefined or null (no previous period), negative or
 * not finite values give "none"; previous 0 gives "new" when current is positive, "flat" when it
 * is 0 too; otherwise the variation rounded to a whole percentage ("flat" when it rounds to 0).
 */
export function trend(current: number, previous: number | null | undefined): Trend {
  if (
    previous === undefined ||
    previous === null ||
    !Number.isFinite(previous) ||
    !Number.isFinite(current) ||
    previous < 0 ||
    current < 0
  ) {
    return { kind: 'none' };
  }
  if (previous === 0) {
    return current > 0 ? { kind: 'new' } : { kind: 'flat', percent: 0 };
  }
  const percent = Math.round(((current - previous) / previous) * 100);
  if (percent === 0) {
    return { kind: 'flat', percent: 0 };
  }
  return percent > 0 ? { kind: 'up', percent } : { kind: 'down', percent: -percent };
}

/** Sums of named counters over rows of statistics, for the period and for the previous period. */
export interface PeriodSums<K extends string> {
  current: Record<K, number>;
  /**
   * Undefined unless there is at least one row and every row carries its previous period (never
   * for 12 months), so that a partial sum is never compared with a full one.
   */
  previous: Record<K, number> | undefined;
}

/** A counter usable in a sum: finite and positive, anything else counts as 0. */
function counter(n: number | undefined): number {
  return n !== undefined && Number.isFinite(n) && n > 0 ? n : 0;
}

/**
 * Sums the counters named by keys over rows of statistics (TenantStats, GlobalStats.tenants[]) and
 * over their previous periods (PeriodTotals), for the KPI tiles of the home page and of the system
 * overview. pick reads the counters of a row or of its previous period; missing, negative or not
 * finite counters count as 0.
 */
export function sumPeriods<K extends string, R extends { previous?: unknown }>(
  rows: readonly R[],
  keys: readonly K[],
  pick: (counters: R | NonNullable<R['previous']>) => Partial<Record<K, number | undefined>>,
): PeriodSums<K> {
  const sum = (list: readonly (R | NonNullable<R['previous']>)[]): Record<K, number> => {
    const out = Object.fromEntries(keys.map((key) => [key, 0])) as Record<K, number>;
    for (const item of list) {
      const counters = pick(item);
      for (const key of keys) {
        out[key] += counter(counters[key]);
      }
    }
    return out;
  };
  const previous = rows.flatMap((row) =>
    row.previous === undefined || row.previous === null ? [] : [row.previous as NonNullable<R['previous']>],
  );
  const complete = rows.length > 0 && previous.length === rows.length;
  return { current: sum(rows), previous: complete ? sum(previous) : undefined };
}

/**
 * Text of a trend over a period of days ("+18 % vs the previous 30 days", "No activity in the
 * previous 7 days"), undefined for "none" (show nothing). formatPercent formats a ratio as a
 * percentage in the current language (e.g. formatNumber(r, { style: 'percent' })).
 */
export function trendText(
  value: Trend,
  days: number,
  t: Translate,
  formatPercent: (ratio: number) => string,
): string | undefined {
  const percent = formatPercent((value.percent ?? 0) / 100);
  switch (value.kind) {
    case 'up':
      return t('adminComponents.trend.up', { percent, days });
    case 'down':
      return t('adminComponents.trend.down', { percent, days });
    case 'flat':
      return t('adminComponents.trend.flat', { days });
    case 'new':
      return t('adminComponents.trend.new', { days });
    default:
      return undefined;
  }
}
