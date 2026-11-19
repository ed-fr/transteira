// Logic of the statistics screen of a tenant (TenantStats.svelte), reusable by the dashboard:
// period read from and written to the URL, loading of GET /admin/tenants/{tenantId}/stats, the
// key figure cards and the chart series (one point per UTC day for 7d and 30d, per calendar
// month for 12m, labelled for the language of the interface).
import { tenantStatsPeriodValues, type components } from '../../../shared/api/schema';
import type { ApiClient } from '../../../shared/api/client';
import type { ChartPoint } from '../../components/charts';
import type { Translate } from '../../../shared/i18n/messages';
import { trend, trendText } from '../../components/trend';

/** Translation function (the t of the i18n module). */
export type { Translate };

/** Statistics of a tenant over a period. */
export type TenantStats = components['schemas']['TenantStats'];
/** Period of the statistics. */
export type StatsPeriod = TenantStats['period'];
/** Metric of a chart series. */
export type SeriesMetric = 'transfers' | 'bytesUploaded';
/** Number of days of the periods that have a previous period (none for 12 months). */
const PERIOD_DAYS: Partial<Record<StatsPeriod, number>> = { '7d': 7, '30d': 30 };

/**
 * Neutral trend texts of the key figure cards against the previous period ("+18 % vs the previous
 * 30 days"), by card id. Empty for 12 months (no previous period) and for a figure the server does
 * not report; a card absent from the result shows no trend.
 */
export function cardTrends(
  stats: TenantStats,
  t: Translate,
  formatPercent: (ratio: number) => string,
): Partial<Record<StatCardView['id'], string>> {
  const days = PERIOD_DAYS[stats.period];
  const previous = stats.previous;
  if (days === undefined || previous === undefined) {
    return {};
  }
  const current: Record<StatCardView['id'], number | undefined> = {
    transfers: stats.transferCount,
    bytesUploaded: stats.bytesUploaded,
    downloads: stats.downloadCount,
    bytesDownloaded: stats.bytesDownloaded,
    secretsCreated: stats.secretsCreated,
    virusDetections: stats.virusDetections,
  };
  const before: Record<StatCardView['id'], number> = {
    transfers: previous.transferCount,
    bytesUploaded: previous.bytesUploaded,
    downloads: previous.downloadCount,
    bytesDownloaded: previous.bytesDownloaded,
    secretsCreated: previous.secretsCreated,
    virusDetections: previous.virusDetections,
  };
  const texts: Partial<Record<StatCardView['id'], string>> = {};
  for (const id of Object.keys(current) as StatCardView['id'][]) {
    const now = current[id];
    const text = now === undefined ? undefined : trendText(trend(now, before[id]), days, t, formatPercent);
    if (text !== undefined) {
      texts[id] = text;
    }
  }
  return texts;
}

/** Granularity of the series of a period. */
export type SeriesGranularity = 'day' | 'month';

/** Periods, in display order. */
export const STATS_PERIODS: readonly StatsPeriod[] = tenantStatsPeriodValues;
/** Period used when the URL names none (or an invalid one); the API default too. */
export const DEFAULT_PERIOD: StatsPeriod = '30d';

/** Reports whether value is a period. */
export function isPeriod(value: string | null | undefined): value is StatsPeriod {
  return value !== null && value !== undefined && (STATS_PERIODS as readonly string[]).includes(value);
}

/** Period named by the query string (?period=7d); the default when absent or invalid. */
export function parsePeriod(query: URLSearchParams | string): StatsPeriod {
  const params = typeof query === 'string' ? new URLSearchParams(query) : query;
  const value = params.get('period');
  return isPeriod(value) ? value : DEFAULT_PERIOD;
}

/** Path of the screen for a period: the default period is left out of the URL. */
export function periodPath(path: string, period: StatsPeriod): string {
  return period === DEFAULT_PERIOD ? path : `${path}?period=${period}`;
}

/** Options of the period selector (radio buttons). */
export function periodOptions(t: Translate): { value: StatsPeriod; label: string }[] {
  return STATS_PERIODS.map((value) => ({ value, label: t(`opsStats.periods.${value}`) }));
}

/** Loads the statistics of a tenant (the API client is passed in, e.g. adminApi). */
export async function loadTenantStats(
  api: Pick<ApiClient, 'get'>,
  tenantId: string,
  period: StatsPeriod = DEFAULT_PERIOD,
): Promise<TenantStats> {
  const res = await api.get('/admin/tenants/{tenantId}/stats', { path: { tenantId }, params: { period } });
  return res.data;
}

/** Number and size formatters of the cards. */
export interface StatsFormatters {
  number: (n: number) => string;
  bytes: (n: number) => string;
}

/** A key figure card (StatCard props). */
export interface StatCardView {
  id: 'transfers' | 'bytesUploaded' | 'downloads' | 'bytesDownloaded' | 'secretsCreated' | 'virusDetections';
  label: string;
  value: string;
  variant: 'default' | 'warning';
}

/**
 * Key figure cards of the period: transfers, volume uploaded, downloads, volume downloaded and
 * virus detections (warning variant when at least one). The one-time secrets card (since 2.1)
 * comes before the virus card and is shown when the server reports it.
 */
export function statsCards(stats: TenantStats, fmt: StatsFormatters, t: Translate): StatCardView[] {
  const cards: StatCardView[] = [
    {
      id: 'transfers',
      label: t('opsStats.cards.transfers'),
      value: fmt.number(stats.transferCount),
      variant: 'default',
    },
    {
      id: 'bytesUploaded',
      label: t('opsStats.cards.bytesUploaded'),
      value: fmt.bytes(stats.bytesUploaded),
      variant: 'default',
    },
    {
      id: 'downloads',
      label: t('opsStats.cards.downloads'),
      value: fmt.number(stats.downloadCount),
      variant: 'default',
    },
    {
      id: 'bytesDownloaded',
      label: t('opsStats.cards.bytesDownloaded'),
      value: fmt.bytes(stats.bytesDownloaded),
      variant: 'default',
    },
    ...(stats.secretsCreated === undefined
      ? []
      : [
          {
            id: 'secretsCreated' as const,
            label: t('opsStats.cards.secretsCreated'),
            value: fmt.number(stats.secretsCreated),
            variant: 'default' as const,
          },
        ]),
    {
      id: 'virusDetections',
      label: t('opsStats.cards.virusDetections'),
      value: fmt.number(stats.virusDetections),
      variant: stats.virusDetections > 0 ? 'warning' : 'default',
    },
  ];
  return cards;
}

/** Granularity of the series of a period: months for 12m, days otherwise. */
export function granularity(period: string): SeriesGranularity {
  return period === '12m' ? 'month' : 'day';
}

const DATE = /^(\d{4})-(\d{2})-(\d{2})$/;

/**
 * Label of a series date (YYYY-MM-DD, a UTC day) in a language: "12 Oct" for a day, "Oct 2026"
 * for a month. A value that is not a date is returned as is.
 */
export function seriesLabel(date: string, unit: SeriesGranularity, locale: string): string {
  const m = DATE.exec(date);
  if (m === null) {
    return date;
  }
  const instant = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
  const options: Intl.DateTimeFormatOptions =
    unit === 'month'
      ? { timeZone: 'UTC', month: 'short', year: 'numeric' }
      : { timeZone: 'UTC', day: 'numeric', month: 'short' };
  try {
    return new Intl.DateTimeFormat(locale, options).format(instant);
  } catch {
    return new Intl.DateTimeFormat('en', options).format(instant);
  }
}

/** Chart points of a metric, oldest first, labelled for the language (see seriesLabel). */
export function seriesFor(stats: TenantStats, metric: SeriesMetric, locale: string): ChartPoint[] {
  const unit = granularity(stats.period);
  return stats.series.map((point) => ({
    label: seriesLabel(point.date, unit, locale),
    value: point[metric],
  }));
}

/** Titles of the two charts and the header of their label column, for the granularity. */
export function chartTexts(
  period: string,
  t: Translate,
): { transfersTitle: string; volumeTitle: string; labelHeader: string } {
  const unit = granularity(period);
  return {
    transfersTitle: t(`opsStats.charts.transfers.${unit}`),
    volumeTitle: t(`opsStats.charts.volume.${unit}`),
    labelHeader: t(`opsStats.charts.labelHeader.${unit}`),
  };
}
