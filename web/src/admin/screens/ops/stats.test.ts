import { describe, expect, it, vi } from 'vitest';
import type { ApiClient } from '../../../shared/api/client';
import {
  DEFAULT_PERIOD,
  STATS_PERIODS,
  chartTexts,
  granularity,
  isPeriod,
  loadTenantStats,
  parsePeriod,
  periodOptions,
  periodPath,
  seriesFor,
  seriesLabel,
  statsCards,
  type TenantStats,
  type Translate,
} from './stats';

const t: Translate = (key) => key;

function stats(overrides: Partial<TenantStats> = {}): TenantStats {
  return {
    period: '7d',
    transferCount: 12,
    bytesUploaded: 2048,
    downloadCount: 30,
    bytesDownloaded: 4096,
    virusDetections: 0,
    storageUsedBytes: 100,
    storageQuotaBytes: 1000,
    storageUsedRatio: 0.1,
    series: [
      { date: '2026-10-12', transfers: 2, bytesUploaded: 1024 },
      { date: '2026-10-13', transfers: 0, bytesUploaded: 0 },
    ],
    ...overrides,
  };
}

describe('period', () => {
  it('lists the periods of the specification', () => {
    expect(STATS_PERIODS).toEqual(['7d', '30d', '12m']);
    expect(DEFAULT_PERIOD).toBe('30d');
    expect(isPeriod('12m')).toBe(true);
    expect(isPeriod('1y')).toBe(false);
    expect(isPeriod(null)).toBe(false);
    expect(isPeriod(undefined)).toBe(false);
  });

  it('reads the period from the query string, ignoring invalid values', () => {
    expect(parsePeriod('?period=7d')).toBe('7d');
    expect(parsePeriod(new URLSearchParams('period=12m'))).toBe('12m');
    expect(parsePeriod('')).toBe('30d');
    expect(parsePeriod('?period=1y')).toBe('30d');
  });

  it('writes the period in the path, the default left out', () => {
    expect(periodPath('/tenants/t/stats', '7d')).toBe('/tenants/t/stats?period=7d');
    expect(periodPath('/tenants/t/stats', '30d')).toBe('/tenants/t/stats');
  });

  it('builds the selector options', () => {
    expect(periodOptions(t)).toEqual([
      { value: '7d', label: 'opsStats.periods.7d' },
      { value: '30d', label: 'opsStats.periods.30d' },
      { value: '12m', label: 'opsStats.periods.12m' },
    ]);
  });
});

describe('loadTenantStats', () => {
  it('calls the stats endpoint of the tenant with the period', async () => {
    const data = stats();
    const get = vi.fn().mockResolvedValue({ data });
    const api = { get } as unknown as Pick<ApiClient, 'get'>;
    await expect(loadTenantStats(api, 'ten_1', '12m')).resolves.toBe(data);
    expect(get).toHaveBeenCalledWith('/admin/tenants/{tenantId}/stats', {
      path: { tenantId: 'ten_1' },
      params: { period: '12m' },
    });
    await loadTenantStats(api, 'ten_1');
    expect(get).toHaveBeenLastCalledWith('/admin/tenants/{tenantId}/stats', {
      path: { tenantId: 'ten_1' },
      params: { period: '30d' },
    });
  });
});

describe('statsCards', () => {
  const fmt = { number: (n: number) => `#${n}`, bytes: (n: number) => `${n} B` };

  it('maps the figures of the period', () => {
    expect(statsCards(stats(), fmt, t)).toEqual([
      { id: 'transfers', label: 'opsStats.cards.transfers', value: '#12', variant: 'default' },
      { id: 'bytesUploaded', label: 'opsStats.cards.bytesUploaded', value: '2048 B', variant: 'default' },
      { id: 'downloads', label: 'opsStats.cards.downloads', value: '#30', variant: 'default' },
      { id: 'bytesDownloaded', label: 'opsStats.cards.bytesDownloaded', value: '4096 B', variant: 'default' },
      { id: 'virusDetections', label: 'opsStats.cards.virusDetections', value: '#0', variant: 'default' },
    ]);
  });

  it('warns when viruses were detected', () => {
    const card = statsCards(stats({ virusDetections: 2 }), fmt, t).at(-1);
    expect(card).toMatchObject({ value: '#2', variant: 'warning' });
  });
});

describe('series', () => {
  it('uses days for 7d and 30d, months for 12m', () => {
    expect(granularity('7d')).toBe('day');
    expect(granularity('30d')).toBe('day');
    expect(granularity('12m')).toBe('month');
  });

  it('labels days and months for the language, in UTC', () => {
    expect(seriesLabel('2026-10-12', 'day', 'en-GB')).toBe('12 Oct');
    expect(seriesLabel('2026-10-01', 'month', 'en')).toBe('Oct 2026');
    expect(seriesLabel('2026-10-12', 'day', 'fr')).toMatch(/^12 oct/);
    expect(seriesLabel('2026-10-01', 'month', 'fr')).toMatch(/^oct.* 2026$/);
    expect(seriesLabel('not a date', 'day', 'en')).toBe('not a date');
  });

  it('falls back to English for an invalid language tag', () => {
    expect(seriesLabel('2026-10-01', 'month', '!!')).toBe('Oct 2026');
  });

  it('maps the daily points of a metric, oldest first', () => {
    expect(seriesFor(stats(), 'transfers', 'en-GB')).toEqual([
      { label: '12 Oct', value: 2 },
      { label: '13 Oct', value: 0 },
    ]);
    expect(seriesFor(stats(), 'bytesUploaded', 'en-GB').map((p) => p.value)).toEqual([1024, 0]);
  });

  it('maps the monthly points of 12m', () => {
    const monthly = stats({
      period: '12m',
      series: [
        { date: '2026-09-01', transfers: 5, bytesUploaded: 10 },
        { date: '2026-10-01', transfers: 7, bytesUploaded: 20 },
      ],
    });
    expect(seriesFor(monthly, 'transfers', 'en')).toEqual([
      { label: 'Sep 2026', value: 5 },
      { label: 'Oct 2026', value: 7 },
    ]);
  });

  it('gives the chart titles of the granularity', () => {
    expect(chartTexts('30d', t)).toEqual({
      transfersTitle: 'opsStats.charts.transfers.day',
      volumeTitle: 'opsStats.charts.volume.day',
      labelHeader: 'opsStats.charts.labelHeader.day',
    });
    expect(chartTexts('12m', t).transfersTitle).toBe('opsStats.charts.transfers.month');
  });
});
