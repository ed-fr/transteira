import { describe, expect, it, vi } from 'vitest';
import {
  OVERVIEW_PATH,
  SETTINGS_PATH,
  SYSTEM_SMTP_VARIABLES,
  diskView,
  loadGlobalStats,
  overviewTotals,
  trendDays,
  tenantStatsRow,
  tenantStatsRows,
  type DiskStats,
  type GlobalStats,
} from './overview';

const t = (key: string, params?: Record<string, string | number>): string =>
  params === undefined ? key : `${key} ${JSON.stringify(params)}`;
const GiB = 2 ** 30;
const percent = (r: number): string => `${Math.round(r * 100)} %`;
const fmt = { number: (n: number) => `#${n}`, bytes: (n: number) => `${n / GiB} GiB`, percent };

const disk: DiskStats = {
  totalBytes: 1000 * GiB,
  usedBytes: 720 * GiB,
  usedRatio: 0.72,
  alertThreshold: 0.85,
  alertActive: false,
  alertMailConfigured: true,
};

const stats: GlobalStats = {
  period: '7d',
  disk,
  tenants: [
    {
      tenantId: 'ten_B',
      name: 'Entity B',
      transferCount: 4,
      bytesUploaded: 2 * GiB,
      storageUsedBytes: 90 * GiB,
      storageQuotaBytes: 100 * GiB,
      storageUsedRatio: 0.9,
    },
    {
      tenantId: 'ten_A',
      name: 'Entity A',
      transferCount: 0,
      bytesUploaded: 0,
      storageUsedBytes: 0,
      storageQuotaBytes: 0,
      storageUsedRatio: 0,
    },
  ],
};

describe('loadGlobalStats', () => {
  it('requests the period and returns the data', async () => {
    const get = vi.fn().mockResolvedValue({ data: stats });
    await expect(loadGlobalStats({ get } as never, '7d')).resolves.toBe(stats);
    expect(get).toHaveBeenCalledWith('/admin/system/stats', { params: { period: '7d' } });
  });

  it('defaults to 30 days', async () => {
    const get = vi.fn().mockResolvedValue({ data: stats });
    await loadGlobalStats({ get } as never);
    expect(get).toHaveBeenCalledWith('/admin/system/stats', { params: { period: '30d' } });
  });
});

describe('paths and constants', () => {
  it('point to the system screens and name the SMTP variables', () => {
    expect(SETTINGS_PATH).toBe('/system/settings');
    expect(OVERVIEW_PATH).toBe('/system');
    expect(SYSTEM_SMTP_VARIABLES).toContain('TT_SYSTEM_SMTP_HOST');
  });
});

describe('diskView', () => {
  it('formats the usage and the configured threshold', () => {
    const view = diskView(disk, t, percent);
    expect(view).toEqual({
      used: 720 * GiB,
      total: 1000 * GiB,
      threshold: 0.85,
      thresholdLabel: 'sysStats.disk.threshold {"percent":"85 %"}',
      alertActive: false,
      alertVariant: 'ok',
      alertLabel: 'sysStats.disk.alertInactive',
      mailWarning: false,
    });
  });

  it('shows a raised alert as an error badge', () => {
    const view = diskView({ ...disk, alertActive: true, usedRatio: 0.9 }, t, percent);
    expect(view.alertActive).toBe(true);
    expect(view.alertVariant).toBe('error');
    expect(view.alertLabel).toBe('sysStats.disk.alertActive');
  });

  it('warns when the alert is not sent by mail', () => {
    expect(diskView({ ...disk, alertMailConfigured: false }, t, percent).mailWarning).toBe(true);
  });

  it('never formats a negative or invalid ratio', () => {
    const view = diskView({ ...disk, usedRatio: -1, alertThreshold: Number.NaN }, t, percent);
    expect(view.thresholdLabel).toBe('sysStats.disk.threshold {"percent":"0 %"}');
    expect(view.threshold).toBeUndefined();
    expect(diskView({ ...disk, alertThreshold: 1.5 }, t, percent).threshold).toBeUndefined();
  });
});

describe('tenant rows', () => {
  it('maps a row with its activity and storage level', () => {
    const [b] = stats.tenants;
    expect(tenantStatsRow(b!, fmt, t)).toEqual({
      id: 'ten_B',
      name: 'Entity B',
      path: '/tenants/ten_B/general',
      transfers: '#4',
      volume: '2 GiB',
      viruses: '#0',
      downloads: '#0',
      used: 90 * GiB,
      quota: 100 * GiB,
      usage: 'adminComponents.quota.usage {"used":"90 GiB","quota":"100 GiB","percent":"90 %"}',
      level: 'warning',
      levelVariant: 'warning',
      levelLabel: 'adminComponents.quota.level.warning',
    });
  });

  it('keeps the order of the API and handles a tenant without quota', () => {
    const rows = tenantStatsRows(stats, fmt, t);
    expect(rows.map((r) => r.id)).toEqual(['ten_B', 'ten_A']);
    expect(rows[1]).toMatchObject({
      used: 0,
      quota: 0,
      level: 'ok',
      levelVariant: 'ok',
      usage: 'adminComponents.quota.noQuota {"used":"0 GiB"}',
    });
  });

  it('shows a full quota as an error badge', () => {
    const row = tenantStatsRow(
      { ...stats.tenants[0]!, storageUsedBytes: 120 * GiB, storageUsedRatio: 1.2 },
      fmt,
      t,
    );
    expect(row.level).toBe('full');
    expect(row.levelVariant).toBe('error');
  });
});

describe('overviewTotals', () => {
  const row = (n: number, previous?: boolean) => ({
    ...stats.tenants[0]!,
    transferCount: n,
    bytesUploaded: n * 10,
    virusDetections: n,
    downloadCount: n * 2,
    ...(previous
      ? {
          previous: {
            transferCount: 1,
            bytesUploaded: 2,
            downloadCount: 3,
            bytesDownloaded: 0,
            virusDetections: 4,
            secretsCreated: 0,
          },
        }
      : {}),
  });

  it('sums the counters and the previous period when every row has one', () => {
    const totals = overviewTotals({ ...stats, tenants: [row(1, true), row(2, true)] });
    expect(totals.current).toEqual({ transfers: 3, bytes: 30, viruses: 3, downloads: 6 });
    expect(totals.previous).toEqual({ transfers: 2, bytes: 4, viruses: 8, downloads: 6 });
  });

  it('has no previous period when a row lacks it, or without rows, and tolerates missing counters', () => {
    expect(overviewTotals({ ...stats, tenants: [row(1, true), row(2)] }).previous).toBeUndefined();
    expect(overviewTotals({ ...stats, tenants: [] })).toEqual({
      current: { transfers: 0, bytes: 0, viruses: 0, downloads: 0 },
      previous: undefined,
    });
    expect(overviewTotals(stats).current.viruses).toBe(0);
  });
});

describe('trendDays', () => {
  it('gives the length of the periods that have a previous one', () => {
    expect(trendDays('7d')).toBe(7);
    expect(trendDays('30d')).toBe(30);
    expect(trendDays('12m')).toBeUndefined();
  });
});
