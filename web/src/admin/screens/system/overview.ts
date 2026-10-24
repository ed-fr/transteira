// Logic of the system overview (SystemOverview.svelte), reusable by the dashboard of the super
// admin: loading of GET /admin/system/stats, view of the data disk (usage, configured alert
// threshold, alert state, warning when the alert cannot be sent by mail) and rows of the tenant
// table (activity over the period, storage level). The period helpers of the tenant statistics
// (screens/ops/stats.ts) are reused: both endpoints accept the same periods.
import type { components } from '../../../shared/api/schema';
import type { ApiClient } from '../../../shared/api/client';
import type { Translate } from '../../../shared/i18n/messages';
import {
  quotaBadgeVariant,
  quotaLevel,
  quotaRatio,
  quotaTexts,
  type QuotaLevel,
} from '../../components/quota';
import { systemPath, tenantPath } from '../../shell';
import { DEFAULT_PERIOD, type StatsPeriod } from '../ops/stats';

/** Translation function (the t of the i18n module). */
export type { Translate };

/** Global statistics of the instance. */
export type GlobalStats = components['schemas']['GlobalStats'];
/** Usage of the data disk. */
export type DiskStats = GlobalStats['disk'];
/** A row of the global statistics (one active tenant). */
export type GlobalTenantStats = GlobalStats['tenants'][number];

/** Loads the global statistics (the API client is passed in, e.g. adminApi). */
export async function loadGlobalStats(
  api: Pick<ApiClient, 'get'>,
  period: StatsPeriod = DEFAULT_PERIOD,
): Promise<GlobalStats> {
  const res = await api.get('/admin/system/stats', { params: { period } });
  return res.data;
}

/** Path of the system settings, where the alert threshold and address are set. */
export const SETTINGS_PATH = systemPath('settings');
/** Path of the system overview. */
export const OVERVIEW_PATH = systemPath('overview');

/** Environment variables of the system SMTP server, named in the mail warning. */
export const SYSTEM_SMTP_VARIABLES = 'TT_SYSTEM_SMTP_HOST, TT_SYSTEM_SMTP_FROM';

/** What the disk section shows. */
export interface DiskView {
  /** Bytes used (meter value). */
  used: number;
  /** Size of the filesystem (meter maximum). */
  total: number;
  /** Configured alert threshold (ratio), the warning ratio of the meter (undefined if invalid). */
  threshold: number | undefined;
  /** "Alert threshold: 85 %". */
  thresholdLabel: string;
  /** The alert is raised. */
  alertActive: boolean;
  /** Badge of the alert state: error when raised, ok otherwise. */
  alertVariant: 'error' | 'ok';
  /** Text of the alert badge. */
  alertLabel: string;
  /** The alert is not sent by mail: the screen warns that it is only visible in the interface. */
  mailWarning: boolean;
}

function ratioOrZero(ratio: number): number {
  return Number.isFinite(ratio) && ratio > 0 ? ratio : 0;
}

function thresholdOrUndefined(ratio: number): number | undefined {
  return Number.isFinite(ratio) && ratio > 0 && ratio <= 1 ? ratio : undefined;
}

/**
 * View of the disk usage. The threshold is passed to QuotaMeter as its warning ratio (colour
 * of the meter); the screens hide the level badge of the meter and show the alert badge
 * instead, so that "OK" never sits next to "Alert active". formatPercent formats a ratio
 * (Intl percent style).
 */
export function diskView(disk: DiskStats, t: Translate, formatPercent: (ratio: number) => string): DiskView {
  return {
    used: disk.usedBytes,
    total: disk.totalBytes,
    threshold: thresholdOrUndefined(disk.alertThreshold),
    thresholdLabel: t('sysStats.disk.threshold', {
      percent: formatPercent(ratioOrZero(disk.alertThreshold)),
    }),
    alertActive: disk.alertActive,
    alertVariant: disk.alertActive ? 'error' : 'ok',
    alertLabel: t(disk.alertActive ? 'sysStats.disk.alertActive' : 'sysStats.disk.alertInactive'),
    mailWarning: !disk.alertMailConfigured,
  };
}

/** A row of the tenant table. */
export interface TenantStatsRow {
  id: string;
  name: string;
  /** Path of the general settings of the tenant. */
  path: string;
  /** Transfers over the period, formatted. */
  transfers: string;
  /** Volume uploaded over the period, formatted. */
  volume: string;
  /** "12 GiB of 100 GiB (12 %)", or the no-quota notice. */
  usage: string;
  level: QuotaLevel;
  levelVariant: 'ok' | 'warning' | 'error';
  levelLabel: string;
}

/** Formatters of the tenant rows. */
export interface RowFormatters {
  number: (n: number) => string;
  bytes: (n: number) => string;
  percent: (ratio: number) => string;
}

/** Row of a tenant, with its storage level (quota.ts). */
export function tenantStatsRow(row: GlobalTenantStats, fmt: RowFormatters, t: Translate): TenantStatsRow {
  const level = quotaLevel(quotaRatio(row.storageUsedBytes, row.storageQuotaBytes));
  const texts = quotaTexts(row.storageUsedBytes, row.storageQuotaBytes, fmt.bytes, fmt.percent, t);
  return {
    id: row.tenantId,
    name: row.name,
    path: tenantPath(row.tenantId, 'general'),
    transfers: fmt.number(row.transferCount),
    volume: fmt.bytes(row.bytesUploaded),
    usage: texts.usage,
    level,
    levelVariant: quotaBadgeVariant(level),
    levelLabel: texts.level,
  };
}

/** Rows of the tenant table, in the order of the API. */
export function tenantStatsRows(stats: GlobalStats, fmt: RowFormatters, t: Translate): TenantStatsRow[] {
  return stats.tenants.map((row) => tenantStatsRow(row, fmt, t));
}
