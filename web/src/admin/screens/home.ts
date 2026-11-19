// Logic of the administration home (dashboard; CLAUDE.md sections 13.2 and 21.2), kept out of the
// component so that it is unit tested in Node:
// - kind of dashboard per role and greeting of the page header;
// - key figures over the last 30 days (KPI tiles): for the super admin, the sum of the rows of
//   ONE global statistics call (transfers, volume, viruses, each with its trend against the
//   previous 30 days) and the disk tile (usage, alert threshold marker, free space); for the other
//   roles, the sum of the statistics of their tenants, loaded with a bounded concurrency, and a
//   storage tile (their quotas summed) instead of the disk;
// - rows of the entity table (colour swatch, name and domain, status, storage), at most
//   HOME_TENANT_ROWS, and the quick links of the delegated admins and auditors.
// Trends are neutral texts (trend.ts, plan deviation 10).
import type { components } from '../../shared/api/schema';
import type { AdminMe } from '../auth/machine';
import { gaugeLevel, type GaugeLevel } from '../components/gauge';
import {
  QUOTA_WARNING_RATIO,
  quotaBadgeVariant,
  quotaGaugeLevel,
  quotaLevel,
  quotaRatio,
  quotaTexts,
  type QuotaLevel,
} from '../components/quota';
import { sumPeriods, trend, trendText } from '../components/trend';
import { tenantPath, type TenantSection } from '../shell';
import type { DiskStats, GlobalStats } from './system/overview';
import { statusView } from './tenants/tenants';
import type { Translate } from '../../shared/i18n/messages';

/** Translation function (the t of the i18n module). */
export type { Translate };

/** Statistics of a tenant, as returned by the API. */
export type TenantStats = components['schemas']['TenantStats'];
/** A tenant, as returned by the API. */
export type Tenant = components['schemas']['Tenant'];
/** A tenant the admin is attached to (AdminMe.tenants). */
export type TenantRef = AdminMe['tenants'][number];

/** Period of the statistics of the dashboard. */
export const DASHBOARD_PERIOD = '30d' as const;

/** Length of the period in days, for the trend texts ("vs the previous 30 days"). */
export const TREND_DAYS = 30;

/** Maximum number of statistics requests in flight at once. */
export const STATS_CONCURRENCY = 4;

/** Rows of the entity table of the home ("See all" opens the full list). */
export const HOME_TENANT_ROWS = 10;

/** Formatters of the dashboard, in the current language. */
export interface HomeFormatters {
  /** A count ("1,234"). */
  number: (n: number) => string;
  /** A size ("3 GiB"). */
  bytes: (n: number) => string;
  /** A ratio as a percentage with one decimal at most ("47.5 %"). */
  percent: (ratio: number) => string;
  /** A ratio as a whole percentage, for the trends ("18 %"). */
  trendPercent: (ratio: number) => string;
}

// ---- Concurrency -----------------------------------------------------------------------------

/**
 * Runs fn on every item with at most limit calls in flight, and returns their settled results in
 * the order of the items. A failure of one item never stops the others (it is returned as a
 * rejected result). A limit below 1 counts as 1.
 */
export async function mapLimit<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<PromiseSettledResult<R>[]> {
  const results: PromiseSettledResult<R>[] = new Array<PromiseSettledResult<R>>(items.length);
  let next = 0;
  async function worker(): Promise<void> {
    while (next < items.length) {
      const index = next++;
      try {
        results[index] = { status: 'fulfilled', value: await fn(items[index] as T, index) };
      } catch (reason) {
        results[index] = { status: 'rejected', reason };
      }
    }
  }
  const workers = Math.min(Math.max(1, Math.floor(limit) || 1), items.length);
  await Promise.all(Array.from({ length: workers }, () => worker()));
  return results;
}

// ---- Kind and greeting -----------------------------------------------------------------------

/**
 * Content of the dashboard: instance figures, disk, entities and system status (super), figures,
 * storage, entities and quick links of the tenants of the admin (delegated: configuration links;
 * auditor: consultation links only), nothing.
 */
export type DashboardKind = 'super' | 'delegated' | 'auditor' | 'none';

/** Kind of dashboard of an admin. */
export function dashboardKind(me: AdminMe | undefined): DashboardKind {
  if (me === undefined) {
    return 'none';
  }
  if (me.role === 'super_admin') {
    return 'super';
  }
  return me.role === 'auditor' ? 'auditor' : 'delegated';
}

/**
 * Description of the page header (the h1 stays "Home", plan deviation 1): "Hello, superadmin ·
 * Instance overview · 2 entities" for the super admin, the count being the tenants of the profile
 * (every tenant of the instance for a super admin, whatever its status: the same count as the
 * Entities card and the sidebar, known as soon as the profile is), the overview of the entity or
 * of the N entities of a delegated admin or an auditor (read-only for the auditor), "Hello, name"
 * alone without entity.
 */
export function greeting(
  me: Pick<AdminMe, 'username' | 'tenants'>,
  kind: DashboardKind,
  t: Translate,
): string {
  const username = me.username;
  if (kind === 'super') {
    return t('adminHome.greeting.superCount', { username, count: me.tenants.length });
  }
  const only = me.tenants.length === 1 ? me.tenants[0] : undefined;
  if (kind === 'none' || me.tenants.length === 0) {
    return t('adminHome.greeting.plain', { username });
  }
  const prefix = kind === 'auditor' ? 'adminHome.greeting.auditor' : 'adminHome.greeting.delegated';
  return only !== undefined
    ? t(`${prefix}One`, { username, name: only.name })
    : t(`${prefix}Many`, { username, count: me.tenants.length });
}

// ---- Generations of the loads -------------------------------------------------------------------

/**
 * Generations of the loads of a screen. The home reloads its blocks when the profile changes (a
 * tenant added or removed): each reload starts a new generation, and an answer of a previous one
 * (slower than the new one) is ignored, so that it never overwrites newer data. Once the screen is
 * gone (stop), every answer is ignored.
 */
export interface LoadGenerations {
  /** Starts a new generation and returns it. */
  next(): number;
  /** The generation running now. */
  current(): number;
  /** An answer of generation gen may still be shown (current generation, screen not stopped). */
  isCurrent(gen: number): boolean;
  /** The screen is gone: every answer is ignored from now on. */
  stop(): void;
}

/** New generations, starting at 0. */
export function createLoadGenerations(): LoadGenerations {
  let generation = 0;
  let stopped = false;
  return {
    next: () => ++generation,
    current: () => generation,
    isCurrent: (gen) => !stopped && gen === generation,
    stop: () => {
      stopped = true;
    },
  };
}

// ---- Statistics of the tenants of a delegated admin or an auditor ------------------------------

/** Loading state of the statistics of one tenant. */
export type TenantCard =
  | { id: string; name: string; state: 'loading' }
  | { id: string; name: string; state: 'ready'; stats: TenantStats }
  | { id: string; name: string; state: 'error'; message: string };

/** States of the tenants of an admin, all loading, in the order of the profile. */
export function initialCards(tenants: readonly TenantRef[]): TenantCard[] {
  return tenants.map((ref) => ({ id: ref.id, name: ref.name, state: 'loading' }));
}

/** Replaces the state of tenant id by its loaded statistics. */
export function withStats(cards: readonly TenantCard[], id: string, stats: TenantStats): TenantCard[] {
  return cards.map((c) => (c.id === id ? { id: c.id, name: c.name, state: 'ready', stats } : c));
}

/** Puts the state of tenant id back to loading (retry). */
export function withLoading(cards: readonly TenantCard[], id: string): TenantCard[] {
  return cards.map((c) => (c.id === id ? { id: c.id, name: c.name, state: 'loading' } : c));
}

/** Replaces the state of tenant id by an error message. */
export function withError(cards: readonly TenantCard[], id: string, message: string): TenantCard[] {
  return cards.map((c) => (c.id === id ? { id: c.id, name: c.name, state: 'error', message } : c));
}

/**
 * State of the tile group of a delegated admin or an auditor: the tiles sum every tenant, so they
 * show only once every tenant is loaded; any failure gives ONE error (the names of the failed
 * tenants and the first message) with a single "Try again", which reloads the failed tenants.
 */
export type TenantTilesState =
  | { state: 'loading' }
  | { state: 'ready'; stats: TenantStats[] }
  | { state: 'error'; failed: string[]; names: string; message: string };

/** State of the tile group from the state of each tenant. */
export function tenantTilesState(cards: readonly TenantCard[]): TenantTilesState {
  const failed = cards.filter((c): c is Extract<TenantCard, { state: 'error' }> => c.state === 'error');
  const first = failed[0];
  if (first !== undefined) {
    return {
      state: 'error',
      failed: failed.map((c) => c.id),
      names: failed.map((c) => c.name).join(', '),
      message: first.message,
    };
  }
  const ready: TenantStats[] = [];
  for (const card of cards) {
    if (card.state !== 'ready') {
      return { state: 'loading' };
    }
    ready.push(card.stats);
  }
  return { state: 'ready', stats: ready };
}

// ---- Key figures -----------------------------------------------------------------------------

/** Counters summed into the key figure tiles. */
export interface FigureTotals {
  transferCount: number;
  bytesUploaded: number;
  virusDetections: number;
}

/** Key figures of the period, and of the previous period when known (7 and 30 days only). */
export interface PeriodFigures {
  current: FigureTotals;
  /**
   * Undefined unless every row carries its previous period (never for 12 months, nor without any
   * row), so that a partial sum is never compared with a full one.
   */
  previous: FigureTotals | undefined;
}

const FIGURE_KEYS = [
  'transferCount',
  'bytesUploaded',
  'virusDetections',
] as const satisfies readonly (keyof FigureTotals)[];

/** A counter or byte size usable in a sum: finite and positive, anything else counts as 0. */
function count(n: number | undefined): number {
  return n !== undefined && Number.isFinite(n) && n > 0 ? n : 0;
}

type Counters = { transferCount: number; bytesUploaded: number; virusDetections?: number | undefined };

function periodFigures(rows: readonly (Counters & { previous?: Counters | undefined })[]): PeriodFigures {
  return sumPeriods(rows, FIGURE_KEYS, (row) => row);
}

/**
 * Key figures of the instance: the sum of the rows of the global statistics (one per active
 * tenant), with the previous period when every row carries it (sumPeriods, shared with the
 * system overview).
 */
export function globalFigures(stats: Pick<GlobalStats, 'tenants'>): PeriodFigures {
  return periodFigures(stats.tenants);
}

/** Key figures of the tenants of an admin: the sum of their statistics (same rule). */
export function tenantFigures(list: readonly TenantStats[]): PeriodFigures {
  return periodFigures(list);
}

/** A key figure tile: label, value and neutral trend text. */
export interface FigureTile {
  id: 'transfers' | 'volume' | 'viruses';
  label: string;
  value: string;
  /** "+18 % vs the previous 30 days"; undefined without previous period. */
  trend: string | undefined;
}

/** The three key figure tiles: transfers, volume exchanged, viruses blocked. */
export function figureTiles(figures: PeriodFigures, t: Translate, fmt: HomeFormatters): FigureTile[] {
  const { current, previous } = figures;
  const trendOf = (key: keyof FigureTotals): string | undefined =>
    trendText(trend(current[key], previous?.[key]), TREND_DAYS, t, fmt.trendPercent);
  return [
    {
      id: 'transfers',
      label: t('adminHome.tiles.transfers'),
      value: fmt.number(current.transferCount),
      trend: trendOf('transferCount'),
    },
    {
      id: 'volume',
      label: t('adminHome.tiles.volume'),
      value: fmt.bytes(current.bytesUploaded),
      trend: trendOf('bytesUploaded'),
    },
    {
      id: 'viruses',
      label: t('adminHome.tiles.viruses'),
      value: fmt.number(current.virusDetections),
      trend: trendOf('virusDetections'),
    },
  ];
}

// ---- Disk tile (super admin) and storage tile (other roles) ----------------------------------

/** Gauge of a tile (Gauge.svelte), in bytes. */
export interface TileGauge {
  value: number;
  max: number;
  /** Alert threshold marked on the track, in bytes; undefined without a valid threshold. */
  threshold: number | undefined;
  level: GaugeLevel;
  /** aria-valuetext of the meter. */
  valueText: string;
  /** Accessible name of the meter. */
  label: string;
}

/** A tile with a gauge: the disk of the instance, or the storage of the tenants of an admin. */
export interface GaugeTile {
  label: string;
  /** The usage as a percentage, or the bytes used without quota. */
  value: string;
  /** Undefined when there is nothing to measure against (no quota, empty disk). */
  gauge: TileGauge | undefined;
  /** Visible line under the gauge; it says the threshold the marker shows. */
  text: string;
  /** Emphasis of the tile: danger while the disk alert is raised or a quota is full. */
  variant: 'default' | 'warning' | 'danger';
  /** Extra information (alert raised, alert not sent by mail). */
  hint: string | undefined;
}

function validRatio(ratio: number): number | undefined {
  return Number.isFinite(ratio) && ratio > 0 && ratio <= 1 ? ratio : undefined;
}

/**
 * Disk tile of the super admin: usage percentage, gauge with the marker of the configured alert
 * threshold, "Alert at 85 % · 940 GiB free", and a hint when the alert is raised or not sent by
 * mail. The tile is in the danger variant while the alert is raised.
 */
export function diskTile(disk: DiskStats, t: Translate, fmt: HomeFormatters): GaugeTile {
  const total = count(disk.totalBytes);
  const used = Math.min(count(disk.usedBytes), total);
  const ratio = total > 0 ? used / total : 0;
  const thresholdRatio = validRatio(disk.alertThreshold);
  const threshold = thresholdRatio === undefined ? undefined : thresholdRatio * total;
  const free = fmt.bytes(Math.max(0, total - used));
  const percent = fmt.percent(ratio);
  const hints = [
    disk.alertActive ? t('adminHome.tiles.diskAlertActive') : undefined,
    disk.alertMailConfigured ? undefined : t('adminHome.tiles.diskMailOff'),
  ].filter((h): h is string => h !== undefined);
  const level = gaugeLevel(used, total, threshold);
  return {
    label: t('adminHome.tiles.disk'),
    value: percent,
    gauge:
      total > 0
        ? {
            value: used,
            max: total,
            threshold,
            level: disk.alertActive && level === 'default' ? 'warning' : level,
            valueText: t('adminHome.tiles.diskValueText', {
              percent,
              used: fmt.bytes(used),
              total: fmt.bytes(total),
            }),
            label: t('sysStats.disk.label'),
          }
        : undefined,
    text:
      thresholdRatio === undefined
        ? t('adminHome.tiles.diskFree', { free })
        : t('adminHome.tiles.diskText', { threshold: fmt.percent(thresholdRatio), free }),
    variant: disk.alertActive ? 'danger' : 'default',
    hint: hints.length === 0 ? undefined : hints.join(' '),
  };
}

/**
 * Storage tile of a delegated admin or an auditor: the storage used by their tenants against the
 * sum of their quotas, the gauge marking the preventive alert at 80 % (CLAUDE.md section 8.5).
 * Without any quota, the bytes used alone.
 */
export function storageTile(
  list: readonly Pick<TenantStats, 'storageUsedBytes' | 'storageQuotaBytes'>[],
  t: Translate,
  fmt: HomeFormatters,
): GaugeTile {
  const used = list.reduce((sum, s) => sum + count(s.storageUsedBytes), 0);
  const quota = list.reduce((sum, s) => sum + count(s.storageQuotaBytes), 0);
  const label = t('adminHome.tiles.storage');
  if (quota <= 0) {
    return {
      label,
      value: fmt.bytes(used),
      gauge: undefined,
      text: t('adminComponents.quota.noQuota', { used: fmt.bytes(used) }),
      variant: 'default',
      hint: undefined,
    };
  }
  const ratio = quotaRatio(used, quota);
  const level: QuotaLevel = quotaLevel(ratio);
  const texts = quotaTexts(used, quota, fmt.bytes, fmt.percent, t);
  return {
    label,
    value: fmt.percent(ratio),
    gauge: {
      value: Math.min(used, quota),
      max: quota,
      threshold: QUOTA_WARNING_RATIO * quota,
      level: quotaGaugeLevel(level),
      valueText: texts.usage,
      label,
    },
    text: t('adminHome.tiles.storageText', {
      used: fmt.bytes(used),
      quota: fmt.bytes(quota),
      threshold: fmt.percent(QUOTA_WARNING_RATIO),
    }),
    variant: level === 'full' ? 'danger' : level === 'warning' ? 'warning' : 'default',
    hint: level === 'ok' ? undefined : texts.level,
  };
}

// ---- Quick links (delegated admin, auditor) ----------------------------------------------------

/** A quick link to a section of a tenant. */
export interface QuickLink {
  section: TenantSection;
  path: string;
  label: string;
}

/** Sections reachable from the quick links of a delegated admin. */
export const QUICK_SECTIONS = ['transfers', 'audit', 'stats'] as const satisfies readonly TenantSection[];

/** Sections reachable from the quick links of an auditor (the read-only sections of a tenant). */
export const AUDITOR_QUICK_SECTIONS = [
  'transfers',
  'audit',
  'security',
  'stats',
] as const satisfies readonly TenantSection[];

/**
 * Quick links of a tenant (the tenant name is in the label, for unambiguous link texts). An
 * auditor also gets the security log; it has no link to a section it cannot open.
 */
export function quickLinks(
  tenant: { id: string; name: string },
  t: Translate,
  kind: DashboardKind = 'delegated',
): QuickLink[] {
  const sections: readonly TenantSection[] = kind === 'auditor' ? AUDITOR_QUICK_SECTIONS : QUICK_SECTIONS;
  return sections.map((section) => ({
    section,
    path: tenantPath(tenant.id, section),
    label: t(`adminHome.links.${section}`, { name: tenant.name }),
  }));
}

// ---- Entity table ----------------------------------------------------------------------------

/** A row of the entity table of the home. */
export interface TenantRow {
  id: string;
  name: string;
  fqdn: string;
  /** Primary colour of the tenant, for the decorative swatch (validated again by TenantSwatch). */
  color: string | undefined;
  /** Path of the general settings of the tenant ("Summary" for an auditor). */
  path: string;
  statusVariant: 'ok' | 'warning';
  statusKey: string;
  /** Bytes used and storage quota (QuotaMeter). */
  used: number;
  quota: number;
  /** "12 GiB of 100 GiB (12 %)", or the no-quota notice. */
  usage: string;
  level: QuotaLevel;
  levelVariant: 'ok' | 'warning' | 'error';
  levelLabel: string;
}

/** Row of a tenant in the entity table, with its storage level. */
export function tenantRow(
  tenant: Tenant,
  t: Translate,
  formatBytes: (n: number) => string,
  formatPercent: (ratio: number) => string,
): TenantRow {
  const status = statusView(tenant.status, tenant.setupState);
  const level = quotaLevel(quotaRatio(tenant.storageUsedBytes, tenant.storageQuotaBytes));
  const texts = quotaTexts(tenant.storageUsedBytes, tenant.storageQuotaBytes, formatBytes, formatPercent, t);
  return {
    id: tenant.id,
    name: tenant.name,
    fqdn: tenant.fqdn,
    color: tenant.primaryColor,
    path: tenantPath(tenant.id, 'general'),
    statusVariant: status.variant,
    statusKey: status.key,
    used: tenant.storageUsedBytes,
    quota: tenant.storageQuotaBytes,
    usage: texts.usage,
    level,
    levelVariant: quotaBadgeVariant(level),
    levelLabel: texts.level,
  };
}

/** Rows of the entity table: the first HOME_TENANT_ROWS tenants, in the order of the API. */
export function homeTenantRows(
  tenants: readonly Tenant[],
  t: Translate,
  formatBytes: (n: number) => string,
  formatPercent: (ratio: number) => string,
): TenantRow[] {
  return tenants.slice(0, HOME_TENANT_ROWS).map((tenant) => tenantRow(tenant, t, formatBytes, formatPercent));
}

/**
 * Text of the action link of a row: "Configure" (super admin, delegated admin) or "Open" for an
 * auditor (read-only), followed in the accessible name by the tenant name (visually hidden), so
 * that each link is unambiguous out of its row.
 */
export function rowAction(
  row: Pick<TenantRow, 'name'>,
  kind: DashboardKind,
  t: Translate,
): { text: string; name: string } {
  return kind === 'auditor'
    ? { text: t('adminHome.table.open'), name: t('adminHome.table.openName', { name: row.name }) }
    : { text: t('adminHome.table.configure'), name: t('adminHome.table.configureName', { name: row.name }) };
}
