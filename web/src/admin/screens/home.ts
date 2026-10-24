// Logic of the administration home (dashboard), kept out of the component so that it is unit
// tested in Node: kind of dashboard per role, cards of a delegated admin (30-day statistics,
// storage quota, quick links) loaded with a bounded concurrency, and, for the super admin, the
// rows of the tenant table, the disk card and the maintenance state. The statistics mapping is
// deliberately minimal (the statistics screen has its own).
import type { components } from '../../shared/api/schema';
import type { AdminMe } from '../auth/machine';
import { quotaBadgeVariant, quotaLevel, quotaRatio, quotaTexts, type QuotaLevel } from '../components/quota';
import { maintenanceBanner, maintenanceBannerText, type Maintenance } from '../maintenanceBanner';
import { systemPath, tenantPath, type TenantSection } from '../shell';
import { diskView, type DiskView, type GlobalStats } from './system/overview';
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

/** Maximum number of statistics requests in flight at once. */
export const STATS_CONCURRENCY = 4;

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

// ---- Kind ------------------------------------------------------------------------------------

/** Content of the dashboard: tenant table (super admin), tenant cards (delegated), nothing. */
export type DashboardKind = 'super' | 'delegated' | 'none';

/** Kind of dashboard of an admin. */
export function dashboardKind(me: AdminMe | undefined): DashboardKind {
  if (me === undefined) {
    return 'none';
  }
  return me.role === 'super_admin' ? 'super' : 'delegated';
}

// ---- Delegated admin cards -------------------------------------------------------------------

/** A card of a tenant of a delegated admin. */
export type TenantCard =
  | { id: string; name: string; state: 'loading' }
  | { id: string; name: string; state: 'ready'; stats: TenantStats }
  | { id: string; name: string; state: 'error'; message: string };

/** Cards of the tenants of an admin, all loading, in the order of the profile. */
export function initialCards(tenants: readonly TenantRef[]): TenantCard[] {
  return tenants.map((ref) => ({ id: ref.id, name: ref.name, state: 'loading' }));
}

/** Replaces the card of tenant id by its loaded statistics. */
export function withStats(cards: readonly TenantCard[], id: string, stats: TenantStats): TenantCard[] {
  return cards.map((c) => (c.id === id ? { id: c.id, name: c.name, state: 'ready', stats } : c));
}

/** Puts the card of tenant id back to loading (retry). */
export function withLoading(cards: readonly TenantCard[], id: string): TenantCard[] {
  return cards.map((c) => (c.id === id ? { id: c.id, name: c.name, state: 'loading' } : c));
}

/** Replaces the card of tenant id by an error message. */
export function withError(cards: readonly TenantCard[], id: string, message: string): TenantCard[] {
  return cards.map((c) => (c.id === id ? { id: c.id, name: c.name, state: 'error', message } : c));
}

/**
 * Heading level of the tenant name in a card: with a single tenant, the card is the content of
 * the page (level 2); with several, the cards sit under a "My entities" heading (level 3).
 */
export function cardHeadingLevel(count: number): 2 | 3 {
  return count <= 1 ? 2 : 3;
}

/** A key figure of a card. */
export interface Figure {
  id: string;
  label: string;
  value: string;
}

/** Key figures of a card over the period: transfers and volume uploaded. */
export function cardFigures(
  stats: Pick<TenantStats, 'transferCount' | 'bytesUploaded'>,
  t: Translate,
  formatNumber: (n: number) => string,
  formatBytes: (n: number) => string,
): Figure[] {
  return [
    { id: 'transfers', label: t('adminHome.card.transfers'), value: formatNumber(stats.transferCount) },
    { id: 'volume', label: t('adminHome.card.volume'), value: formatBytes(stats.bytesUploaded) },
  ];
}

/** A quick link of a card. */
export interface QuickLink {
  section: TenantSection;
  path: string;
  label: string;
}

/** Sections reachable from a card. */
export const QUICK_SECTIONS = ['transfers', 'audit', 'stats'] as const satisfies readonly TenantSection[];

/** Quick links of a card (the tenant name is in the label, for unambiguous link texts). */
export function quickLinks(card: Pick<TenantCard, 'id' | 'name'>, t: Translate): QuickLink[] {
  return QUICK_SECTIONS.map((section) => ({
    section,
    path: tenantPath(card.id, section),
    label: t(`adminHome.links.${section}`, { name: card.name }),
  }));
}

// ---- Super admin table -----------------------------------------------------------------------

/** A row of the tenant table of the super admin. */
export interface TenantRow {
  id: string;
  name: string;
  fqdn: string;
  /** Path of the general settings of the tenant. */
  path: string;
  statusVariant: 'ok' | 'warning';
  statusKey: string;
  /** "12 GiB of 100 GiB (12 %)", or the no-quota notice. */
  usage: string;
  level: QuotaLevel;
  levelVariant: 'ok' | 'warning' | 'error';
  levelLabel: string;
}

/** Row of a tenant in the table of the super admin, with its storage level. */
export function tenantRow(
  tenant: Tenant,
  t: Translate,
  formatBytes: (n: number) => string,
  formatPercent: (ratio: number) => string,
): TenantRow {
  const status = statusView(tenant.status);
  const level = quotaLevel(quotaRatio(tenant.storageUsedBytes, tenant.storageQuotaBytes));
  const texts = quotaTexts(tenant.storageUsedBytes, tenant.storageQuotaBytes, formatBytes, formatPercent, t);
  return {
    id: tenant.id,
    name: tenant.name,
    fqdn: tenant.fqdn,
    path: tenantPath(tenant.id, 'general'),
    statusVariant: status.variant,
    statusKey: status.key,
    usage: texts.usage,
    level,
    levelVariant: quotaBadgeVariant(level),
    levelLabel: texts.level,
  };
}

// ---- Super admin: disk card and maintenance state -------------------------------------------

/** Period requested for the disk card (only the disk part of the answer is used). */
export const DISK_CARD_PERIOD = '30d' as const;

/** State of the disk card of the super admin, loaded independently of the tenant table. */
export type DiskCard =
  { state: 'loading' } | { state: 'ready'; disk: DiskView } | { state: 'error'; message: string };

/** Disk card built from the global statistics. */
export function diskCard(
  stats: Pick<GlobalStats, 'disk'>,
  t: Translate,
  formatPercent: (r: number) => string,
): DiskCard {
  return { state: 'ready', disk: diskView(stats.disk, t, formatPercent) };
}

/** Maintenance line of the dashboard of the super admin. */
export interface MaintenanceLine {
  /** The state is known (read at least once). */
  known: boolean;
  /** The state is unknown because its read failed: the card says so instead of waiting. */
  failed: boolean;
  /** Badge: warning while the maintenance mode is on, ok otherwise. */
  variant: 'warning' | 'ok';
  /** Text of the badge. */
  label: string;
  /** Detail: the banner text while on (start date, forced by the environment), empty otherwise. */
  text: string;
  /** Link to the maintenance screen. */
  linkPath: string;
}

/**
 * Maintenance line for the last known state (undefined while unknown); failed tells that the
 * latest read failed (adminMaintenance.failed).
 */
export function maintenanceLine(
  state: Maintenance | undefined,
  t: Translate,
  formatDate: (iso: string) => string,
  failed = false,
): MaintenanceLine {
  const view = maintenanceBanner(state, 'super_admin');
  return {
    known: state !== undefined,
    failed: state === undefined && failed,
    variant: view.visible ? 'warning' : 'ok',
    label: t(view.visible ? 'sysStats.home.maintenanceOn' : 'sysStats.home.maintenanceOff'),
    text: view.visible ? maintenanceBannerText(view, t, formatDate) : '',
    linkPath: systemPath('maintenance'),
  };
}
