<script lang="ts">
  // System overview (super admin, GET /admin/system/stats): period selector reflected in the URL
  // (?period=7d, default 30d), usage of the data disk with the configured alert threshold and the
  // alert state (a prominent warning when the alert cannot be sent by mail), KPI tiles with a
  // neutral trend against the previous period (7 and 30 days), and the activity and storage of
  // every active tenant over the period (a compact storage gauge per row, its level written out
  // when nearly full or full). The system navigation is in the sidebar.
  import { untrack } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, HelpIcon, RadioGroup, Spinner } from '../../../shared/components';
  import { formatNumber, i18n, locale, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import Card from '../../components/Card.svelte';
  import DataTable from '../../components/DataTable.svelte';
  import QuotaMeter from '../../components/QuotaMeter.svelte';
  import StatCard from '../../components/StatCard.svelte';
  import StatusBadge from '../../components/StatusBadge.svelte';
  import { trend, trendText } from '../../components/trend';
  import { formatBytes as formatBinaryBytes } from '../../forms/bytes';
  import PageHeader from '../../components/PageHeader.svelte';
  import { parsePeriod, periodOptions, periodPath, type StatsPeriod } from '../ops/stats';
  import type { AdminScreenProps } from '../types';
  import VersionBlock from './VersionBlock.svelte';
  import {
    SETTINGS_PATH,
    SYSTEM_SMTP_VARIABLES,
    diskView,
    loadGlobalStats,
    overviewTotals,
    trendDays,
    tenantStatsRows,
    type GlobalStats,
    type TenantStatsRow,
  } from './overview';

  let { nav }: AdminScreenProps = $props();

  const formatBytes = (n: number): string => formatBinaryBytes(n, locale.current);
  const formatPercent = (r: number): string =>
    formatNumber(r, { style: 'percent', maximumFractionDigits: 1 });

  const period = $derived(parsePeriod(nav.current.search));
  let selected = $state<StatsPeriod>('30d');
  let stats = $state.raw<GlobalStats | undefined>(undefined);
  let loading = $state(true);
  let error = $state('');
  let generation = 0;

  const disk = $derived(stats === undefined ? undefined : diskView(stats.disk, t, formatPercent));
  const rows = $derived(
    stats === undefined
      ? []
      : tenantStatsRows(
          stats,
          { number: (n) => formatNumber(n), bytes: formatBytes, percent: formatPercent },
          t,
        ),
  );

  const totals = $derived(stats === undefined ? undefined : overviewTotals(stats));
  const diskRatio = $derived(
    disk === undefined || disk.total <= 0 ? 0 : Math.min(1, Math.max(0, disk.used / disk.total)),
  );

  // Neutral trend text under a tile; none for 12 months (no previous period).
  function tileTrend(current: number, previous: number | undefined): string | undefined {
    const days = trendDays(period);
    return days === undefined
      ? undefined
      : trendText(trend(current, previous), days, t, (r) =>
          formatNumber(r, { style: 'percent', maximumFractionDigits: 0 }),
        );
  }

  async function load(p: StatsPeriod): Promise<void> {
    const mine = ++generation;
    loading = true;
    error = '';
    try {
      const result = await loadGlobalStats(adminApi, p);
      if (mine === generation) {
        stats = result;
      }
    } catch (err) {
      if (mine === generation) {
        error = describeError(i18n, err).message;
      }
    } finally {
      if (mine === generation) {
        loading = false;
      }
    }
  }

  // The period comes from the URL: a change (selector, back button) reloads the figures.
  $effect(() => {
    const p = period;
    untrack(() => {
      selected = p;
      void load(p);
    });
  });

  function choose(value: StatsPeriod): void {
    void nav.navigate(periodPath(nav.current.path, value));
  }
</script>

{#snippet nameCell(row: TenantStatsRow)}
  <a class="tt-break" href={nav.href(row.path)} use:nav.link>{row.name}</a>
{/snippet}

{#snippet transfersCell(row: TenantStatsRow)}
  {row.transfers}
{/snippet}

{#snippet volumeCell(row: TenantStatsRow)}
  {row.volume}
{/snippet}

{#snippet virusesCell(row: TenantStatsRow)}
  {row.viruses}
{/snippet}

{#snippet downloadsCell(row: TenantStatsRow)}
  {row.downloads}
{/snippet}

{#snippet storageCell(row: TenantStatsRow)}
  <QuotaMeter
    used={row.used}
    quota={row.quota}
    label={t('sysStats.tenants.storageOf', { name: row.name })}
    labelHidden
    compact
    showLevel="alert"
    {formatBytes}
  />
{/snippet}

<PageHeader title={t('adminSystem.overview.title')} description={t('adminSystem.overview.intro')}>
  {#snippet help()}
    <HelpIcon topic="system-overview" title={t('adminSystem.overview.title')} {nav} />
  {/snippet}
</PageHeader>

<Card padding="sm">
  <RadioGroup
    legend={t('opsStats.period')}
    options={periodOptions(t)}
    bind:value={selected}
    inline
    onchange={choose}
  />
  <p class="tt-overview__note">{t('sysStats.indicative')}</p>
</Card>

{#if error !== ''}
  <Alert severity="error">
    <p>{error}</p>
    <Button variant="secondary" onclick={() => void load(period)}>{t('common.retry')}</Button>
  </Alert>
{:else if stats === undefined || disk === undefined || totals === undefined}
  <Spinner />
{:else}
  <div aria-busy={loading ? 'true' : undefined}>
    <div class="tt-overview__tiles" role="group" aria-label={t('sysStats.tiles.label')}>
      <StatCard
        label={t('sysStats.tiles.transfers')}
        value={formatNumber(totals.current.transfers)}
        trend={tileTrend(totals.current.transfers, totals.previous?.transfers)}
      />
      <StatCard
        label={t('sysStats.tiles.volume')}
        value={formatBytes(totals.current.bytes)}
        trend={tileTrend(totals.current.bytes, totals.previous?.bytes)}
      />
      <StatCard
        label={t('sysStats.tiles.viruses')}
        value={formatNumber(totals.current.viruses)}
        trend={tileTrend(totals.current.viruses, totals.previous?.viruses)}
      />
      <StatCard
        label={t('sysStats.tiles.downloads')}
        value={formatNumber(totals.current.downloads)}
        trend={tileTrend(totals.current.downloads, totals.previous?.downloads)}
      />
      <StatCard
        label={t('sysStats.tiles.disk')}
        value={formatPercent(diskRatio)}
        hint={`${formatBytes(disk.used)} / ${formatBytes(disk.total)}`}
        variant={disk.alertActive ? 'warning' : 'default'}
      />
    </div>

    <Card title={t('sysStats.disk.title')}>
      {#if disk.mailWarning}
        <Alert severity="warning" live={false}>
          <p><strong>{t('sysStats.disk.mailWarningTitle')}</strong></p>
          <p>{t('sysStats.disk.mailWarning')}</p>
          <p>{t('sysStats.disk.mailWarningAction', { variables: SYSTEM_SMTP_VARIABLES })}</p>
          <p class="tt-overview__link">
            <a href={nav.href(SETTINGS_PATH)} use:nav.link>{t('sysStats.disk.settingsLink')}</a>
          </p>
        </Alert>
      {/if}
      <QuotaMeter
        label={t('sysStats.disk.label')}
        showLevel={false}
        showThreshold
        used={disk.used}
        quota={disk.total}
        warningRatio={disk.threshold}
        {formatBytes}
      />
      <p class="tt-overview__alert">
        <span>{disk.thresholdLabel}</span>
        <StatusBadge variant={disk.alertVariant} label={disk.alertLabel} />
      </p>
      <p class="tt-overview__note">{t('sysStats.disk.thresholdHint')}</p>
      <p class="tt-overview__link">
        <a href={nav.href(SETTINGS_PATH)} use:nav.link>{t('sysStats.disk.changeSettings')}</a>
      </p>
    </Card>

    <Card title={t('sysStats.tenants.title')} flush>
      <DataTable
        variant="plain"
        caption={t('sysStats.tenants.caption')}
        captionHidden
        {rows}
        key={(row) => row.id}
        {loading}
        emptyText={t('sysStats.tenants.empty')}
        columns={[
          { id: 'name', header: t('sysStats.tenants.name'), cell: nameCell, rowHeader: true },
          { id: 'transfers', header: t('sysStats.tenants.transfers'), cell: transfersCell, align: 'end' },
          { id: 'volume', header: t('sysStats.tenants.volume'), cell: volumeCell, align: 'end' },
          { id: 'viruses', header: t('sysStats.tenants.viruses'), cell: virusesCell, align: 'end' },
          { id: 'downloads', header: t('sysStats.tenants.downloads'), cell: downloadsCell, align: 'end' },
          { id: 'storage', header: t('sysStats.tenants.storage'), cell: storageCell },
        ]}
      />
    </Card>
  </div>
{/if}

<VersionBlock />

<style>
  /* Standalone links to the settings: 44 px click targets. */
  .tt-overview__link a {
    display: inline-flex;
    align-items: center;
    min-height: 44px;
  }

  .tt-overview__tiles {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(12rem, 1fr));
    gap: var(--tt-space-4);
    margin-bottom: var(--tt-space-4);
  }

  .tt-overview__note {
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }

  .tt-overview__alert {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--tt-space-2);
    margin-bottom: var(--tt-space-1);
  }
</style>
