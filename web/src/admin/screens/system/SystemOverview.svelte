<script lang="ts">
  // System overview (super admin, GET /admin/system/stats): period selector reflected in the URL
  // (?period=7d, default 30d), usage of the data disk with the configured alert threshold and the
  // alert state (a prominent warning when the alert cannot be sent by mail), and the activity and
  // storage of every active tenant over the period. The system sub-navigation is rendered by
  // App.svelte.
  import { untrack } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, RadioGroup, Spinner } from '../../../shared/components';
  import { formatNumber, i18n, locale, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import DataTable from '../../components/DataTable.svelte';
  import QuotaMeter from '../../components/QuotaMeter.svelte';
  import StatusBadge from '../../components/StatusBadge.svelte';
  import { formatBytes as formatBinaryBytes } from '../../forms/bytes';
  import { parsePeriod, periodOptions, periodPath, type StatsPeriod } from '../ops/stats';
  import type { AdminScreenProps } from '../types';
  import {
    SETTINGS_PATH,
    SYSTEM_SMTP_VARIABLES,
    diskView,
    loadGlobalStats,
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

{#snippet storageCell(row: TenantStatsRow)}
  <span class="tt-overview__storage">
    <StatusBadge variant={row.levelVariant} label={row.levelLabel} />
    <span>{row.usage}</span>
  </span>
{/snippet}

<h1 tabindex="-1">{t('adminSystem.overview.title')}</h1>
<p>{t('adminSystem.overview.intro')}</p>

<RadioGroup
  legend={t('opsStats.period')}
  options={periodOptions(t)}
  bind:value={selected}
  inline
  onchange={choose}
/>

<p class="tt-overview__note">{t('sysStats.indicative')}</p>

{#if error !== ''}
  <Alert severity="error">
    <p>{error}</p>
    <Button variant="secondary" onclick={() => void load(period)}>{t('common.retry')}</Button>
  </Alert>
{:else if stats === undefined || disk === undefined}
  <Spinner />
{:else}
  <div aria-busy={loading ? 'true' : undefined}>
    <h2>{t('sysStats.disk.title')}</h2>
    {#if disk.mailWarning}
      <Alert severity="warning" live={false}>
        <p><strong>{t('sysStats.disk.mailWarningTitle')}</strong></p>
        <p>{t('sysStats.disk.mailWarning')}</p>
        <p>{t('sysStats.disk.mailWarningAction', { variables: SYSTEM_SMTP_VARIABLES })}</p>
        <p><a href={nav.href(SETTINGS_PATH)} use:nav.link>{t('sysStats.disk.settingsLink')}</a></p>
      </Alert>
    {/if}
    <QuotaMeter
      label={t('sysStats.disk.label')}
      showLevel={false}
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
    <p><a href={nav.href(SETTINGS_PATH)} use:nav.link>{t('sysStats.disk.changeSettings')}</a></p>

    <h2>{t('sysStats.tenants.title')}</h2>
    <DataTable
      caption={t('sysStats.tenants.caption')}
      {rows}
      key={(row) => row.id}
      {loading}
      emptyText={t('sysStats.tenants.empty')}
      columns={[
        { id: 'name', header: t('sysStats.tenants.name'), cell: nameCell, rowHeader: true },
        { id: 'transfers', header: t('sysStats.tenants.transfers'), cell: transfersCell, align: 'end' },
        { id: 'volume', header: t('sysStats.tenants.volume'), cell: volumeCell, align: 'end' },
        { id: 'storage', header: t('sysStats.tenants.storage'), cell: storageCell },
      ]}
    />
  </div>
{/if}

<style>
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

  .tt-overview__storage {
    display: inline-flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--tt-space-2);
  }
</style>
