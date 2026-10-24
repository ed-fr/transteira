<script lang="ts">
  // Statistics of a tenant (GET /admin/tenants/{tenantId}/stats): period selector reflected in
  // the URL (?period=7d, default 30d), key figure cards, storage meter and two bar charts (with
  // their equivalent tables) of the transfers and the volume deposited per day or per month.
  import { untrack } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, RadioGroup, Spinner } from '../../../shared/components';
  import { formatNumber, i18n, locale, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import BarChart from '../../components/BarChart.svelte';
  import QuotaMeter from '../../components/QuotaMeter.svelte';
  import StatCard from '../../components/StatCard.svelte';
  import { formatBytes as formatBinaryBytes } from '../../forms/bytes';
  import type { AdminScreenProps } from '../types';
  import {
    chartTexts,
    loadTenantStats,
    parsePeriod,
    periodOptions,
    periodPath,
    seriesFor,
    statsCards,
    type StatsPeriod,
    type TenantStats,
  } from './stats';

  let { params, nav }: AdminScreenProps = $props();

  const formatBytes = (n: number): string => formatBinaryBytes(n, locale.current);
  const formatCount = (n: number): string => formatNumber(n);

  const period = $derived(parsePeriod(nav.current.search));
  let selected = $state<StatsPeriod>('30d');
  let stats = $state.raw<TenantStats | undefined>(undefined);
  let loading = $state(true);
  let error = $state('');
  let generation = 0;

  const cards = $derived(
    stats === undefined ? [] : statsCards(stats, { number: formatCount, bytes: formatBytes }, t),
  );
  const texts = $derived(chartTexts(stats?.period ?? period, t));
  const transferSeries = $derived(stats === undefined ? [] : seriesFor(stats, 'transfers', locale.current));
  const volumeSeries = $derived(stats === undefined ? [] : seriesFor(stats, 'bytesUploaded', locale.current));

  async function load(tenantId: string, p: StatsPeriod): Promise<void> {
    const mine = ++generation;
    loading = true;
    error = '';
    try {
      const result = await loadTenantStats(adminApi, tenantId, p);
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
    const tenantId = params['id'] ?? '';
    untrack(() => {
      selected = p;
      void load(tenantId, p);
    });
  });

  function choose(value: StatsPeriod): void {
    void nav.navigate(periodPath(nav.current.path, value));
  }
</script>

<h1 tabindex="-1">{t('adminOps.stats.title')}</h1>
<p>{t('adminOps.stats.intro')}</p>

<RadioGroup
  legend={t('opsStats.period')}
  options={periodOptions(t)}
  bind:value={selected}
  inline
  onchange={choose}
/>

<p class="tt-stats__note">{t('opsStats.indicative')}</p>

{#if error !== ''}
  <Alert severity="error">
    <p>{error}</p>
    <Button variant="secondary" onclick={() => void load(params['id'] ?? '', period)}
      >{t('common.retry')}</Button
    >
  </Alert>
{:else if stats === undefined}
  <Spinner />
{:else}
  <div aria-busy={loading ? 'true' : undefined}>
    <h2>{t('opsStats.figures')}</h2>
    <div class="tt-stats__cards">
      {#each cards as card (card.id)}
        <StatCard label={card.label} value={card.value} variant={card.variant} />
      {/each}
    </div>

    <h2>{t('opsStats.storage')}</h2>
    <QuotaMeter
      label={t('opsStats.storageLabel')}
      used={stats.storageUsedBytes}
      quota={stats.storageQuotaBytes}
      {formatBytes}
    />

    <h2>{t('opsStats.activity')}</h2>
    <BarChart
      title={texts.transfersTitle}
      series={transferSeries}
      formatValue={formatCount}
      labelHeader={texts.labelHeader}
      valueHeader={t('opsStats.charts.transfersHeader')}
    />
    <BarChart
      title={texts.volumeTitle}
      series={volumeSeries}
      formatValue={formatBytes}
      labelHeader={texts.labelHeader}
      valueHeader={t('opsStats.charts.volumeHeader')}
    />
  </div>
{/if}

<style>
  .tt-stats__note {
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }

  .tt-stats__cards {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(min(12rem, 100%), 1fr));
    gap: var(--tt-space-4);
    margin-bottom: var(--tt-space-6);
  }
</style>
