<script lang="ts">
  // Administration home (dashboard, CLAUDE.md section 21.2):
  // - delegated admin: one card per tenant with the statistics of the last 30 days (transfers,
  //   volume uploaded), the storage quota and quick links; the statistics are loaded with at
  //   most 4 requests at once, and a failed card shows its own message without affecting the
  //   others;
  // - super admin: table of the tenants (GET /admin/tenants, page by page) with their status and
  //   storage level;
  // - always: the recommendation to enable two-factor authentication when it is off.
  import { onDestroy, untrack } from 'svelte';
  import { describeError } from '../../shared/api/problem';
  import { Alert, Button, Spinner } from '../../shared/components';
  import { formatNumber, i18n, locale, t } from '../../shared/i18n/i18n.svelte';
  import { adminApi, adminSession } from '../api';
  import DataTable from '../components/DataTable.svelte';
  import QuotaMeter from '../components/QuotaMeter.svelte';
  import StatCard from '../components/StatCard.svelte';
  import StatusBadge from '../components/StatusBadge.svelte';
  import { formatBytes as formatBinaryBytes } from '../forms/bytes';
  import { tenantPath } from '../shell';
  import {
    DASHBOARD_PERIOD,
    STATS_CONCURRENCY,
    cardFigures,
    cardHeadingLevel,
    dashboardKind,
    initialCards,
    mapLimit,
    quickLinks,
    tenantRow,
    withError,
    withLoading,
    withStats,
    type TenantCard,
    type TenantRow,
  } from './home';
  import { appendPage, type Tenant } from './tenants/tenants';
  import type { AdminScreenProps } from './types';

  let { nav }: AdminScreenProps = $props();

  const me = $derived(adminSession.me);
  const kind = $derived(dashboardKind(me));
  const formatBytes = (n: number): string => formatBinaryBytes(n, locale.current);
  const formatPercent = (r: number): string =>
    formatNumber(r, { style: 'percent', maximumFractionDigits: 1 });

  let alive = true;
  onDestroy(() => {
    alive = false;
  });

  // ---- Delegated admin ----
  let cards = $state.raw<TenantCard[]>([]);
  const level = $derived(cardHeadingLevel(cards.length));

  type Ref = NonNullable<typeof me>['tenants'][number];

  async function loadCard(ref: Ref): Promise<void> {
    try {
      const res = await adminApi.get('/admin/tenants/{tenantId}/stats', {
        path: { tenantId: ref.id },
        params: { period: DASHBOARD_PERIOD },
      });
      if (alive) {
        cards = withStats(cards, ref.id, res.data);
      }
    } catch (err) {
      if (alive) {
        cards = withError(cards, ref.id, describeError(i18n, err).message);
      }
    }
  }

  async function loadCards(refs: readonly Ref[]): Promise<void> {
    cards = initialCards(refs);
    await mapLimit(refs, STATS_CONCURRENCY, loadCard);
  }

  function retryCard(card: TenantCard): void {
    const ref = me?.tenants.find((r) => r.id === card.id);
    if (ref !== undefined) {
      cards = withLoading(cards, card.id);
      void loadCard(ref);
    }
  }

  // ---- Super admin ----
  let tenants = $state.raw<Tenant[]>([]);
  let nextCursor = $state<string | undefined>(undefined);
  let tenantsLoading = $state(true);
  let tenantsError = $state('');
  let moreError = $state('');
  const rows = $derived(tenants.map((tenant) => tenantRow(tenant, t, formatBytes, formatPercent)));

  async function loadTenants(): Promise<void> {
    tenantsLoading = true;
    tenantsError = '';
    moreError = '';
    try {
      const res = await adminApi.get('/admin/tenants');
      tenants = res.data.items;
      nextCursor = res.data.nextCursor;
    } catch (err) {
      tenantsError = describeError(i18n, err).message;
    } finally {
      tenantsLoading = false;
    }
  }

  async function loadMoreTenants(): Promise<void> {
    if (nextCursor === undefined) {
      return;
    }
    moreError = '';
    try {
      const res = await adminApi.get('/admin/tenants', { params: { cursor: nextCursor } });
      tenants = appendPage(tenants, res.data.items);
      nextCursor = res.data.nextCursor;
    } catch (err) {
      moreError = describeError(i18n, err).message;
    }
  }

  // Loads once per admin and role (the profile is reloaded after some changes). The loaders are
  // untracked: adminApi reads the locale synchronously, which must not re-run this effect.
  let loadedFor = '';
  $effect(() => {
    const current = me;
    if (current === undefined) {
      return;
    }
    const signature = `${current.id}|${current.role}|${current.tenants.map((r) => r.id).join(',')}`;
    if (signature === loadedFor) {
      return;
    }
    loadedFor = signature;
    untrack(() => {
      if (current.role === 'super_admin') {
        void loadTenants();
      } else {
        void loadCards(current.tenants);
      }
    });
  });
</script>

{#snippet nameCell(row: TenantRow)}
  <a class="tt-break" href={nav.href(row.path)} use:nav.link>{row.name}</a>
{/snippet}

{#snippet fqdnCell(row: TenantRow)}
  <span class="tt-break">{row.fqdn}</span>
{/snippet}

{#snippet statusCell(row: TenantRow)}
  <StatusBadge variant={row.statusVariant} label={t(row.statusKey)} />
{/snippet}

{#snippet storageCell(row: TenantRow)}
  <span class="tt-home__storage">
    <StatusBadge variant={row.levelVariant} label={row.levelLabel} />
    <span>{row.usage}</span>
  </span>
{/snippet}

{#snippet cardHeading(card: TenantCard)}
  <svelte:element this={level === 2 ? 'h2' : 'h3'} class="tt-home__card-title">
    <a class="tt-break" href={nav.href(tenantPath(card.id, 'general'))} use:nav.link>
      {card.name}
    </a>
  </svelte:element>
{/snippet}

<h1 tabindex="-1">{t('admin.home.title')}</h1>
{#if me}
  <p>{t('adminHome.welcome', { username: me.username })}</p>
  {#if !me.totpEnabled}
    <Alert severity="warning" live={false}>
      <p>
        {t('adminHome.totpRecommended')}
        <a href={nav.href('/account')} use:nav.link>{t('adminHome.accountLink')}</a>
      </p>
    </Alert>
  {/if}
{/if}

{#if kind === 'delegated'}
  {#if cards.length === 0}
    <Alert severity="info" live={false}>
      <p>{t('adminHome.noTenant')}</p>
    </Alert>
  {:else}
    {#if cards.length > 1}
      <h2>{t('adminHome.tenantsTitle')}</h2>
    {/if}
    <p>{t('adminHome.periodNote')}</p>
    <ul class="tt-home__cards" role="list">
      {#each cards as card (card.id)}
        <li class="tt-home__card">
          {@render cardHeading(card)}
          {#if card.state === 'loading'}
            <Spinner label={t('adminHome.card.loading', { name: card.name })} />
          {:else if card.state === 'error'}
            <Alert severity="error" live={false}>
              <p>{t('adminHome.card.error', { name: card.name })}</p>
              <p>{card.message}</p>
              <Button variant="secondary" small onclick={() => retryCard(card)}
                >{t('adminHome.card.retry')}</Button
              >
            </Alert>
          {:else}
            <div class="tt-home__figures">
              {#each cardFigures(card.stats, t, (n) => formatNumber(n), formatBytes) as figure (figure.id)}
                <StatCard label={figure.label} value={figure.value} />
              {/each}
            </div>
            <QuotaMeter used={card.stats.storageUsedBytes} quota={card.stats.storageQuotaBytes} />
          {/if}
          <ul class="tt-home__links">
            {#each quickLinks(card, t) as link (link.section)}
              <li><a href={nav.href(link.path)} use:nav.link>{link.label}</a></li>
            {/each}
          </ul>
        </li>
      {/each}
    </ul>
  {/if}
{:else if kind === 'super'}
  <h2>{t('adminHome.tenantsTitle')}</h2>
  {#if tenantsError !== ''}
    <Alert severity="error">
      <p>{tenantsError}</p>
      <Button variant="secondary" onclick={() => void loadTenants()}>{t('common.retry')}</Button>
    </Alert>
  {:else}
    <DataTable
      caption={t('adminHome.table.caption')}
      captionHidden
      {rows}
      key={(row) => row.id}
      loading={tenantsLoading}
      emptyText={t('adminHome.table.empty')}
      {nextCursor}
      onloadmore={loadMoreTenants}
      columns={[
        { id: 'name', header: t('adminHome.table.name'), cell: nameCell, rowHeader: true },
        { id: 'fqdn', header: t('adminHome.table.fqdn'), cell: fqdnCell },
        { id: 'status', header: t('adminHome.table.status'), cell: statusCell },
        { id: 'storage', header: t('adminHome.table.storage'), cell: storageCell },
      ]}
    />
    {#if moreError !== ''}
      <Alert severity="error">{moreError}</Alert>
    {/if}
    <p><a href={nav.href('/tenants')} use:nav.link>{t('adminHome.allTenants')}</a></p>
  {/if}
{/if}

<style>
  .tt-home__cards {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(min(100%, 22rem), 1fr));
    gap: var(--tt-space-4);
    margin: var(--tt-space-4) 0;
    padding: 0;
    list-style: none;
  }

  .tt-home__card {
    padding: var(--tt-space-4);
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius);
    background: var(--tt-surface);
  }

  .tt-home__card-title {
    margin-top: 0;
  }

  .tt-home__figures {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(min(100%, 9rem), 1fr));
    gap: var(--tt-space-3);
    margin-bottom: var(--tt-space-4);
  }

  .tt-home__links {
    margin: 0;
    padding-left: var(--tt-space-5);
  }

  .tt-home__storage {
    display: inline-flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--tt-space-2);
  }
</style>
