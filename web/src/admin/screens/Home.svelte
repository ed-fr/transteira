<script lang="ts">
  // Administration home (dashboard; CLAUDE.md sections 13.2 and 21.2):
  // - header: the h1 "Home" (unchanged, plan deviation 1) with the greeting as description, the
  //   transfer search (stored in the in-memory searchQuery store, then /search: never in the URL,
  //   T-412) and, for the super admin, "New entity";
  // - key figures of the last 30 days (KPI tiles, neutral trends against the previous 30 days):
  //   super admin, ONE global statistics call giving transfers, volume, viruses and the disk tile
  //   (gauge with the alert threshold marker); other roles, the sum of the statistics of their
  //   tenants (at most 4 requests at once) and a storage tile, one error and one "Try again" for
  //   any failure;
  // - the Entities card: at most 10 rows (colour swatch, name and domain, status, storage, link)
  //   and "See all";
  // - super admin: the "System status" card (getSystemStatus); delegated admin and auditor: the
  //   shortcuts to the sections of their tenants (consultation sections only for the auditor);
  // - always: the recommendation to enable two-factor authentication when it is off, and for a
  //   delegated admin the call to action of the tenants still being set up.
  import { onDestroy, untrack } from 'svelte';
  import { describeError } from '../../shared/api/problem';
  import { Alert, Button, HelpIcon, Spinner } from '../../shared/components';
  import { formatNumber, i18n, locale, t } from '../../shared/i18n/i18n.svelte';
  import { adminApi, adminSession } from '../api';
  import ActionLink from '../components/ActionLink.svelte';
  import Card from '../components/Card.svelte';
  import DataTable from '../components/DataTable.svelte';
  import Gauge from '../components/Gauge.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import QuotaMeter from '../components/QuotaMeter.svelte';
  import StatCard from '../components/StatCard.svelte';
  import StatusBadge from '../components/StatusBadge.svelte';
  import TenantSwatch from '../components/TenantSwatch.svelte';
  import TransferSearchForm from '../components/TransferSearchForm.svelte';
  import { formatBytes as formatBinaryBytes } from '../forms/bytes';
  import { searchQuery } from '../search.svelte';
  import {
    DASHBOARD_PERIOD,
    STATS_CONCURRENCY,
    createLoadGenerations,
    dashboardKind,
    diskTile,
    figureTiles,
    globalFigures,
    greeting,
    homeTenantRows,
    initialCards,
    mapLimit,
    quickLinks,
    rowAction,
    storageTile,
    tenantFigures,
    tenantTilesState,
    withError,
    withLoading,
    withStats,
    type FigureTile,
    type GaugeTile,
    type HomeFormatters,
    type TenantCard,
    type TenantRow,
  } from './home';
  import { loadGlobalStats, type GlobalStats } from './system/overview';
  import { MAINTENANCE_PATH, loadSystemStatus, systemStatusRows, type SystemStatus } from './systemStatus';
  import { setupPath, tenantsInSetup } from './tenants/setup';
  import type { Tenant } from './tenants/tenants';
  import type { AdminScreenProps } from './types';

  let { nav }: AdminScreenProps = $props();

  const me = $derived(adminSession.me);
  const kind = $derived(dashboardKind(me));
  const title = $derived(t('admin.home.title'));
  const fmt: HomeFormatters = {
    number: (n) => formatNumber(n),
    bytes: (n) => formatBinaryBytes(n, locale.current),
    percent: (r) => formatNumber(r, { style: 'percent', maximumFractionDigits: 1 }),
    trendPercent: (r) => formatNumber(r, { style: 'percent', maximumFractionDigits: 0 }),
  };

  // Each profile signature starts a new generation of loads: an answer of a previous one (or one
  // arriving after the screen is gone) is ignored, so that it never overwrites newer data.
  const loads = createLoadGenerations();
  onDestroy(() => {
    loads.stop();
  });

  /** State of a block loaded from the API. */
  type Load<T> = { state: 'loading' } | { state: 'ready'; data: T } | { state: 'error'; message: string };

  function failure(err: unknown): { state: 'error'; message: string } {
    return { state: 'error', message: describeError(i18n, err).message };
  }

  // ---- Search --------------------------------------------------------------------------------
  // The query goes to the in-memory store, then the results screen reads it (never the URL).
  let query = $state('');

  function openSearch(q: string): void {
    searchQuery.set(q);
    void nav.navigate('/search');
  }

  // ---- Super admin: global statistics (figures and disk) and system status --------------------
  let global = $state.raw<Load<GlobalStats>>({ state: 'loading' });
  let status = $state.raw<Load<SystemStatus>>({ state: 'loading' });
  const statusRows = $derived(status.state === 'ready' ? systemStatusRows(status.data, t) : []);

  async function loadGlobal(gen = loads.current()): Promise<void> {
    global = { state: 'loading' };
    try {
      const data = await loadGlobalStats(adminApi, DASHBOARD_PERIOD);
      if (loads.isCurrent(gen)) {
        global = { state: 'ready', data };
      }
    } catch (err) {
      if (loads.isCurrent(gen)) {
        global = failure(err);
      }
    }
  }

  async function loadStatus(gen = loads.current()): Promise<void> {
    status = { state: 'loading' };
    try {
      const data = await loadSystemStatus(adminApi);
      if (loads.isCurrent(gen)) {
        status = { state: 'ready', data };
      }
    } catch (err) {
      if (loads.isCurrent(gen)) {
        status = failure(err);
      }
    }
  }

  // ---- Delegated admin and auditor: statistics of each tenant ----------------------------------
  let cards = $state.raw<TenantCard[]>([]);

  type Ref = NonNullable<typeof me>['tenants'][number];

  /** Loads the statistics of one tenant for generation gen (skipped once it is stale). */
  async function loadCard(ref: Ref, gen: number): Promise<void> {
    if (!loads.isCurrent(gen)) {
      return;
    }
    try {
      const res = await adminApi.get('/admin/tenants/{tenantId}/stats', {
        path: { tenantId: ref.id },
        params: { period: DASHBOARD_PERIOD },
      });
      if (loads.isCurrent(gen)) {
        cards = withStats(cards, ref.id, res.data);
      }
    } catch (err) {
      if (loads.isCurrent(gen)) {
        cards = withError(cards, ref.id, describeError(i18n, err).message);
      }
    }
  }

  async function loadCards(refs: readonly Ref[], gen: number): Promise<void> {
    cards = initialCards(refs);
    await mapLimit(refs, STATS_CONCURRENCY, (ref) => loadCard(ref, gen));
  }

  /** Reloads the failed tenants only (the loaded ones are kept). */
  function retryCards(): void {
    const state = tenantTilesState(cards);
    if (state.state !== 'error') {
      return;
    }
    const refs = (me?.tenants ?? []).filter((ref) => state.failed.includes(ref.id));
    for (const ref of refs) {
      cards = withLoading(cards, ref.id);
    }
    const gen = loads.current();
    void mapLimit(refs, STATS_CONCURRENCY, (ref) => loadCard(ref, gen));
  }

  // ---- Key figures (every role) ---------------------------------------------------------------
  type Figures =
    | { state: 'loading' }
    | { state: 'error'; title: string; message: string }
    | { state: 'ready'; tiles: FigureTile[]; gauge: GaugeTile };

  const figures = $derived.by<Figures>(() => {
    if (kind === 'super') {
      if (global.state === 'ready') {
        return {
          state: 'ready',
          tiles: figureTiles(globalFigures(global.data), t, fmt),
          gauge: diskTile(global.data.disk, t, fmt),
        };
      }
      return global.state === 'error'
        ? { state: 'error', title: t('adminHome.tiles.error'), message: global.message }
        : { state: 'loading' };
    }
    const own = tenantTilesState(cards);
    if (own.state === 'ready') {
      return {
        state: 'ready',
        tiles: figureTiles(tenantFigures(own.stats), t, fmt),
        gauge: storageTile(own.stats, t, fmt),
      };
    }
    return own.state === 'error'
      ? {
          state: 'error',
          title: t('adminHome.tiles.errorTenants', { names: own.names }),
          message: own.message,
        }
      : { state: 'loading' };
  });

  function retryFigures(): void {
    if (kind === 'super') {
      void loadGlobal();
    } else {
      retryCards();
    }
  }

  // ---- Entities (every role: the API lists the tenants of the admin) ---------------------------
  let tenants = $state.raw<Load<Tenant[]>>({ state: 'loading' });
  const rows = $derived(
    tenants.state === 'ready' ? homeTenantRows(tenants.data, t, fmt.bytes, fmt.percent) : [],
  );
  // Tenants of a delegated admin still being set up (call to action to their wizard).
  const setupTenants = $derived(
    kind === 'delegated' && tenants.state === 'ready' ? tenantsInSetup(tenants.data) : [],
  );
  // The greeting counts the tenants of the profile (every tenant for a super admin, whatever its
  // status, like the Entities card and the sidebar), not the rows of the statistics.
  const description = $derived(me === undefined ? undefined : greeting(me, kind, t));
  const hasTenants = $derived(kind === 'super' || (me?.tenants.length ?? 0) > 0);

  async function loadTenants(gen = loads.current()): Promise<void> {
    tenants = { state: 'loading' };
    try {
      const res = await adminApi.get('/admin/tenants');
      if (loads.isCurrent(gen)) {
        tenants = { state: 'ready', data: res.data.items };
      }
    } catch (err) {
      if (loads.isCurrent(gen)) {
        tenants = failure(err);
      }
    }
  }

  // Loads once per admin and role (the profile is reloaded after some changes), in a new
  // generation each time (the answers of the previous one are then ignored). The loaders are
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
      const gen = loads.next();
      if (current.role === 'super_admin') {
        void loadGlobal(gen);
        void loadStatus(gen);
        void loadTenants(gen);
      } else if (current.tenants.length > 0) {
        void loadCards(current.tenants, gen);
        void loadTenants(gen);
      }
    });
  });
</script>

{#snippet entityCell(row: TenantRow)}
  <span class="tt-home__entity">
    <TenantSwatch color={row.color} />
    <span class="tt-home__entity-text">
      <a class="tt-home__entity-name tt-break" href={nav.href(row.path)} use:nav.link>{row.name}</a>
      <span class="tt-home__fqdn tt-break">{row.fqdn}</span>
    </span>
  </span>
{/snippet}

{#snippet statusCell(row: TenantRow)}
  <StatusBadge variant={row.statusVariant} label={t(row.statusKey)} />
{/snippet}

{#snippet storageCell(row: TenantRow)}
  <QuotaMeter
    used={row.used}
    quota={row.quota}
    label={t('adminHome.table.storageOf', { name: row.name })}
    labelHidden
    compact
    showLevel="alert"
    formatBytes={fmt.bytes}
  />
{/snippet}

{#snippet actionCell(row: TenantRow)}
  {@const action = rowAction(row, kind, t)}
  <a class="tt-home__action" href={nav.href(row.path)} use:nav.link
    ><span aria-hidden="true">{action.text}</span><span class="visually-hidden">{action.name}</span></a
  >
{/snippet}

<PageHeader {title} {description}>
  {#snippet help()}
    <HelpIcon topic="admin" {title} {nav} />
  {/snippet}
  {#snippet actions()}
    {#if me}
      <TransferSearchForm
        class="tt-home__search"
        auditor={kind === 'auditor'}
        bind:value={query}
        onsearch={openSearch}
      />
    {/if}
    {#if kind === 'super'}
      <ActionLink to="/tenants/new" {nav} icon="plus">{t('adminHome.newTenant')}</ActionLink>
    {/if}
  {/snippet}
</PageHeader>

{#if me && !me.totpEnabled}
  <Alert severity="warning" live={false}>
    <p>
      {t('adminHome.totpRecommended')}
      <a href={nav.href('/account')} use:nav.link>{t('adminHome.accountLink')}</a>
    </p>
  </Alert>
{/if}

{#if setupTenants.length > 0}
  <Alert severity="warning" live={false} title={t('setup.home.title')}>
    {#if setupTenants.length === 1}
      {@const only = setupTenants[0] as Tenant}
      <p>{t('setup.home.text', { name: only.name })}</p>
    {:else}
      <p>{t('setup.home.textMany')}</p>
    {/if}
    <ul>
      {#each setupTenants as tenant (tenant.id)}
        <li>
          <a class="tt-link-target" href={nav.href(setupPath(tenant.id))} use:nav.link>
            {t('setup.home.action', { name: tenant.name })}
          </a>
        </li>
      {/each}
    </ul>
  </Alert>
{/if}

{#if kind === 'delegated' || kind === 'auditor'}
  {#if !hasTenants}
    <Alert severity="info" live={false}>
      <p>{t('adminHome.noTenant')}</p>
    </Alert>
  {/if}
{/if}

{#if kind !== 'none' && hasTenants}
  <section class="tt-home__figures" aria-labelledby="tt-home-figures">
    <h2 id="tt-home-figures" class="visually-hidden">{t('adminHome.tiles.title')}</h2>
    {#if figures.state === 'loading'}
      <Card padding="sm">
        <Spinner showLabel label={t('adminHome.tiles.loading')} />
      </Card>
    {:else if figures.state === 'error'}
      <Alert severity="error">
        <p>{figures.title}</p>
        <p>{figures.message}</p>
        <Button variant="secondary" small onclick={retryFigures}>{t('common.retry')}</Button>
      </Alert>
    {:else}
      <ul class="tt-home__tiles" role="list">
        {#each figures.tiles as tile (tile.id)}
          <li>
            <StatCard label={tile.label} value={tile.value} trend={tile.trend} />
          </li>
        {/each}
        <li>
          <StatCard
            class={kind === 'super' ? 'tt-home__disk' : 'tt-home__storage'}
            label={figures.gauge.label}
            value={figures.gauge.value}
            variant={figures.gauge.variant}
            hint={figures.gauge.hint}
          >
            {#if figures.gauge.gauge}
              <Gauge
                value={figures.gauge.gauge.value}
                max={figures.gauge.gauge.max}
                threshold={figures.gauge.gauge.threshold}
                level={figures.gauge.gauge.level}
                label={figures.gauge.gauge.label}
                valueText={figures.gauge.gauge.valueText}
                text={figures.gauge.text}
              />
            {:else}
              <p class="tt-home__gauge-text">{figures.gauge.text}</p>
            {/if}
          </StatCard>
        </li>
      </ul>
    {/if}
  </section>

  <div class="tt-home__columns">
    <Card title={t('adminHome.tenantsTitle')} flush class="tt-home__entities">
      {#snippet actions()}
        <ActionLink to="/tenants" {nav} variant="secondary"
          ><span aria-hidden="true">{t('adminHome.seeAll')}</span><span class="visually-hidden"
            >{t('adminHome.seeAllName')}</span
          ></ActionLink
        >
      {/snippet}
      {#if tenants.state === 'error'}
        <div class="tt-home__pad">
          <Alert severity="error">
            <p>{tenants.message}</p>
            <Button variant="secondary" small onclick={() => void loadTenants()}>{t('common.retry')}</Button>
          </Alert>
        </div>
      {:else}
        <DataTable
          variant="plain"
          caption={t('adminHome.table.caption')}
          captionHidden
          {rows}
          key={(row) => row.id}
          loading={tenants.state === 'loading'}
          emptyText={t('adminHome.table.empty')}
          columns={[
            { id: 'entity', header: t('adminHome.table.entity'), cell: entityCell, rowHeader: true },
            { id: 'status', header: t('adminHome.table.status'), cell: statusCell },
            { id: 'storage', header: t('adminHome.table.storage'), cell: storageCell },
            {
              id: 'actions',
              header: t('adminHome.table.actions'),
              cell: actionCell,
              headerHidden: true,
              align: 'end',
            },
          ]}
        />
      {/if}
    </Card>

    {#if kind === 'super'}
      <Card title={t('adminHome.system.title')} class="tt-home__side">
        {#if status.state === 'loading'}
          <Spinner showLabel label={t('adminHome.system.loading')} />
        {:else if status.state === 'error'}
          <Alert severity="error">
            <p>{t('adminHome.system.error')}</p>
            <p>{status.message}</p>
            <Button variant="secondary" small onclick={() => void loadStatus()}>{t('common.retry')}</Button>
          </Alert>
        {:else}
          <dl class="tt-home__status">
            {#each statusRows as row (row.id)}
              <div class="tt-home__status-row">
                <dt>{row.label}</dt>
                <dd>
                  {#if row.variant !== undefined}
                    <StatusBadge variant={row.variant} label={row.value} />
                  {:else}
                    <span class="tt-home__muted">{row.value}</span>
                  {/if}
                  {#if row.detail !== undefined}
                    <span class="tt-home__detail">{row.detail}</span>
                  {/if}
                </dd>
              </div>
            {/each}
          </dl>
        {/if}
        <ActionLink to={MAINTENANCE_PATH} {nav} variant="secondary" fullWidth class="tt-home__maintenance"
          >{t('adminHome.system.manageMaintenance')}</ActionLink
        >
      </Card>
    {:else if me}
      <Card title={t('adminHome.shortcuts.title')} class="tt-home__side">
        {#each me.tenants as ref (ref.id)}
          {#if me.tenants.length > 1}
            <h3 class="tt-home__shortcut-title tt-break">{ref.name}</h3>
          {/if}
          <ul class="tt-home__links" role="list">
            {#each quickLinks(ref, t, kind) as link (link.section)}
              <li><a class="tt-break" href={nav.href(link.path)} use:nav.link>{link.label}</a></li>
            {/each}
          </ul>
        {/each}
      </Card>
    {/if}
  </div>
{/if}

<style>
  .tt-home__figures {
    margin-bottom: var(--tt-space-6);
  }

  .tt-home__tiles {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(min(100%, 12.5rem), 1fr));
    gap: var(--tt-space-4);
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .tt-home__tiles > li {
    display: flex;
    min-width: 0;
  }

  .tt-home__tiles > li > :global(.tt-stat) {
    flex: 1;
  }

  .tt-home__gauge-text {
    margin: 0;
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }

  .tt-home__columns {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-start;
    gap: var(--tt-space-4);
  }

  .tt-home__columns > :global(.tt-admin-card) {
    margin-bottom: 0;
  }

  .tt-home__columns > :global(.tt-home__entities) {
    flex: 999 1 32.5rem;
  }

  .tt-home__columns > :global(.tt-home__side) {
    flex: 1 1 17.5rem;
  }

  .tt-home__pad {
    padding: 0 var(--tt-space-5) var(--tt-space-5);
  }

  .tt-home__entity {
    display: flex;
    align-items: center;
    gap: var(--tt-space-3);
    min-width: 12rem;
  }

  .tt-home__entity-text {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }

  .tt-home__entity-name {
    color: var(--tt-text);
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-home__fqdn {
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
    font-weight: var(--tt-font-weight-normal);
  }

  .tt-home__action {
    justify-content: center;
    min-width: var(--tt-control-height);
    white-space: nowrap;
  }

  .tt-home__status {
    display: flex;
    flex-direction: column;
    gap: var(--tt-space-3);
    margin: 0 0 var(--tt-space-4);
  }

  .tt-home__status-row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: var(--tt-space-1) var(--tt-space-2);
  }

  .tt-home__status dt {
    font-weight: var(--tt-font-weight-normal);
  }

  .tt-home__status dd {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: flex-end;
    gap: var(--tt-space-1) var(--tt-space-2);
    margin: 0;
    text-align: right;
  }

  .tt-home__muted,
  .tt-home__detail {
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }

  .tt-home__shortcut-title {
    margin: var(--tt-space-3) 0 0;
    font-size: var(--tt-font-size-base);
  }

  .tt-home__shortcut-title:first-child {
    margin-top: 0;
  }

  .tt-home__links {
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .tt-home__links a {
    display: inline-flex;
    align-items: center;
    min-height: var(--tt-control-height);
  }
</style>
