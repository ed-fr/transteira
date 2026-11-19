<script lang="ts">
  // Transfer search of the administration (CLAUDE.md section 13.2; plan of step 3c, deviation 3):
  // route /search, opened by the search form of the home header, with the same form. The query (a
  // transfer identifier or a complete address) comes from the in-memory searchQuery store
  // (search.svelte.ts), read once when the screen opens, and stays in the component state: never
  // in the URL nor in a browser storage (threat model T-412); the request is a POST
  // (searchTransfers). An auditor may search by identifier only: an address is refused before
  // sending (T-411).
  // - A transfer identifier matching exactly one transfer opens its detail screen (the search
  //   entry of the history is replaced, so that "back" returns to the previous page).
  // - Otherwise the results card: entity (colour swatch), identifier (link to the detail), sender,
  //   number of recipients, creation date and status, newest first; the number found is announced;
  //   when some matches are left out, the notice and, for an address, a link per entity to its
  //   transfer list filtered by the address (its existing ?email= filter).
  // - Errors: a refused query shows its message on the input (400), moving the focus there or
  //   announcing it when the input already has the focus (signalQueryError), the wait of the rate
  //   limit (429, Retry-After) or the general message otherwise.
  import { onDestroy, onMount, tick } from 'svelte';
  import { describeError } from '../../shared/api/problem';
  import { Alert, HelpIcon, announce } from '../../shared/components';
  import { formatDate, i18n, t } from '../../shared/i18n/i18n.svelte';
  import { adminApi, adminSession } from '../api';
  import Card from '../components/Card.svelte';
  import DataTable from '../components/DataTable.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import StatusBadge from '../components/StatusBadge.svelte';
  import TenantSwatch from '../components/TenantSwatch.svelte';
  import TransferSearchForm from '../components/TransferSearchForm.svelte';
  import { searchQuery } from '../search.svelte';
  import { canSearchByAddress } from '../shell';
  import {
    checkQuery,
    countText,
    directPath,
    emptyText,
    loadTenantColors,
    moreLinks,
    searchFailure,
    searchRows,
    searchTransfers,
    signalQueryError,
    type SearchResult,
    type SearchRow,
  } from './search';
  import type { AdminScreenProps } from './types';

  let { nav }: AdminScreenProps = $props();

  const title = $derived(t('admin.search.title'));
  // Searching by address is refused to an auditor (and to an unknown role).
  const auditor = $derived(!canSearchByAddress(adminSession.me?.role));
  const dateTime = (d: string): string => formatDate(d, { dateStyle: 'medium', timeStyle: 'short' });

  // The query of the home header is run once: the store is emptied, so a reload starts empty.
  const initial = searchQuery.consume();
  let query = $state(initial ?? '');
  let input = $state<HTMLInputElement | undefined>();
  let busy = $state(false);
  let fieldError = $state('');
  let generalError = $state('');
  let searched = $state.raw<{ query: string; result: SearchResult } | undefined>(undefined);
  let colors = $state.raw<ReadonlyMap<string, unknown>>(new Map());
  let colorsRequested = false;
  let generation = 0;
  let alive = true;

  const rows = $derived(searched === undefined ? [] : searchRows(searched.result, colors, t, dateTime));
  const more = $derived(searched === undefined ? [] : moreLinks(searched.result, searched.query, auditor, t));
  const found = $derived(searched?.result.items.length ?? 0);

  onDestroy(() => {
    alive = false;
  });

  /** Colours of the swatches: the first page of the tenants, once (neutral swatches on failure). */
  function requestColors(): void {
    if (colorsRequested) {
      return;
    }
    colorsRequested = true;
    void loadTenantColors(adminApi).then((map) => {
      if (alive) {
        colors = map;
      }
    });
  }

  /** Shows an error on the input and brings it to a screen reader user (signalQueryError). */
  async function showFieldError(message: string): Promise<void> {
    const active = document.activeElement;
    fieldError = message;
    await tick();
    if (alive) {
      signalQueryError(input, active, message, t, (m) => announce(m, 'assertive'));
    }
  }

  async function run(raw: string): Promise<void> {
    const check = checkQuery(raw, auditor, t);
    if (!check.ok) {
      await showFieldError(check.error);
      return;
    }
    const mine = ++generation;
    busy = true;
    fieldError = '';
    generalError = '';
    requestColors();
    try {
      const result = await searchTransfers(adminApi, check.query);
      if (!alive || mine !== generation) {
        return;
      }
      const direct = directPath(result);
      if (direct !== undefined) {
        await nav.navigate(direct, { replace: true });
        return;
      }
      searched = { query: check.query, result };
      announce(countText(result.items.length, t));
    } catch (err) {
      if (!alive || mine !== generation) {
        return;
      }
      searched = undefined;
      const failure = searchFailure(describeError(i18n, err), auditor, t);
      if ('field' in failure) {
        await showFieldError(failure.field);
      } else {
        generalError = failure.message;
      }
    } finally {
      if (alive && mine === generation) {
        busy = false;
      }
    }
  }

  onMount(() => {
    if (initial !== undefined) {
      void run(initial);
    }
  });
</script>

{#snippet entityCell(row: SearchRow)}
  <span class="tt-search-results__entity">
    <TenantSwatch color={row.color} size="sm" />
    <span class="tt-break">{row.tenantName}</span>
  </span>
{/snippet}

{#snippet transferCell(row: SearchRow)}
  <a class="tt-search-results__id" href={nav.href(row.path)} use:nav.link>{row.transferId}</a>
{/snippet}

{#snippet senderCell(row: SearchRow)}
  <span class="tt-break">{row.sender}</span>
{/snippet}

{#snippet recipientsCell(row: SearchRow)}
  <span class="tt-search-results__nowrap">{row.recipients}</span>
{/snippet}

{#snippet createdCell(row: SearchRow)}
  {row.created}
{/snippet}

{#snippet statusCell(row: SearchRow)}
  <span class="tt-search-results__status">
    <StatusBadge variant={row.statusVariant} label={row.statusLabel} />
    {#if row.e2e}
      <StatusBadge variant="info" label={t('opsTransfers.e2eBadge')} />
    {/if}
  </span>
{/snippet}

<PageHeader {title}>
  {#snippet help()}
    <HelpIcon topic="admin-search" {title} {nav} />
  {/snippet}
</PageHeader>

<Card>
  <TransferSearchForm
    {auditor}
    bind:value={query}
    bind:input
    error={fieldError}
    {busy}
    labelHidden={false}
    hint={t(auditor ? 'adminSearch.form.hintAuditor' : 'adminSearch.form.hint')}
    onsearch={run}
  />
</Card>

{#if generalError !== ''}
  <Alert severity="error">
    <p>{generalError}</p>
  </Alert>
{/if}

{#if searched !== undefined}
  <Card
    title={t('adminSearch.results.title')}
    description={found > 0 ? countText(found, t) : undefined}
    flush
    class="tt-search-results"
  >
    {#if searched.result.truncated || more.length > 0}
      <div class="tt-search-results__notice">
        <Alert severity="info" live={false}>
          {#if searched.result.truncated}
            <p>{t('adminSearch.results.truncated')}</p>
          {/if}
          {#if more.length > 0}
            <p>{t('adminSearch.results.moreIntro')}</p>
            <ul class="tt-search-results__more" role="list">
              {#each more as link (link.tenantId)}
                <li><a class="tt-break" href={nav.href(link.path)} use:nav.link>{link.label}</a></li>
              {/each}
            </ul>
          {/if}
        </Alert>
      </div>
    {/if}
    <DataTable
      variant="plain"
      caption={t('adminSearch.results.caption')}
      captionHidden
      {rows}
      key={(row) => row.key}
      emptyText={emptyText(searched.result.kind, t)}
      columns={[
        { id: 'entity', header: t('adminSearch.results.columns.entity'), cell: entityCell },
        {
          id: 'transfer',
          header: t('adminSearch.results.columns.transfer'),
          cell: transferCell,
          rowHeader: true,
        },
        { id: 'sender', header: t('adminSearch.results.columns.sender'), cell: senderCell },
        { id: 'recipients', header: t('adminSearch.results.columns.recipients'), cell: recipientsCell },
        { id: 'created', header: t('adminSearch.results.columns.created'), cell: createdCell },
        { id: 'status', header: t('adminSearch.results.columns.status'), cell: statusCell },
      ]}
    />
  </Card>
{/if}

<style>
  .tt-search-results__notice {
    padding: 0 var(--tt-space-5) var(--tt-space-4);
  }

  .tt-search-results__more {
    margin: var(--tt-space-1) 0 0;
    padding: 0;
    list-style: none;
  }

  .tt-search-results__more a {
    display: inline-flex;
    align-items: center;
    min-height: var(--tt-control-height);
  }

  .tt-search-results__entity {
    display: inline-flex;
    align-items: center;
    gap: var(--tt-space-2);
    min-width: 8rem;
  }

  .tt-search-results__id {
    font-family: var(--tt-font-mono);
    font-size: var(--tt-font-size-sm);
    white-space: nowrap;
  }

  .tt-search-results__nowrap {
    white-space: nowrap;
  }

  .tt-search-results__status {
    display: inline-flex;
    flex-wrap: wrap;
    gap: var(--tt-space-1);
  }
</style>
