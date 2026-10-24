<script lang="ts">
  // Transfers of a tenant (GET /admin/tenants/{id}/transfers, most recent first, page by page
  // with the cursor), filtered by status, address (sender or recipient) and creation day. The
  // filters live in the URL query string (bookmarkable, restored by the back button): the screen
  // is kept when only the query changes, so the list reloads when the filter query changes. The
  // date column links to the detail screen. The tenant sub-navigation is rendered by App.svelte.
  import { untrack } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, TextField } from '../../../shared/components';
  import { formatDate, formatNumber, i18n, locale, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import DataTable from '../../components/DataTable.svelte';
  import FilterBar from '../../components/FilterBar.svelte';
  import SelectField from '../../components/SelectField.svelte';
  import StatusBadge from '../../components/StatusBadge.svelte';
  import { formatBytes as formatBinaryBytes } from '../../forms/bytes';
  import type { AdminScreenProps } from '../types';
  import {
    EMAIL_MAX_LENGTH,
    TRANSFER_FILTERS,
    filtersToApiParams,
    filtersToForm,
    isEmpty,
    parseFilters,
  } from './filters';
  import { emptyList, receiveError, receivePage, startMore, startReset, type PagedList } from './paging';
  import {
    dateOr,
    detailPath,
    filesText,
    originLabel,
    recipientsSummary,
    resultText,
    statusOptions,
    statusView,
    submitFilters,
    type TransferFilterField,
    type TransferFilterForm,
    type TransferSummary,
  } from './transfers';

  let { params, nav }: AdminScreenProps = $props();

  const tenantId = $derived(params['id'] ?? '');
  const formatBytes = (n: number): string => formatBinaryBytes(n, locale.current);
  const dateTime = (d: string): string => formatDate(d, { dateStyle: 'medium', timeStyle: 'short' });

  const filters = $derived(parseFilters(TRANSFER_FILTERS, nav.current.search));

  let form = $state<TransferFilterForm>(filtersToForm(TRANSFER_FILTERS, {}));
  let errors = $state<Partial<Record<TransferFilterField, string>>>({});
  let statusInput = $state<HTMLSelectElement | undefined>();
  let emailInput = $state<HTMLInputElement | undefined>();
  let dateInput = $state<HTMLInputElement | undefined>();
  let list = $state.raw<PagedList<TransferSummary>>(emptyList());

  const loadError = $derived(!list.loaded && typeof list.error === 'string' ? list.error : '');
  const moreError = $derived(list.loaded && typeof list.error === 'string' ? list.error : '');
  const summary = $derived(
    list.loaded ? resultText(list.items.length, list.nextCursor !== null, t) : undefined,
  );

  async function reload(): Promise<void> {
    list = startReset(list);
    const generation = list.generation;
    try {
      const res = await adminApi.get('/admin/tenants/{tenantId}/transfers', {
        path: { tenantId },
        params: filtersToApiParams(TRANSFER_FILTERS, filters),
      });
      list = receivePage(list, generation, res.data);
    } catch (err) {
      list = receiveError(list, generation, describeError(i18n, err).message);
    }
  }

  async function loadMore(): Promise<void> {
    const next = startMore(list);
    if (next === list || list.nextCursor === null) {
      return;
    }
    const cursor = list.nextCursor;
    list = next;
    const generation = list.generation;
    try {
      const res = await adminApi.get('/admin/tenants/{tenantId}/transfers', {
        path: { tenantId },
        params: filtersToApiParams(TRANSFER_FILTERS, filters, { cursor }),
      });
      list = receivePage(list, generation, res.data);
    } catch (err) {
      list = receiveError(list, generation, describeError(i18n, err).message);
    }
  }

  // Filters (and the tenant) come from the route: a change (apply, reset, back button) refills
  // the form and reloads the list. Navigating to the same URL reloads as well.
  $effect(() => {
    void tenantId;
    const current = filters;
    untrack(() => {
      form = filtersToForm(TRANSFER_FILTERS, current);
      errors = {};
      void reload();
    });
  });

  async function apply(): Promise<boolean> {
    const outcome = submitFilters(nav.current.path, form, t);
    if (!outcome.ok) {
      errors = outcome.errors;
      const first = { status: statusInput, email: emailInput, createdAfter: dateInput }[outcome.first];
      first?.focus();
      return false;
    }
    errors = {};
    await nav.navigate(outcome.path);
    return true;
  }

  async function reset(): Promise<void> {
    errors = {};
    await nav.navigate(nav.current.path);
  }
</script>

{#snippet dateCell(row: TransferSummary)}
  <a href={nav.href(detailPath(tenantId, row.id))} use:nav.link>
    {dateTime(row.createdAt)}<span class="visually-hidden">
      — {t('opsTransfers.list.openLabel', { sender: row.senderEmail })}</span
    >
  </a>
{/snippet}

{#snippet senderCell(row: TransferSummary)}
  <span class="tt-break">{row.senderEmail}</span>
{/snippet}

{#snippet recipientsCell(row: TransferSummary)}
  <span class="tt-break">{recipientsSummary(row.recipients, t).text}</span>
{/snippet}

{#snippet filesCell(row: TransferSummary)}
  {filesText(row.fileCount, row.totalBytes, t, formatBytes)}
{/snippet}

{#snippet statusCell(row: TransferSummary)}
  {@const view = statusView(row.status, t)}
  <StatusBadge variant={view.variant} label={view.label} />
{/snippet}

{#snippet originCell(row: TransferSummary)}
  {originLabel(row.origin, t)}
{/snippet}

{#snippet downloadsCell(row: TransferSummary)}
  {formatNumber(row.downloadCount)}
{/snippet}

{#snippet expiryCell(row: TransferSummary)}
  {dateOr(row.expiresAt, t('opsTransfers.list.noExpiry'), dateTime)}
{/snippet}

<h1 tabindex="-1">{t('adminOps.transfers.title')}</h1>
<p>{t('adminOps.transfers.intro')}</p>

<FilterBar
  label={t('opsTransfers.list.filtersLabel')}
  onapply={apply}
  onreset={reset}
  busy={list.loading && !list.loaded}
  resultText={summary}
>
  <SelectField
    label={t('opsTransfers.list.status')}
    options={statusOptions(t)}
    bind:value={form.status}
    error={errors.status}
    bind:element={statusInput}
  />
  <TextField
    label={t('opsTransfers.list.email')}
    hint={t('opsTransfers.list.emailHint')}
    type="email"
    autocomplete="off"
    spellcheck={false}
    maxlength={EMAIL_MAX_LENGTH}
    bind:value={form.email}
    error={errors.email}
    bind:element={emailInput}
  />
  <TextField
    label={t('opsTransfers.list.createdAfter')}
    hint={t('opsTransfers.list.createdAfterHint')}
    type="date"
    bind:value={form.createdAfter}
    error={errors.createdAfter}
    bind:element={dateInput}
  />
</FilterBar>

{#if loadError !== ''}
  <Alert severity="error">
    <p>{loadError}</p>
    <Button variant="secondary" onclick={() => void reload()}>{t('common.retry')}</Button>
  </Alert>
{:else}
  <DataTable
    caption={t('opsTransfers.list.caption')}
    captionHidden
    rows={list.items}
    key={(row) => row.id}
    loading={list.loading && !list.loaded}
    emptyText={isEmpty(filters) ? t('opsTransfers.list.empty') : t('opsTransfers.list.emptyFiltered')}
    nextCursor={list.nextCursor}
    onloadmore={loadMore}
    columns={[
      { id: 'date', header: t('opsTransfers.list.columns.date'), cell: dateCell, rowHeader: true },
      { id: 'sender', header: t('opsTransfers.list.columns.sender'), cell: senderCell },
      { id: 'recipients', header: t('opsTransfers.list.columns.recipients'), cell: recipientsCell },
      { id: 'files', header: t('opsTransfers.list.columns.files'), cell: filesCell },
      { id: 'status', header: t('opsTransfers.list.columns.status'), cell: statusCell },
      { id: 'origin', header: t('opsTransfers.list.columns.origin'), cell: originCell },
      {
        id: 'downloads',
        header: t('opsTransfers.list.columns.downloads'),
        cell: downloadsCell,
        align: 'end',
      },
      { id: 'expiry', header: t('opsTransfers.list.columns.expiry'), cell: expiryCell },
    ]}
  />
  {#if moreError !== ''}
    <Alert severity="error">{moreError}</Alert>
  {/if}
{/if}
