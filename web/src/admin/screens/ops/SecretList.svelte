<script lang="ts">
  // One-time secrets of a tenant (GET /admin/tenants/{id}/secrets; since 2.1, CLAUDE.md section
  // 22.1), most recent first, page by page with the cursor, filtered by state and creator
  // address (not for an auditor: 403 read-only-role). Metadata only: the text, the file and the
  // link of a secret are never available. A delegated admin or the super admin can delete a
  // pending or active secret after a confirmation; the auditor only reads. The filters live in
  // the URL query string, like the transfer list. The tenant sub-navigation is rendered by
  // App.svelte.
  import { tick, untrack } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, HelpIcon, TextField, announce } from '../../../shared/components';
  import { formatDate, i18n, locale, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi, adminSession } from '../../api';
  import ConfirmDialog from '../../components/ConfirmDialog.svelte';
  import DataTable from '../../components/DataTable.svelte';
  import FilterBar from '../../components/FilterBar.svelte';
  import SelectField from '../../components/SelectField.svelte';
  import StatusBadge from '../../components/StatusBadge.svelte';
  import { formatBytes as formatBinaryBytes } from '../../forms/bytes';
  import { canSearchByAddress, isAuditor } from '../../shell';
  import type { AdminScreenProps } from '../types';
  import {
    EMAIL_MAX_LENGTH,
    SECRET_FILTERS,
    dropFilter,
    filtersToApiParams,
    filtersToForm,
    isEmpty,
    parseFilters,
  } from './filters';
  import { emptyList, receiveError, receivePage, startMore, startReset, type PagedList } from './paging';
  import {
    afterSecretDelete,
    canDeleteSecret,
    creatorKindLabel,
    dateOr,
    deliveryText,
    secretStateOptions,
    secretStateView,
    secretsResultText,
    submitSecretFilters,
    type AdminSecret,
    type SecretFilterField,
    type SecretFilterForm,
  } from './secrets';

  const { params, nav }: AdminScreenProps = $props();

  const tenantId = $derived(params['id'] ?? '');
  const readOnly = $derived(isAuditor(adminSession.me?.role));
  const dateTime = (d: string): string => formatDate(d, { dateStyle: 'medium', timeStyle: 'short' });
  const formatBytes = (n: number): string => formatBinaryBytes(n, locale.current);

  // An auditor may not search by address: no input, and a sender filter of the URL is ignored.
  const byAddress = $derived(canSearchByAddress(adminSession.me?.role));
  const filters = $derived(
    dropFilter(parseFilters(SECRET_FILTERS, nav.current.search), 'sender', !byAddress),
  );

  let form = $state<SecretFilterForm>(filtersToForm(SECRET_FILTERS, {}));
  let errors = $state<Partial<Record<SecretFilterField, string>>>({});
  let stateInput = $state<HTMLSelectElement | undefined>();
  let senderInput = $state<HTMLInputElement | undefined>();
  let list = $state.raw<PagedList<AdminSecret>>(emptyList());
  let target = $state.raw<AdminSecret | undefined>(undefined);
  let confirmOpen = $state(false);
  let deleted = false;
  let heading = $state<HTMLHeadingElement | undefined>();

  const loadError = $derived(!list.loaded && typeof list.error === 'string' ? list.error : '');
  const moreError = $derived(list.loaded && typeof list.error === 'string' ? list.error : '');
  const summary = $derived(
    list.loaded ? secretsResultText(list.items.length, list.nextCursor !== null, t) : undefined,
  );

  async function fetchPage(cursor?: string): Promise<{ items: AdminSecret[]; nextCursor?: string }> {
    const res = await adminApi.get('/admin/tenants/{tenantId}/secrets', {
      path: { tenantId },
      params: filtersToApiParams(SECRET_FILTERS, filters, cursor === undefined ? {} : { cursor }),
    });
    return res.data;
  }

  async function reload(): Promise<void> {
    list = startReset(list);
    const generation = list.generation;
    try {
      list = receivePage(list, generation, await fetchPage());
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
      list = receivePage(list, generation, await fetchPage(cursor));
    } catch (err) {
      list = receiveError(list, generation, describeError(i18n, err).message);
    }
  }

  // Filters (and the tenant) come from the route: a change refills the form and reloads.
  $effect(() => {
    void tenantId;
    const current = filters;
    untrack(() => {
      form = filtersToForm(SECRET_FILTERS, current);
      errors = {};
      void reload();
    });
  });

  async function apply(): Promise<boolean> {
    const outcome = submitSecretFilters(nav.current.path, form, t);
    if (!outcome.ok) {
      errors = outcome.errors;
      ({ state: stateInput, sender: senderInput })[outcome.first]?.focus();
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

  function askDelete(row: AdminSecret): void {
    target = row;
    deleted = false;
    confirmOpen = true;
  }

  async function remove(): Promise<string | void> {
    const row = target;
    if (row === undefined) {
      return;
    }
    try {
      await adminApi.delete('/admin/tenants/{tenantId}/secrets/{secretId}', {
        path: { tenantId, secretId: row.id },
      });
    } catch (err) {
      const view = describeError(i18n, err);
      if (view.status !== 404) {
        return view.message;
      }
    }
    list = afterSecretDelete(list, row.id, filters, new Date().toISOString());
    deleted = true;
    announce(t('adminSecrets.delete.done'));
  }

  async function closed(): Promise<void> {
    // The delete button of the row is gone: the focus goes back to the page heading.
    if (deleted) {
      deleted = false;
      await tick();
      heading?.focus();
    }
  }
</script>

{#snippet createdCell(row: AdminSecret)}
  {dateTime(row.createdAt)}
{/snippet}

{#snippet creatorCell(row: AdminSecret)}
  <span class="tt-break">{row.senderEmail}</span>
  <span class="tt-secretlist__sub">{creatorKindLabel(row.creatorKind, t)}</span>
{/snippet}

{#snippet deliveryCell(row: AdminSecret)}
  <span class="tt-break">{deliveryText(row, t)}</span>
{/snippet}

{#snippet fileCell(row: AdminSecret)}
  {row.hasFile
    ? row.fileSize === undefined
      ? t('adminSecrets.list.file.yes')
      : formatBytes(row.fileSize)
    : t('adminSecrets.list.file.no')}
{/snippet}

{#snippet stateCell(row: AdminSecret)}
  {@const view = secretStateView(row.state, t)}
  <StatusBadge variant={view.variant} label={view.label} />
{/snippet}

{#snippet expiryCell(row: AdminSecret)}
  {dateOr(row.expiresAt, t('adminSecrets.list.noExpiry'), dateTime)}
{/snippet}

{#snippet readCell(row: AdminSecret)}
  {dateOr(row.readAt, t('adminSecrets.list.notRead'), dateTime)}
{/snippet}

{#snippet actionsCell(row: AdminSecret)}
  {#if canDeleteSecret(row.state)}
    <Button
      variant="secondary"
      aria-label={t('adminSecrets.delete.buttonFor', { creator: row.senderEmail })}
      onclick={() => askDelete(row)}
    >
      {t('adminSecrets.delete.button')}
    </Button>
  {/if}
{/snippet}

<div class="tt-title-row">
  <h1 tabindex="-1" bind:this={heading}>{t('adminOps.secrets.title')}</h1>
  <HelpIcon topic="tenant-secrets" title={t('adminOps.secrets.title')} {nav} />
</div>
<p>{t(readOnly ? 'adminOps.secrets.introReadOnly' : 'adminOps.secrets.intro')}</p>

<FilterBar
  label={t('adminSecrets.list.filtersLabel')}
  onapply={apply}
  onreset={reset}
  busy={list.loading && !list.loaded}
  resultText={summary}
>
  <SelectField
    label={t('adminSecrets.list.state')}
    options={secretStateOptions(t)}
    bind:value={form.state}
    error={errors.state}
    bind:element={stateInput}
  />
  {#if byAddress}
    <TextField
      label={t('adminSecrets.list.sender')}
      hint={t('adminSecrets.list.senderHint')}
      type="email"
      autocomplete="off"
      spellcheck={false}
      maxlength={EMAIL_MAX_LENGTH}
      bind:value={form.sender}
      error={errors.sender}
      bind:element={senderInput}
    />
  {/if}
</FilterBar>

{#if loadError !== ''}
  <Alert severity="error">
    <p>{loadError}</p>
    <Button variant="secondary" onclick={() => void reload()}>{t('common.retry')}</Button>
  </Alert>
{:else}
  <DataTable
    caption={t('adminSecrets.list.caption')}
    captionHidden
    rows={list.items}
    key={(row) => row.id}
    loading={list.loading && !list.loaded}
    emptyText={isEmpty(filters) ? t('adminSecrets.list.empty') : t('adminSecrets.list.emptyFiltered')}
    nextCursor={list.nextCursor}
    onloadmore={loadMore}
    columns={[
      { id: 'created', header: t('adminSecrets.list.columns.created'), cell: createdCell, rowHeader: true },
      { id: 'creator', header: t('adminSecrets.list.columns.creator'), cell: creatorCell },
      { id: 'delivery', header: t('adminSecrets.list.columns.delivery'), cell: deliveryCell },
      { id: 'file', header: t('adminSecrets.list.columns.file'), cell: fileCell },
      { id: 'state', header: t('adminSecrets.list.columns.state'), cell: stateCell },
      { id: 'expiry', header: t('adminSecrets.list.columns.expiry'), cell: expiryCell },
      { id: 'read', header: t('adminSecrets.list.columns.read'), cell: readCell },
      ...(readOnly
        ? []
        : [
            {
              id: 'actions',
              header: t('adminSecrets.list.columns.actions'),
              cell: actionsCell,
              headerHidden: true,
            },
          ]),
    ]}
  />
  {#if moreError !== ''}
    <Alert severity="error">{moreError}</Alert>
  {/if}
{/if}

<ConfirmDialog
  bind:open={confirmOpen}
  title={t('adminSecrets.delete.title')}
  text={t('adminSecrets.delete.text', { creator: target?.senderEmail ?? '' })}
  confirmLabel={t('adminSecrets.delete.confirm')}
  busyLabel={t('adminSecrets.delete.busy')}
  danger
  onconfirm={remove}
  onclose={() => void closed()}
/>

<style>
  .tt-secretlist__sub {
    display: block;
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }
</style>
