<script lang="ts">
  // One-time secrets of a tenant (GET /admin/tenants/{id}/secrets; since 2.1, CLAUDE.md section
  // 22.1), most recent first, page by page with the cursor, filtered by state and creator
  // address (not for an auditor: 403 read-only-role). Metadata only: the text, the file and the
  // link of a secret are never available. A delegated admin or the super admin can delete a
  // pending or active secret after a confirmation; the auditor only reads. The filters live in
  // the URL query string, like the transfer list. The tenant navigation is in the
  // sidebar (SidebarTenantBlock of AdminShell).
  // Since 2.3 (express secrets, CLAUDE.md section 22.2): express secrets carry an "Express"
  // marker and the creator kind "Anonymous" (no creator address), and a field finds a secret
  // from its pasted link (POST …/secrets/lookup, also for an auditor: read only). The link goes
  // only in the body, without its "#k=" key part, is cleared from the field after the search and
  // is never kept (T-408); the result shows the metadata of the list row. Each row shows the
  // identifier (sec_…) under its creation date, in small monospace text, so that the secret of an
  // abuse report (which only gives that identifier) can be found in the list.
  import { tick, untrack } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, HelpIcon, TextField, announce } from '../../../shared/components';
  import { formatDate, i18n, locale, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi, adminSession } from '../../api';
  import Card from '../../components/Card.svelte';
  import PageHeader from '../../components/PageHeader.svelte';
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
    creatorText,
    dateOr,
    deliveryText,
    isExpress,
    lookupErrorMessage,
    lookupInput,
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

  // Lookup from a link (the typed link is never kept after the search).
  const uid = $props.id();
  let lookupText = $state('');
  let lookupError = $state('');
  let lookupBusy = $state(false);
  let found = $state.raw<AdminSecret | undefined>(undefined);
  let lookupInputEl = $state<HTMLInputElement | undefined>();
  let foundHeading = $state<HTMLHeadingElement | undefined>();

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
    if (found?.id === row.id) {
      found = { ...found, state: 'deleted' };
    }
    deleted = true;
    announce(t('adminSecrets.delete.done'));
  }

  async function lookup(): Promise<boolean> {
    if (lookupBusy) {
      return false;
    }
    found = undefined;
    const input = lookupInput(lookupText, t);
    if (!input.ok) {
      lookupError = input.message;
      lookupInputEl?.focus();
      return false;
    }
    lookupError = '';
    lookupBusy = true;
    // The link leaves the field as soon as it is sent.
    lookupText = '';
    try {
      const res = await adminApi.post('/admin/tenants/{tenantId}/secrets/lookup', {
        path: { tenantId },
        body: input.body,
      });
      found = res.data;
      announce(t('adminSecrets.lookup.found'));
      await tick();
      foundHeading?.focus();
    } catch (err) {
      lookupError = lookupErrorMessage(describeError(i18n, err), t);
      lookupInputEl?.focus();
    } finally {
      lookupBusy = false;
    }
    return true;
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
  <span class="tt-secretlist__id"
    ><span class="visually-hidden">{t('adminSecrets.list.idLabel')} </span><code>{row.id}</code></span
  >
{/snippet}

{#snippet creatorCell(row: AdminSecret)}
  {#if row.senderEmail !== undefined}<span class="tt-break">{row.senderEmail}</span>{/if}
  <span class="tt-secretlist__sub">{creatorKindLabel(row.creatorKind, t)}</span>
  {#if isExpress(row)}
    <StatusBadge variant="info" label={t('adminSecrets.list.express')} />
  {/if}
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
      aria-label={t('adminSecrets.delete.buttonFor', { creator: creatorText(row, t) })}
      onclick={() => askDelete(row)}
    >
      {t('adminSecrets.delete.button')}
    </Button>
  {/if}
{/snippet}

<PageHeader
  title={t('adminOps.secrets.title')}
  description={t(readOnly ? 'adminOps.secrets.introReadOnly' : 'adminOps.secrets.intro')}
  bind:element={heading}
>
  {#snippet help()}
    <HelpIcon topic="tenant-secrets" title={t('adminOps.secrets.title')} {nav} />
  {/snippet}
</PageHeader>

<Card tag="div">
  <form
    class="tt-secretlist__lookup"
    aria-labelledby="{uid}-lookup-title"
    onsubmit={(e) => {
      e.preventDefault();
      void lookup();
    }}
  >
    <h2 class="tt-text-lg" id="{uid}-lookup-title">{t('adminSecrets.lookup.title')}</h2>
    <p class="tt-text-sm tt-text-muted">{t('adminSecrets.lookup.intro')}</p>
    <TextField
      id="{uid}-lookup"
      label={t('adminSecrets.lookup.label')}
      hint={t('adminSecrets.lookup.hint')}
      autocomplete="off"
      autocapitalize="off"
      spellcheck={false}
      maxlength={2048}
      bind:value={lookupText}
      error={lookupError === '' ? undefined : lookupError}
      bind:element={lookupInputEl}
    />
    <Button
      type="submit"
      variant="secondary"
      loading={lookupBusy}
      loadingLabel={t('adminSecrets.lookup.busy')}
    >
      {t('adminSecrets.lookup.button')}
    </Button>
  </form>
</Card>

{#if found !== undefined}
  {@const view = secretStateView(found.state, t)}
  <Card tag="div">
    <section class="tt-secretlist__found" id="{uid}-found" aria-labelledby="{uid}-found-title">
      <h2 class="tt-text-lg" id="{uid}-found-title" tabindex="-1" bind:this={foundHeading}>
        {t('adminSecrets.lookup.result.title')}
      </h2>
      <dl class="tt-dl">
        <dt>{t('adminSecrets.lookup.result.id')}</dt>
        <dd class="tt-break"><code>{found.id}</code></dd>
        <dt>{t('adminSecrets.lookup.result.kind')}</dt>
        <dd>
          {t(isExpress(found) ? 'adminSecrets.lookup.result.express' : 'adminSecrets.lookup.result.standard')}
        </dd>
        <dt>{t('adminSecrets.list.columns.state')}</dt>
        <dd><StatusBadge variant={view.variant} label={view.label} /></dd>
        <dt>{t('adminSecrets.list.columns.creator')}</dt>
        <dd class="tt-break">
          {#if found.senderEmail !== undefined}{found.senderEmail}<br />{/if}
          {creatorKindLabel(found.creatorKind, t)}
        </dd>
        <dt>{t('adminSecrets.list.columns.delivery')}</dt>
        <dd class="tt-break">{deliveryText(found, t)}</dd>
        <dt>{t('adminSecrets.list.columns.file')}</dt>
        <dd>
          {found.hasFile
            ? found.fileSize === undefined
              ? t('adminSecrets.list.file.yes')
              : formatBytes(found.fileSize)
            : t('adminSecrets.list.file.no')}
        </dd>
        <dt>{t('adminSecrets.list.columns.created')}</dt>
        <dd>{dateTime(found.createdAt)}</dd>
        <dt>{t('adminSecrets.list.columns.expiry')}</dt>
        <dd>{dateOr(found.expiresAt, t('adminSecrets.list.noExpiry'), dateTime)}</dd>
        <dt>{t('adminSecrets.list.columns.read')}</dt>
        <dd>{dateOr(found.readAt, t('adminSecrets.list.notRead'), dateTime)}</dd>
      </dl>
      {#if !readOnly && canDeleteSecret(found.state)}
        <Button variant="secondary" onclick={() => found !== undefined && askDelete(found)}>
          {t('adminSecrets.delete.button')}
        </Button>
      {/if}
    </section>
  </Card>
{/if}

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
  text={t('adminSecrets.delete.text', {
    creator: target === undefined ? '' : creatorText(target, t),
  })}
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

  .tt-secretlist__id {
    display: block;
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
    overflow-wrap: anywhere;
  }

  .tt-secretlist__id code {
    color: inherit;
    font-size: inherit;
  }
</style>
