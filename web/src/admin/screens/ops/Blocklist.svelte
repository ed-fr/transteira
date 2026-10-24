<script lang="ts">
  // Blocklist of a tenant (CLAUDE.md section 15.2; /admin/tenants/{id}/blocklist): email
  // addresses and domains that can no longer deposit, SHA-256 digests of refused files.
  // - add form: kind, value (checked per kind, hint per kind) and optional comment; the new
  //   entry, as normalised by the server, comes first in the list and the form is reset; a value
  //   already listed (409 already-exists) is reported on the value field;
  // - list filtered by kind (reflected in the URL query string): value, kind, comment, author,
  //   date, and a remove action after confirmation.
  // The tenant sub-navigation is rendered by App.svelte.
  import { tick, untrack } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, TextArea, TextField, announce } from '../../../shared/components';
  import { formatDate, i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import ConfirmDialog from '../../components/ConfirmDialog.svelte';
  import DataTable from '../../components/DataTable.svelte';
  import FilterBar from '../../components/FilterBar.svelte';
  import FormSection from '../../components/FormSection.svelte';
  import SelectField from '../../components/SelectField.svelte';
  import { errorFor, type SubmitOutcome, type SummaryError } from '../../components/form';
  import type { AdminScreenProps } from '../types';
  import {
    afterDelete,
    COMMENT_MAX_LENGTH,
    createErrorOutcome,
    emptyForm,
    entryBody,
    kindFilterOptions,
    kindLabel,
    kindOptions,
    loadedText,
    prependEntry,
    validateEntry,
    valueHint,
    VALUE_MAX_LENGTH,
    type BlocklistEntry,
    type BlocklistForm,
    type BlocklistKind,
  } from './blocklist';
  import {
    BLOCKLIST_FILTERS,
    filtersToApiParams,
    filtersToForm,
    formToFilters,
    isEmpty,
    parseFilters,
    pathWithFilters,
  } from './filters';
  import { emptyList, receiveError, receivePage, startMore, startReset, type PagedList } from './paging';

  const { params, nav }: AdminScreenProps = $props();

  const uid = $props.id();
  const ids = { kind: `${uid}-kind`, value: `${uid}-value`, comment: `${uid}-comment` };

  const tenantId = $derived(params['id'] ?? '');
  const filters = $derived(parseFilters(BLOCKLIST_FILTERS, nav.current.search));

  let list = $state.raw<PagedList<BlocklistEntry>>(emptyList());
  let filterKind = $state('');
  let kind = $state<string>(emptyForm().kind);
  let value = $state('');
  let comment = $state('');
  let errors = $state<SummaryError[]>([]);
  let target = $state.raw<BlocklistEntry | undefined>(undefined);
  let confirmOpen = $state(false);
  let deleted = false;
  let heading: HTMLHeadingElement | undefined = $state();

  const fields = $derived({
    kind: { id: ids.kind, label: t('opsBlocklist.form.kind') },
    value: { id: ids.value, label: t('opsBlocklist.form.value') },
    comment: { id: ids.comment, label: t('opsBlocklist.form.comment') },
  });
  // The kind select only offers the BlocklistKind values.
  const form = $derived<BlocklistForm>({ kind: kind as BlocklistKind, value, comment });
  const hasInput = $derived(value.trim() !== '' || comment.trim() !== '');
  const loadError = $derived(!list.loaded && typeof list.error === 'string' ? list.error : '');
  const moreError = $derived(list.loaded && typeof list.error === 'string' ? list.error : '');
  const resultText = $derived(
    list.loaded ? loadedText(list.items.length, list.nextCursor !== null, t) : undefined,
  );

  const when = (iso: string): string => formatDate(iso, { dateStyle: 'medium', timeStyle: 'short' });

  async function fetchPage(cursor?: string): Promise<{ items: BlocklistEntry[]; nextCursor?: string }> {
    const res = await adminApi.get('/admin/tenants/{tenantId}/blocklist', {
      path: { tenantId },
      params: filtersToApiParams(BLOCKLIST_FILTERS, filters, { cursor }),
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

  // Filters (and the tenant) come from the route: the filter form follows them and the list reloads.
  $effect(() => {
    void tenantId;
    const values = filtersToForm(BLOCKLIST_FILTERS, filters);
    untrack(() => {
      filterKind = values.kind;
      void reload();
    });
  });

  async function apply(): Promise<boolean> {
    const next = formToFilters(BLOCKLIST_FILTERS, { kind: filterKind });
    if (next === undefined) {
      return false;
    }
    await nav.navigate(pathWithFilters(nav.current.path, BLOCKLIST_FILTERS, next));
    return true;
  }

  async function clear(): Promise<void> {
    filterKind = '';
    await nav.navigate(pathWithFilters(nav.current.path, BLOCKLIST_FILTERS, {}));
  }

  async function add(): Promise<SubmitOutcome> {
    const body = entryBody(form);
    if (body === undefined) {
      return { ok: false, errors: validateEntry(form, fields, t) };
    }
    try {
      const res = await adminApi.post('/admin/tenants/{tenantId}/blocklist', { path: { tenantId }, body });
      list = prependEntry(list, res.data, filters);
      value = '';
      comment = '';
      return { ok: true, message: t('opsBlocklist.form.added', { value: res.data.value }) };
    } catch (err) {
      return createErrorOutcome(describeError(i18n, err), fields, t);
    }
  }

  function askDelete(row: BlocklistEntry): void {
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
      await adminApi.delete('/admin/tenants/{tenantId}/blocklist/{entryId}', {
        path: { tenantId, entryId: row.id },
      });
    } catch (err) {
      const view = describeError(i18n, err);
      // 404: already removed (by another admin); the row leaves the list all the same.
      if (view.status !== 404) {
        return view.message;
      }
    }
    list = afterDelete(list, row.id);
    deleted = true;
    announce(t('opsBlocklist.delete.done', { value: row.value }));
  }

  async function closed(): Promise<void> {
    // The row and its remove button are gone: the focus goes back to the page heading.
    if (deleted) {
      deleted = false;
      await tick();
      heading?.focus();
    }
  }
</script>

{#snippet valueCell(row: BlocklistEntry)}
  <span class="tt-break" class:tt-blocklist__digest={row.kind === 'sha256'}>{row.value}</span>
{/snippet}

{#snippet kindCell(row: BlocklistEntry)}
  {kindLabel(row.kind, t)}
{/snippet}

{#snippet commentCell(row: BlocklistEntry)}
  <span class="tt-break">{row.comment ?? ''}</span>
{/snippet}

{#snippet createdByCell(row: BlocklistEntry)}
  <span class="tt-break">{row.createdBy}</span>
{/snippet}

{#snippet createdAtCell(row: BlocklistEntry)}
  {when(row.createdAt)}
{/snippet}

{#snippet actionsCell(row: BlocklistEntry)}
  <Button
    variant="secondary"
    aria-label={t('opsBlocklist.delete.buttonFor', { value: row.value })}
    onclick={() => askDelete(row)}
  >
    {t('opsBlocklist.delete.button')}
  </Button>
{/snippet}

<h1 tabindex="-1" bind:this={heading}>{t('adminOps.blocklist.title')}</h1>
<p>{t('adminOps.blocklist.intro')}</p>

<FormSection
  title={t('opsBlocklist.form.title')}
  intro={t('opsBlocklist.form.intro')}
  dirty={hasInput ? true : undefined}
  addGuard={(guard) => nav.addGuard(guard)}
  validate={() => validateEntry(form, fields, t)}
  onsubmit={add}
  saveLabel={t('opsBlocklist.form.submit')}
  savingLabel={t('opsBlocklist.form.submitting')}
  bind:errors
>
  <SelectField
    id={ids.kind}
    label={t('opsBlocklist.form.kind')}
    options={kindOptions(t)}
    bind:value={kind}
    required
    error={errorFor(errors, ids.kind)}
  />
  <TextField
    id={ids.value}
    label={t('opsBlocklist.form.value')}
    hint={valueHint(form.kind, t)}
    bind:value
    required
    maxlength={VALUE_MAX_LENGTH}
    autocomplete="off"
    spellcheck={false}
    error={errorFor(errors, ids.value)}
  />
  <TextArea
    id={ids.comment}
    label={t('opsBlocklist.form.comment')}
    hint={t('opsBlocklist.form.commentHint')}
    bind:value={comment}
    maxlength={COMMENT_MAX_LENGTH}
    rows={3}
    error={errorFor(errors, ids.comment)}
  />
</FormSection>

<FilterBar
  label={t('opsBlocklist.filters.label')}
  onapply={apply}
  onreset={clear}
  busy={list.loading && !list.loaded}
  {resultText}
>
  <SelectField
    label={t('opsBlocklist.filters.kind')}
    options={kindFilterOptions(t)}
    bind:value={filterKind}
  />
</FilterBar>

{#if loadError !== ''}
  <Alert severity="error">
    <p>{loadError}</p>
    <Button variant="secondary" onclick={() => void reload()}>{t('common.retry')}</Button>
  </Alert>
{:else}
  <DataTable
    caption={t('opsBlocklist.caption')}
    captionHidden
    rows={list.items}
    key={(row) => row.id}
    loading={list.loading && !list.loaded}
    emptyText={isEmpty(filters) ? t('opsBlocklist.empty') : t('opsBlocklist.emptyFiltered')}
    nextCursor={list.nextCursor}
    onloadmore={loadMore}
    columns={[
      { id: 'value', header: t('opsBlocklist.columns.value'), cell: valueCell, rowHeader: true },
      { id: 'kind', header: t('opsBlocklist.columns.kind'), cell: kindCell },
      { id: 'comment', header: t('opsBlocklist.columns.comment'), cell: commentCell },
      { id: 'createdBy', header: t('opsBlocklist.columns.createdBy'), cell: createdByCell },
      { id: 'createdAt', header: t('opsBlocklist.columns.createdAt'), cell: createdAtCell },
      {
        id: 'actions',
        header: t('opsBlocklist.columns.actions'),
        cell: actionsCell,
        headerHidden: true,
      },
    ]}
  />
  {#if moreError !== ''}
    <Alert severity="error">{moreError}</Alert>
  {/if}
{/if}

<ConfirmDialog
  bind:open={confirmOpen}
  title={t('opsBlocklist.delete.title')}
  text={t('opsBlocklist.delete.text', { value: target?.value ?? '' })}
  confirmLabel={t('opsBlocklist.delete.confirm')}
  busyLabel={t('opsBlocklist.delete.busy')}
  danger
  onconfirm={remove}
  onclose={() => void closed()}
/>

<style>
  .tt-blocklist__digest {
    font-family: var(--tt-font-mono);
    font-size: var(--tt-font-size-sm);
  }
</style>
