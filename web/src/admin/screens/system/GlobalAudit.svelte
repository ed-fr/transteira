<script lang="ts">
  // Global audit log (super admin, GET /admin/system/audit-events, most recent first, page by
  // page): filters reflected in the URL (tenant, action from a grouped list or typed), one row per
  // event with its tenant ("Instance" for the events without tenant), date, actor, action,
  // object, IP and free details. The API has no "instance events only" filter, so the tenant
  // select only offers "All" and the tenants (see globalAudit.ts). The system sub-navigation is
  // rendered by App.svelte.
  import { untrack } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, TextField } from '../../../shared/components';
  import { i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import AuditEventsTable from '../../components/AuditEventsTable.svelte';
  import FilterBar from '../../components/FilterBar.svelte';
  import SelectField from '../../components/SelectField.svelte';
  import { loadAllPages } from '../admins/admins';
  import { loadedText } from '../ops/audit';
  import type { AuditEvent } from '../ops/auditLabels';
  import { ACTION_MAX_LENGTH, parseFilters, pathWithFilters } from '../ops/filters';
  import { emptyList, receiveError, receivePage, startMore, startReset, type PagedList } from '../ops/paging';
  import type { AdminScreenProps } from '../types';
  import {
    CUSTOM_ACTION,
    emptyText,
    GLOBAL_AUDIT_FILTERS,
    globalActionEntries,
    globalAuditApiParams,
    globalAuditFormOf,
    submitGlobalAuditForm,
    tenantCell,
    tenantNames,
    tenantOptions,
    type GlobalAuditFilters,
    type GlobalAuditForm,
    type GlobalAuditFormField,
    type TenantRef,
  } from './globalAudit';

  const { nav }: AdminScreenProps = $props();

  const uid = $props.id();
  const ids: Record<GlobalAuditFormField | 'actionSelect', string> = {
    tenantId: `${uid}-tenant`,
    actionSelect: `${uid}-action`,
    actionCustom: `${uid}-action-code`,
  };

  const filters = $derived(parseFilters(GLOBAL_AUDIT_FILTERS, nav.current.search));
  let form = $state<GlobalAuditForm>({ tenantId: '', actionSelect: '', actionCustom: '' });
  let errors = $state<Partial<Record<GlobalAuditFormField, string>>>({});
  let list = $state.raw<PagedList<AuditEvent>>(emptyList());
  let tenants = $state.raw<TenantRef[]>([]);
  let namesError = $state(false);

  const names = $derived(tenantNames(tenants));
  const tenantEntries = $derived(tenantOptions(tenants, form.tenantId, t));
  const actionEntries = $derived(globalActionEntries(t));
  const loadError = $derived(!list.loaded && typeof list.error === 'string' ? list.error : '');
  const moreError = $derived(list.loaded && typeof list.error === 'string' ? list.error : '');
  const resultText = $derived(
    list.loaded ? loadedText(list.items.length, list.nextCursor !== null, t) : undefined,
  );

  async function fetchPage(current: GlobalAuditFilters, cursor?: string) {
    const res = await adminApi.get('/admin/system/audit-events', {
      params: globalAuditApiParams(current, cursor),
    });
    return res.data;
  }

  async function reload(): Promise<void> {
    list = startReset(list);
    const generation = list.generation;
    try {
      list = receivePage(list, generation, await fetchPage(filters));
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
      list = receivePage(list, generation, await fetchPage(filters, cursor));
    } catch (err) {
      list = receiveError(list, generation, describeError(i18n, err).message);
    }
  }

  async function loadTenants(): Promise<void> {
    try {
      tenants = await loadAllPages(async (cursor) => {
        const res = await adminApi.get('/admin/tenants', {
          params: cursor === undefined ? { limit: 200 } : { limit: 200, cursor },
        });
        return res.data;
      });
      namesError = false;
    } catch {
      // The tenant ids are shown instead of the names.
      namesError = true;
    }
  }

  $effect(() => {
    untrack(() => void loadTenants());
  });

  // Filters come from the route: a change (apply, reset, back button) refills the form and
  // reloads the list. Navigating to the same URL reloads as well.
  $effect(() => {
    const current = filters;
    untrack(() => {
      form = globalAuditFormOf(current);
      errors = {};
      void reload();
    });
  });

  async function apply(): Promise<boolean> {
    const result = submitGlobalAuditForm(form, t);
    if (!result.ok) {
      errors = result.errors;
      document.getElementById(ids[result.first])?.focus();
      return false;
    }
    errors = {};
    await nav.navigate(pathWithFilters(nav.current.path, GLOBAL_AUDIT_FILTERS, result.filters));
    return true;
  }

  async function reset(): Promise<void> {
    errors = {};
    await nav.navigate(nav.current.path);
  }

  function retry(): void {
    void reload();
  }
</script>

{#snippet tenantColumnCell(row: AuditEvent)}
  {@const cell = tenantCell(row, names)}
  {#if cell.kind === 'tenant'}
    <a class="tt-break" href={nav.href(cell.path)} use:nav.link>{cell.name}</a>
  {:else if cell.kind === 'unknown'}
    <span class="tt-break">{cell.id}</span>
  {:else}
    <span class="tt-global-audit__instance">{t('sysAudit.list.instance')}</span>
  {/if}
{/snippet}

<h1 tabindex="-1">{t('adminSystem.audit.title')}</h1>
<p>{t('adminSystem.audit.intro')}</p>

<FilterBar
  label={t('sysAudit.filters.label')}
  onapply={apply}
  onreset={reset}
  busy={list.loading && !list.loaded}
  {resultText}
>
  <SelectField
    id={ids.tenantId}
    label={t('sysAudit.filters.tenant')}
    hint={t('sysAudit.filters.tenantHint')}
    options={tenantEntries}
    bind:value={form.tenantId}
    error={errors.tenantId}
  />
  <SelectField
    id={ids.actionSelect}
    label={t('opsAudit.filters.action')}
    options={actionEntries}
    bind:value={form.actionSelect}
  />
  {#if form.actionSelect === CUSTOM_ACTION}
    <TextField
      id={ids.actionCustom}
      label={t('opsAudit.filters.customCode')}
      hint={t('opsAudit.filters.customHint')}
      bind:value={form.actionCustom}
      error={errors.actionCustom}
      maxlength={ACTION_MAX_LENGTH}
      autocomplete="off"
      spellcheck="false"
    />
  {/if}
</FilterBar>

{#if namesError}
  <Alert severity="warning">{t('sysAudit.list.namesError')}</Alert>
{/if}

{#if loadError !== ''}
  <Alert severity="error">
    <p>{loadError}</p>
    <Button variant="secondary" onclick={retry}>{t('common.retry')}</Button>
  </Alert>
{:else}
  <AuditEventsTable
    caption={t('sysAudit.list.caption')}
    rows={list.items}
    {nav}
    leadingColumn={{ id: 'tenant', header: t('sysAudit.list.tenantColumn'), cell: tenantColumnCell }}
    loading={list.loading && !list.loaded}
    emptyText={emptyText(filters, t)}
    nextCursor={list.nextCursor}
    onloadmore={loadMore}
  />
  {#if moreError !== ''}
    <Alert severity="error">{moreError}</Alert>
  {/if}
{/if}

<style>
  .tt-global-audit__instance {
    font-style: italic;
  }
</style>
