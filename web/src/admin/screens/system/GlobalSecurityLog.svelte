<script lang="ts">
  // Instance security log (super admin, GET /admin/system/security-events, most recent first,
  // page by page): filters reflected in the URL (tenant, type, period), one row per event with
  // its tenant ("Instance" for the events without tenant: unknown FQDN, provisioning token, admin
  // sign-in), date, type, reason, client IP and occurrences. With a tenant selected, the events
  // without tenant are not shown. The system sub-navigation is rendered by App.svelte.
  import { untrack } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, TextField } from '../../../shared/components';
  import { i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import FilterBar from '../../components/FilterBar.svelte';
  import SecurityEventsTable from '../../components/SecurityEventsTable.svelte';
  import SelectField from '../../components/SelectField.svelte';
  import { loadAllPages } from '../admins/admins';
  import { parseFilters, pathWithFilters } from '../ops/filters';
  import { emptyList, receiveError, receivePage, startMore, startReset, type PagedList } from '../ops/paging';
  import {
    CUSTOM_TYPE,
    GLOBAL_SECURITY_FILTERS,
    TYPE_MAX_LENGTH,
    emptySecurityForm,
    loadedText,
    securityApiParams,
    securityFormOf,
    submitSecurityForm,
    typeEntries,
    type SecurityEvent,
    type SecurityForm,
    type SecurityFormField,
  } from '../ops/securityLog';
  import type { AdminScreenProps } from '../types';
  import { tenantCell, tenantNames, tenantOptions, type TenantRef } from './globalAudit';

  const { nav }: AdminScreenProps = $props();

  const uid = $props.id();
  const ids: Record<SecurityFormField | 'typeSelect', string> = {
    tenantId: `${uid}-tenant`,
    typeSelect: `${uid}-type`,
    typeCustom: `${uid}-type-token`,
    from: `${uid}-from`,
    to: `${uid}-to`,
  };

  const filters = $derived(parseFilters(GLOBAL_SECURITY_FILTERS, nav.current.search));
  let form = $state<SecurityForm>(emptySecurityForm());
  let errors = $state<Partial<Record<SecurityFormField, string>>>({});
  let list = $state.raw<PagedList<SecurityEvent>>(emptyList());
  let tenants = $state.raw<TenantRef[]>([]);
  let namesError = $state(false);

  const names = $derived(tenantNames(tenants));
  const tenantEntries = $derived(tenantOptions(tenants, form.tenantId, t));
  const entries = $derived(typeEntries(t));
  const loadError = $derived(!list.loaded && typeof list.error === 'string' ? list.error : '');
  const moreError = $derived(list.loaded && typeof list.error === 'string' ? list.error : '');
  const resultText = $derived(
    list.loaded ? loadedText(list.items.length, list.nextCursor !== null, t) : undefined,
  );
  const emptyText = $derived(
    Object.values(filters).some((v) => v !== undefined && v !== '')
      ? t('opsSecurity.list.emptyFiltered')
      : t('opsSecurity.list.empty'),
  );

  async function fetchPage(cursor?: string) {
    const res = await adminApi.get('/admin/system/security-events', {
      params: securityApiParams(filters, { cursor, global: true }),
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
      form = securityFormOf(current);
      errors = {};
      void reload();
    });
  });

  async function apply(): Promise<boolean> {
    const result = submitSecurityForm(form, t, true);
    if (!result.ok) {
      errors = result.errors;
      document.getElementById(ids[result.first])?.focus();
      return false;
    }
    errors = {};
    await nav.navigate(pathWithFilters(nav.current.path, GLOBAL_SECURITY_FILTERS, result.filters));
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

{#snippet tenantColumnCell(row: SecurityEvent)}
  {@const cell = tenantCell(row, names)}
  {#if cell.kind === 'tenant'}
    <a class="tt-break" href={nav.href(cell.path)} use:nav.link>{cell.name}</a>
  {:else if cell.kind === 'unknown'}
    <span class="tt-break">{cell.id}</span>
  {:else}
    <span class="tt-global-security__instance">{t('sysAudit.list.instance')}</span>
  {/if}
{/snippet}

<h1 tabindex="-1">{t('adminSystem.security.title')}</h1>
<p>{t('adminSystem.security.intro')}</p>

<FilterBar
  label={t('opsSecurity.filters.globalLabel')}
  onapply={apply}
  onreset={reset}
  busy={list.loading && !list.loaded}
  {resultText}
>
  <SelectField
    id={ids.tenantId}
    label={t('sysAudit.filters.tenant')}
    hint={t('opsSecurity.filters.tenantHint')}
    options={tenantEntries}
    bind:value={form.tenantId}
    error={errors.tenantId}
  />
  <SelectField
    id={ids.typeSelect}
    label={t('opsSecurity.filters.type')}
    options={entries}
    bind:value={form.typeSelect}
  />
  {#if form.typeSelect === CUSTOM_TYPE}
    <TextField
      id={ids.typeCustom}
      label={t('opsSecurity.filters.customToken')}
      hint={t('opsSecurity.filters.customHint')}
      bind:value={form.typeCustom}
      error={errors.typeCustom}
      maxlength={TYPE_MAX_LENGTH}
      autocomplete="off"
      spellcheck="false"
    />
  {/if}
  <TextField
    id={ids.from}
    label={t('opsAudit.filters.from')}
    type="date"
    bind:value={form.from}
    error={errors.from}
  />
  <TextField
    id={ids.to}
    label={t('opsAudit.filters.to')}
    hint={t('opsAudit.filters.periodHint')}
    type="date"
    bind:value={form.to}
    error={errors.to}
  />
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
  <SecurityEventsTable
    caption={t('opsSecurity.list.globalCaption')}
    rows={list.items}
    leadingColumn={{ id: 'tenant', header: t('sysAudit.list.tenantColumn'), cell: tenantColumnCell }}
    loading={list.loading && !list.loaded}
    {emptyText}
    nextCursor={list.nextCursor}
    onloadmore={loadMore}
  />
  {#if moreError !== ''}
    <Alert severity="error">{moreError}</Alert>
  {/if}
{/if}

<style>
  .tt-global-security__instance {
    font-style: italic;
  }
</style>
