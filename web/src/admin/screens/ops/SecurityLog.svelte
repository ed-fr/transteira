<script lang="ts">
  // Security log of a tenant (GET /admin/tenants/{tenantId}/security-events, most recent first,
  // page by page; delegated admins, auditors and super admin): filters reflected in the URL (type
  // from a list or typed, period), one row per event with its date, type, reason, client IP and
  // number of occurrences (identical events coalesced in a short window). The log never holds an
  // e-mail address; events without tenant are not part of it.
  import { untrack } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, TextField } from '../../../shared/components';
  import { i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import FilterBar from '../../components/FilterBar.svelte';
  import SecurityEventsTable from '../../components/SecurityEventsTable.svelte';
  import SelectField from '../../components/SelectField.svelte';
  import type { AdminScreenProps } from '../types';
  import { parseFilters, pathWithFilters } from './filters';
  import { emptyList, receiveError, receivePage, startMore, startReset, type PagedList } from './paging';
  import {
    CUSTOM_TYPE,
    TYPE_MAX_LENGTH,
    SECURITY_FILTERS,
    emptySecurityForm,
    loadedText,
    securityApiParams,
    securityFormOf,
    submitSecurityForm,
    typeEntries,
    type SecurityEvent,
    type SecurityForm,
    type SecurityFormField,
  } from './securityLog';

  const { params, nav }: AdminScreenProps = $props();

  const uid = $props.id();
  const ids: Record<SecurityFormField | 'typeSelect', string> = {
    tenantId: `${uid}-tenant`,
    typeSelect: `${uid}-type`,
    typeCustom: `${uid}-type-token`,
    from: `${uid}-from`,
    to: `${uid}-to`,
  };

  const tenantId = $derived(params['id'] ?? '');
  const filters = $derived(parseFilters(SECURITY_FILTERS, nav.current.search));
  let form = $state<SecurityForm>(emptySecurityForm());
  let errors = $state<Partial<Record<SecurityFormField, string>>>({});
  let list = $state.raw<PagedList<SecurityEvent>>(emptyList());

  const entries = $derived(typeEntries(t));
  const loadError = $derived(!list.loaded && typeof list.error === 'string' ? list.error : '');
  const moreError = $derived(list.loaded && typeof list.error === 'string' ? list.error : '');
  const resultText = $derived(
    list.loaded ? loadedText(list.items.length, list.nextCursor !== null, t) : undefined,
  );

  async function fetchPage(cursor?: string) {
    const res = await adminApi.get('/admin/tenants/{tenantId}/security-events', {
      path: { tenantId },
      params: securityApiParams(filters, { cursor }),
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

  // Filters (and the tenant) come from the route: a change (apply, reset, back button) refills
  // the form and reloads the list. Navigating to the same URL reloads as well.
  $effect(() => {
    void tenantId;
    const current = filters;
    untrack(() => {
      form = securityFormOf(current);
      errors = {};
      void reload();
    });
  });

  async function apply(): Promise<boolean> {
    const result = submitSecurityForm(form, t);
    if (!result.ok) {
      errors = result.errors;
      document.getElementById(ids[result.first])?.focus();
      return false;
    }
    errors = {};
    await nav.navigate(pathWithFilters(nav.current.path, SECURITY_FILTERS, result.filters));
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

<h1 tabindex="-1">{t('adminOps.security.title')}</h1>
<p>{t('adminOps.security.intro')}</p>

<FilterBar
  label={t('opsSecurity.filters.label')}
  onapply={apply}
  onreset={reset}
  busy={list.loading && !list.loaded}
  {resultText}
>
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

{#if loadError !== ''}
  <Alert severity="error">
    <p>{loadError}</p>
    <Button variant="secondary" onclick={retry}>{t('common.retry')}</Button>
  </Alert>
{:else}
  <SecurityEventsTable
    caption={t('opsSecurity.list.caption')}
    rows={list.items}
    loading={list.loading && !list.loaded}
    emptyText={t('opsSecurity.list.empty')}
    nextCursor={list.nextCursor}
    onloadmore={loadMore}
  />
  {#if moreError !== ''}
    <Alert severity="error">{moreError}</Alert>
  {/if}
{/if}
