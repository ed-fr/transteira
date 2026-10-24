<script lang="ts">
  // Audit log of a tenant (GET /admin/tenants/{tenantId}/audit-events, most recent first, page by
  // page): filters reflected in the URL (action from a grouped list or typed, actor, period), one
  // row per event with its date, actor, action, object (a transfer links to its detail), IP and
  // free details. Details are always rendered as text pairs, never as HTML.
  import { untrack } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, TextField } from '../../../shared/components';
  import { i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import AuditEventsTable from '../../components/AuditEventsTable.svelte';
  import FilterBar from '../../components/FilterBar.svelte';
  import SelectField from '../../components/SelectField.svelte';
  import type { AdminScreenProps } from '../types';
  import {
    actionEntries,
    auditFormOf,
    CUSTOM_ACTION,
    loadedText,
    submitAuditForm,
    type AuditForm,
    type AuditFormField,
  } from './audit';
  import type { AuditAction, AuditEvent } from './auditLabels';
  import {
    ACTION_MAX_LENGTH,
    ACTOR_MAX_LENGTH,
    AUDIT_FILTERS,
    filtersToApiParams,
    parseFilters,
    pathWithFilters,
    type AuditFilters,
  } from './filters';
  import { emptyList, receiveError, receivePage, startMore, startReset, type PagedList } from './paging';

  const { params, nav }: AdminScreenProps = $props();

  const uid = $props.id();
  const ids: Record<AuditFormField | 'actionSelect', string> = {
    actionSelect: `${uid}-action`,
    actionCustom: `${uid}-action-code`,
    actor: `${uid}-actor`,
    from: `${uid}-from`,
    to: `${uid}-to`,
  };

  const tenantId = $derived(params['id'] ?? '');
  const filters = $derived(parseFilters(AUDIT_FILTERS, nav.current.search));
  let form = $state<AuditForm>({ actionSelect: '', actionCustom: '', actor: '', from: '', to: '' });
  let errors = $state<Partial<Record<AuditFormField, string>>>({});
  let list = $state.raw<PagedList<AuditEvent>>(emptyList());

  const entries = $derived(actionEntries(t));
  const loadError = $derived(!list.loaded && typeof list.error === 'string' ? list.error : '');
  const moreError = $derived(list.loaded && typeof list.error === 'string' ? list.error : '');
  const resultText = $derived(
    list.loaded ? loadedText(list.items.length, list.nextCursor !== null, t) : undefined,
  );

  function apiParams(tenantFilters: AuditFilters, cursor?: string) {
    const p = filtersToApiParams(AUDIT_FILTERS, tenantFilters, { cursor });
    // The action filter is free text (checked against the "domain.verb" form only), while the
    // query parameter is typed with the closed AuditAction enum of the specification: the API
    // accepts any value of that form (an unknown action simply matches no event).
    return { ...p, action: p.action as AuditAction | undefined };
  }

  async function reload(): Promise<void> {
    list = startReset(list);
    const generation = list.generation;
    try {
      const res = await adminApi.get('/admin/tenants/{tenantId}/audit-events', {
        path: { tenantId },
        params: apiParams(filters),
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
      const res = await adminApi.get('/admin/tenants/{tenantId}/audit-events', {
        path: { tenantId },
        params: apiParams(filters, cursor),
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
      form = auditFormOf(current, t);
      errors = {};
      void reload();
    });
  });

  async function apply(): Promise<boolean> {
    const result = submitAuditForm(form, t);
    if (!result.ok) {
      errors = result.errors;
      document.getElementById(ids[result.first])?.focus();
      return false;
    }
    errors = {};
    await nav.navigate(pathWithFilters(nav.current.path, AUDIT_FILTERS, result.filters));
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

<h1 tabindex="-1">{t('adminOps.audit.title')}</h1>
<p>{t('adminOps.audit.intro')}</p>

<FilterBar
  label={t('opsAudit.filters.label')}
  onapply={apply}
  onreset={reset}
  busy={list.loading && !list.loaded}
  {resultText}
>
  <SelectField
    id={ids.actionSelect}
    label={t('opsAudit.filters.action')}
    options={entries}
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
  <TextField
    id={ids.actor}
    label={t('opsAudit.filters.actor')}
    hint={t('opsAudit.filters.actorHint')}
    bind:value={form.actor}
    error={errors.actor}
    maxlength={ACTOR_MAX_LENGTH}
    autocomplete="off"
    spellcheck="false"
  />
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
  <AuditEventsTable
    caption={t('opsAudit.list.caption')}
    rows={list.items}
    {nav}
    linkTenant={() => tenantId}
    loading={list.loading && !list.loaded}
    emptyText={t('opsAudit.list.empty')}
    nextCursor={list.nextCursor}
    onloadmore={loadMore}
  />
  {#if moreError !== ''}
    <Alert severity="error">{moreError}</Alert>
  {/if}
{/if}
