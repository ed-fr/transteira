<script lang="ts">
  // List of the tenants visible to the admin (GET /admin/tenants, page by page with the cursor):
  // name (link to the configuration), FQDN, status (badge "deletion in progress"), storage
  // used, default language and a configure link. The super admin sees the creation link, the
  // import link and a "Duplicate" action per row (screen TenantImport); a
  // delegated admin with a single tenant goes straight to its general settings.
  import { onMount } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, HelpIcon } from '../../../shared/components';
  import { i18n, locale, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi, adminSession } from '../../api';
  import ActionLink from '../../components/ActionLink.svelte';
  import PageHeader from '../../components/PageHeader.svelte';
  import QuotaMeter from '../../components/QuotaMeter.svelte';
  import TenantSwatch from '../../components/TenantSwatch.svelte';
  import DataTable from '../../components/DataTable.svelte';
  import StatusBadge from '../../components/StatusBadge.svelte';
  import { tenantPath } from '../../shell';
  import type { AdminScreenProps } from '../types';
  import {
    appendPage,
    canManageTenants,
    languageLabel,
    listRedirect,
    statusView,
    type Tenant,
  } from './tenants';
  import { formatBytes as formatBinaryBytes } from '../../forms/bytes';
  import { importPath } from './tenantTransfer';

  // Sizes are shown with the binary units of the size fields (MiB, GiB, TiB).
  const formatBytes = (n: number): string => formatBinaryBytes(n, locale.current);

  let { nav }: AdminScreenProps = $props();

  const me = $derived(adminSession.me);
  const canCreate = $derived(canManageTenants(me));
  // An auditor only consults: the link of a row opens the read-only summary.
  const readOnly = $derived(me?.role === 'auditor');

  let rows = $state.raw<Tenant[]>([]);
  let nextCursor = $state<string | undefined>(undefined);
  let loading = $state(true);
  let error = $state('');
  let moreError = $state('');

  async function load(): Promise<void> {
    loading = true;
    error = '';
    moreError = '';
    try {
      const res = await adminApi.get('/admin/tenants');
      rows = res.data.items;
      nextCursor = res.data.nextCursor;
    } catch (err) {
      error = describeError(i18n, err).message;
    } finally {
      loading = false;
    }
  }

  async function loadMore(): Promise<void> {
    if (nextCursor === undefined) {
      return;
    }
    moreError = '';
    try {
      const res = await adminApi.get('/admin/tenants', { params: { cursor: nextCursor } });
      rows = appendPage(rows, res.data.items);
      nextCursor = res.data.nextCursor;
    } catch (err) {
      moreError = describeError(i18n, err).message;
    }
  }

  onMount(() => {
    const to = listRedirect(adminSession.me);
    if (to !== undefined) {
      void nav.navigate(to, { replace: true });
      return;
    }
    void load();
  });
</script>

{#snippet nameCell(row: Tenant)}
  <span class="tt-tenant-name">
    <TenantSwatch color={row.primaryColor} size="sm" />
    <a class="tt-break" href={nav.href(tenantPath(row.id, 'general'))} use:nav.link>{row.name}</a>
  </span>
{/snippet}

{#snippet fqdnCell(row: Tenant)}
  <span class="tt-break">{row.fqdn}</span>
{/snippet}

{#snippet statusCell(row: Tenant)}
  {@const view = statusView(row.status, row.setupState)}
  <StatusBadge variant={view.variant} label={t(view.key)} />
{/snippet}

{#snippet quotaCell(row: Tenant)}
  <QuotaMeter
    used={row.storageUsedBytes}
    quota={row.storageQuotaBytes}
    label={t('adminTenants.list.quotaFor', { name: row.name })}
    {formatBytes}
    labelHidden
    showLevel="alert"
    compact
  />
{/snippet}

{#snippet languageCell(row: Tenant)}
  {languageLabel(row.defaultLanguage, locale.current)}
{/snippet}

{#snippet actionsCell(row: Tenant)}
  <a href={nav.href(tenantPath(row.id, 'general'))} use:nav.link>
    {t(readOnly ? 'adminTenants.list.view' : 'adminTenants.list.configure', { name: row.name })}
  </a>
  {#if canCreate && row.status !== 'deleting'}
    <a href={nav.href(importPath(row.id))} use:nav.link>
      {t('adminTenants.list.duplicate', { name: row.name })}
    </a>
  {/if}
{/snippet}

<PageHeader title={t('adminTenants.list.title')} description={t('adminTenants.list.intro')}>
  {#snippet help()}
    <HelpIcon topic="tenants" title={t('adminTenants.list.title')} {nav} />
  {/snippet}
  {#snippet actions()}
    {#if canCreate}
      <ActionLink to="/tenants/new" {nav} icon="plus">{t('adminTenants.list.create')}</ActionLink>
      <ActionLink to={importPath()} {nav} variant="secondary">{t('adminTenants.list.import')}</ActionLink>
    {/if}
  {/snippet}
</PageHeader>

{#if error !== ''}
  <Alert severity="error">
    <p>{error}</p>
    <Button variant="secondary" onclick={() => void load()}>{t('common.retry')}</Button>
  </Alert>
{:else}
  <DataTable
    caption={t('adminTenants.list.caption')}
    captionHidden
    {rows}
    key={(row) => row.id}
    {loading}
    emptyText={canCreate ? t('adminTenants.list.empty') : t('adminTenants.list.emptyDelegated')}
    {nextCursor}
    onloadmore={loadMore}
    columns={[
      { id: 'name', header: t('adminTenants.list.columns.name'), cell: nameCell, rowHeader: true },
      { id: 'fqdn', header: t('adminTenants.list.columns.fqdn'), cell: fqdnCell },
      { id: 'status', header: t('adminTenants.list.columns.status'), cell: statusCell },
      { id: 'quota', header: t('adminTenants.list.columns.quota'), cell: quotaCell },
      { id: 'language', header: t('adminTenants.list.columns.language'), cell: languageCell },
      {
        id: 'actions',
        header: t('adminTenants.list.columns.actions'),
        cell: actionsCell,
        headerHidden: true,
      },
    ]}
  />
  {#if moreError !== ''}
    <Alert severity="error">{moreError}</Alert>
  {/if}
{/if}

<style>
  .tt-tenant-name {
    display: inline-flex;
    align-items: center;
    gap: var(--tt-space-3);
  }
</style>
