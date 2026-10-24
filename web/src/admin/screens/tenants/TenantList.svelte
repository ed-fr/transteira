<script lang="ts">
  // List of the tenants visible to the admin (GET /admin/tenants, page by page with the cursor):
  // name (link to the configuration), FQDN, status (badge "deletion in progress"), storage
  // used, default language and a configure link. The super admin sees the creation link; a
  // delegated admin with a single tenant goes straight to its general settings.
  import { onMount } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button } from '../../../shared/components';
  import { formatNumber, i18n, locale, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi, adminSession } from '../../api';
  import DataTable from '../../components/DataTable.svelte';
  import StatusBadge from '../../components/StatusBadge.svelte';
  import { tenantPath } from '../../shell';
  import type { AdminScreenProps } from '../types';
  import {
    appendPage,
    canManageTenants,
    languageLabel,
    listRedirect,
    quotaUsage,
    statusView,
    type Tenant,
  } from './tenants';
  import { formatBytes as formatBinaryBytes } from '../../forms/bytes';

  // Sizes are shown with the binary units of the size fields (MiB, GiB, TiB).
  const formatBytes = (n: number): string => formatBinaryBytes(n, locale.current);

  let { nav }: AdminScreenProps = $props();

  const me = $derived(adminSession.me);
  const canCreate = $derived(canManageTenants(me));

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

  function usageText(tenant: Tenant): string {
    const usage = quotaUsage(tenant);
    return t('adminTenants.list.quotaUsage', {
      used: formatBytes(usage.used),
      quota: formatBytes(usage.quota),
      percent: formatNumber(usage.percent, { maximumFractionDigits: 1 }),
    });
  }
</script>

{#snippet nameCell(row: Tenant)}
  <a class="tt-break" href={nav.href(tenantPath(row.id, 'general'))} use:nav.link>{row.name}</a>
{/snippet}

{#snippet fqdnCell(row: Tenant)}
  <span class="tt-break">{row.fqdn}</span>
{/snippet}

{#snippet statusCell(row: Tenant)}
  {@const view = statusView(row.status)}
  <StatusBadge variant={view.variant} label={t(view.key)} />
{/snippet}

{#snippet quotaCell(row: Tenant)}
  {usageText(row)}
{/snippet}

{#snippet languageCell(row: Tenant)}
  {languageLabel(row.defaultLanguage, locale.current)}
{/snippet}

{#snippet actionsCell(row: Tenant)}
  <a href={nav.href(tenantPath(row.id, 'general'))} use:nav.link>
    {t('adminTenants.list.configure', { name: row.name })}
  </a>
{/snippet}

<h1 tabindex="-1">{t('adminTenants.list.title')}</h1>
<p>{t('adminTenants.list.intro')}</p>

{#if canCreate}
  <p><a href={nav.href('/tenants/new')} use:nav.link>{t('adminTenants.list.create')}</a></p>
{/if}

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
