<script lang="ts">
  // Admin accounts (super admin only; CLAUDE.md section 6.5): every account with its role, the
  // names of its entities, its two-factor status, its status (active, disabled, pending
  // activation) and its last sign-in; the signed-in admin's own row is marked "(you)". The list
  // is paginated by cursor ("Load more"); the entity names come from GET /admin/tenants (an id
  // is shown when its name cannot be loaded).
  import { onMount } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button } from '../../../shared/components';
  import { i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi, adminSession } from '../../api';
  import DataTable from '../../components/DataTable.svelte';
  import StatusBadge from '../../components/StatusBadge.svelte';
  import type { AdminScreenProps } from '../types';
  import {
    adminRow,
    loadAllPages,
    statusVariant,
    tenantNameMap,
    type Admin,
    type AdminRow,
    type TenantNames,
  } from './admins';

  const { nav }: AdminScreenProps = $props();

  const PAGE_SIZE = 50;

  let admins = $state<Admin[]>([]);
  let nextCursor = $state<string | undefined>(undefined);
  let names = $state.raw<TenantNames>(new Map());
  let loading = $state(true);
  let error = $state('');
  let moreError = $state('');

  const meId = $derived(adminSession.me?.id);
  const rows = $derived(
    admins.map((admin) => adminRow(admin, { names, meId, t, formatDate: (iso) => i18n.formatDate(iso) })),
  );

  async function fetchPage(cursor: string | undefined): Promise<void> {
    const res = await adminApi.get('/admin/admins', {
      params: cursor === undefined ? { limit: PAGE_SIZE } : { limit: PAGE_SIZE, cursor },
    });
    admins = cursor === undefined ? res.data.items : [...admins, ...res.data.items];
    nextCursor = res.data.nextCursor ?? undefined;
  }

  async function loadNames(): Promise<void> {
    try {
      const tenants = await loadAllPages(async (cursor) => {
        const res = await adminApi.get('/admin/tenants', {
          params: cursor === undefined ? { limit: 200 } : { limit: 200, cursor },
        });
        return res.data;
      });
      names = tenantNameMap(tenants);
    } catch {
      // The ids are shown instead of the names.
    }
  }

  async function load(): Promise<void> {
    loading = true;
    error = '';
    try {
      await Promise.all([fetchPage(undefined), loadNames()]);
    } catch (err) {
      error = describeError(i18n, err).message;
    } finally {
      loading = false;
    }
  }

  async function loadMore(): Promise<void> {
    moreError = '';
    try {
      await fetchPage(nextCursor);
    } catch (err) {
      moreError = describeError(i18n, err).message;
    }
  }

  onMount(() => {
    void load();
  });
</script>

{#snippet usernameCell(row: AdminRow)}
  <a href={nav.href(row.path)} use:nav.link>{row.username}</a>
  {#if row.self}<span class="tt-text-muted">{t('adminAccounts.list.you')}</span>{/if}
{/snippet}
{#snippet emailCell(row: AdminRow)}<span class="tt-break">{row.email}</span>{/snippet}
{#snippet roleCell(row: AdminRow)}{row.role}{/snippet}
{#snippet tenantsCell(row: AdminRow)}{row.tenants}{/snippet}
{#snippet totpCell(row: AdminRow)}
  <StatusBadge variant={statusVariant(row.totp)} label={t(`adminAccounts.totp.${row.totp}`)} />
{/snippet}
{#snippet statusCell(row: AdminRow)}
  <StatusBadge variant={statusVariant(row.status)} label={t(`adminAccounts.status.${row.status}`)} />
{/snippet}
{#snippet lastLoginCell(row: AdminRow)}{row.lastLogin}{/snippet}
{#snippet actionsCell(row: AdminRow)}
  <a
    href={nav.href(row.path)}
    use:nav.link
    aria-label={t('adminAccounts.list.edit', { username: row.username })}
  >
    {t('admin.common.edit')}
  </a>
{/snippet}

<div class="tt-cluster tt-cluster--between tt-mb-4">
  <h1 tabindex="-1" class="tt-mb-0">{t('adminAccounts.list.title')}</h1>
  <a class="tt-admins__create" href={nav.href('/admins/new')} use:nav.link>{t('adminAccounts.list.create')}</a
  >
</div>
<p>{t('adminAccounts.list.intro')}</p>

{#if error !== ''}
  <Alert severity="error">
    <p>{error}</p>
    <Button variant="secondary" small onclick={() => void load()}>{t('common.retry')}</Button>
  </Alert>
{:else}
  <DataTable
    caption={t('adminAccounts.list.caption')}
    captionHidden
    {loading}
    {rows}
    key={(row) => row.id}
    emptyText={t('adminAccounts.list.empty')}
    {nextCursor}
    onloadmore={loadMore}
    columns={[
      {
        id: 'username',
        header: t('adminAccounts.list.columns.username'),
        cell: usernameCell,
        rowHeader: true,
      },
      { id: 'email', header: t('adminAccounts.list.columns.email'), cell: emailCell },
      { id: 'role', header: t('adminAccounts.list.columns.role'), cell: roleCell },
      { id: 'tenants', header: t('adminAccounts.list.columns.tenants'), cell: tenantsCell },
      { id: 'totp', header: t('adminAccounts.list.columns.totp'), cell: totpCell },
      { id: 'status', header: t('adminAccounts.list.columns.status'), cell: statusCell },
      { id: 'lastLogin', header: t('adminAccounts.list.columns.lastLogin'), cell: lastLoginCell },
      {
        id: 'actions',
        header: t('adminAccounts.list.columns.actions'),
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
  .tt-admins__create {
    font-weight: var(--tt-font-weight-bold);
    color: var(--tt-link);
  }
</style>
