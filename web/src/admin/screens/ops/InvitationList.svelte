<script lang="ts">
  // External invitations of a tenant (CLAUDE.md section 9; GET /admin/tenants/{id}/invitations):
  // - filter by status, reflected in the URL query string (back button, shared link);
  // - columns: invited address, issuer (an issuer erased under the GDPR shows "Erased
  //   address"), status badge, creation, expiry, last use, and a revoke action for the
  //   invitations still usable (pending or used, not expired);
  // - revocation (DELETE, 204 also when already revoked or expired) after a confirmation that
  //   says the link stops working immediately and deposits started with it end.
  // The tenant sub-navigation is rendered by App.svelte.
  import { tick, untrack } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, announce } from '../../../shared/components';
  import { formatDate, i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import ConfirmDialog from '../../components/ConfirmDialog.svelte';
  import DataTable from '../../components/DataTable.svelte';
  import FilterBar from '../../components/FilterBar.svelte';
  import SelectField from '../../components/SelectField.svelte';
  import StatusBadge from '../../components/StatusBadge.svelte';
  import type { AdminScreenProps } from '../types';
  import {
    filtersToApiParams,
    filtersToForm,
    formToFilters,
    INVITATION_FILTERS,
    isEmpty,
    parseFilters,
    pathWithFilters,
  } from './filters';
  import {
    afterRevoke,
    canRevoke,
    invitationStatusView,
    isErasedIssuer,
    issuerText,
    loadedText,
    statusFilterOptions,
    type Invitation,
  } from './invitations';
  import { emptyList, receiveError, receivePage, startMore, startReset, type PagedList } from './paging';

  const { params, nav }: AdminScreenProps = $props();

  const tenantId = $derived(params['id'] ?? '');
  const filters = $derived(parseFilters(INVITATION_FILTERS, nav.current.search));

  let list = $state.raw<PagedList<Invitation>>(emptyList());
  let status = $state('');
  let target = $state.raw<Invitation | undefined>(undefined);
  let confirmOpen = $state(false);
  let revoked = false;
  let heading: HTMLHeadingElement | undefined = $state();

  const loadError = $derived(!list.loaded && typeof list.error === 'string' ? list.error : '');
  const moreError = $derived(list.loaded && typeof list.error === 'string' ? list.error : '');
  const resultText = $derived(
    list.loaded ? loadedText(list.items.length, list.nextCursor !== null, t) : undefined,
  );

  const when = (iso: string): string => formatDate(iso, { dateStyle: 'medium', timeStyle: 'short' });

  async function fetchPage(cursor?: string): Promise<{ items: Invitation[]; nextCursor?: string }> {
    const res = await adminApi.get('/admin/tenants/{tenantId}/invitations', {
      path: { tenantId },
      params: filtersToApiParams(INVITATION_FILTERS, filters, { cursor }),
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

  // Filters (and the tenant) come from the route: the form follows them and the list reloads.
  $effect(() => {
    void tenantId;
    const form = filtersToForm(INVITATION_FILTERS, filters);
    untrack(() => {
      status = form.status;
      void reload();
    });
  });

  async function apply(): Promise<boolean> {
    const next = formToFilters(INVITATION_FILTERS, { status });
    if (next === undefined) {
      return false;
    }
    await nav.navigate(pathWithFilters(nav.current.path, INVITATION_FILTERS, next));
    return true;
  }

  async function clear(): Promise<void> {
    status = '';
    await nav.navigate(pathWithFilters(nav.current.path, INVITATION_FILTERS, {}));
  }

  function askRevoke(row: Invitation): void {
    target = row;
    revoked = false;
    confirmOpen = true;
  }

  async function revoke(): Promise<string | void> {
    const row = target;
    if (row === undefined) {
      return;
    }
    try {
      await adminApi.delete('/admin/tenants/{tenantId}/invitations/{invitationId}', {
        path: { tenantId, invitationId: row.id },
      });
    } catch (err) {
      const view = describeError(i18n, err);
      if (view.status !== 404) {
        return view.message;
      }
    }
    list = afterRevoke(list, row.id, filters);
    revoked = true;
    announce(t('opsInvitations.revoke.done', { email: row.email }));
  }

  async function closed(): Promise<void> {
    // The revoke button of the row is gone: the focus goes back to the page heading.
    if (revoked) {
      revoked = false;
      await tick();
      heading?.focus();
    }
  }
</script>

{#snippet emailCell(row: Invitation)}
  <span class="tt-break">{row.email}</span>
{/snippet}

{#snippet issuerCell(row: Invitation)}
  {#if isErasedIssuer(row.invitedBy)}
    <em>{issuerText(row.invitedBy, t)}</em>
  {:else}
    <span class="tt-break">{row.invitedBy}</span>
  {/if}
{/snippet}

{#snippet statusCell(row: Invitation)}
  {@const view = invitationStatusView(row.status, t)}
  <StatusBadge variant={view.variant} label={view.label} />
{/snippet}

{#snippet createdCell(row: Invitation)}
  {when(row.createdAt)}
{/snippet}

{#snippet expiresCell(row: Invitation)}
  {when(row.expiresAt)}
{/snippet}

{#snippet lastUsedCell(row: Invitation)}
  {row.lastUsedAt === undefined ? t('opsInvitations.never') : when(row.lastUsedAt)}
{/snippet}

{#snippet actionsCell(row: Invitation)}
  {#if canRevoke(row)}
    <Button
      variant="secondary"
      aria-label={t('opsInvitations.revoke.buttonFor', { email: row.email })}
      onclick={() => askRevoke(row)}
    >
      {t('opsInvitations.revoke.button')}
    </Button>
  {/if}
{/snippet}

<h1 tabindex="-1" bind:this={heading}>{t('adminOps.invitations.title')}</h1>
<p>{t('adminOps.invitations.intro')}</p>

<FilterBar
  label={t('opsInvitations.filters.label')}
  onapply={apply}
  onreset={clear}
  busy={list.loading && !list.loaded}
  {resultText}
>
  <SelectField
    label={t('opsInvitations.filters.status')}
    options={statusFilterOptions(t)}
    bind:value={status}
  />
</FilterBar>

{#if loadError !== ''}
  <Alert severity="error">
    <p>{loadError}</p>
    <Button variant="secondary" onclick={() => void reload()}>{t('common.retry')}</Button>
  </Alert>
{:else}
  <DataTable
    caption={t('opsInvitations.caption')}
    captionHidden
    rows={list.items}
    key={(row) => row.id}
    loading={list.loading && !list.loaded}
    emptyText={isEmpty(filters) ? t('opsInvitations.empty') : t('opsInvitations.emptyFiltered')}
    nextCursor={list.nextCursor}
    onloadmore={loadMore}
    columns={[
      { id: 'email', header: t('opsInvitations.columns.email'), cell: emailCell, rowHeader: true },
      { id: 'invitedBy', header: t('opsInvitations.columns.invitedBy'), cell: issuerCell },
      { id: 'status', header: t('opsInvitations.columns.status'), cell: statusCell },
      { id: 'createdAt', header: t('opsInvitations.columns.createdAt'), cell: createdCell },
      { id: 'expiresAt', header: t('opsInvitations.columns.expiresAt'), cell: expiresCell },
      { id: 'lastUsedAt', header: t('opsInvitations.columns.lastUsedAt'), cell: lastUsedCell },
      {
        id: 'actions',
        header: t('opsInvitations.columns.actions'),
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
  title={t('opsInvitations.revoke.title')}
  text={t('opsInvitations.revoke.text', { email: target?.email ?? '' })}
  confirmLabel={t('opsInvitations.revoke.confirm')}
  busyLabel={t('opsInvitations.revoke.busy')}
  danger
  onconfirm={revoke}
  onclose={() => void closed()}
/>
