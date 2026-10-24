<script lang="ts">
  // API tokens of a tenant (GET /admin/tenants/{id}/api-tokens, a plain array, revoked tokens
  // included; CLAUDE.md section 16.4):
  // - table: name, prefix (tt_xxxx…), allowed ranges, allowed senders (or "internal domains"),
  //   creation (date and admin), last use (may lag by up to a minute), expiry, status badge;
  // - per active token: Edit (TokenEditDialog, merge patch) and Revoke (confirmation by typing
  //   the exact token name);
  // - a link to the creation screen, to the interactive API documentation and a mention of the
  //   integration guide.
  // The secret of a token is never available here: the API never returns it again.
  // The tenant sub-navigation is rendered by App.svelte.
  import { tick, untrack } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, announce } from '../../../shared/components';
  import { formatDate, i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import ConfirmDialog from '../../components/ConfirmDialog.svelte';
  import DataTable from '../../components/DataTable.svelte';
  import StatusBadge from '../../components/StatusBadge.svelte';
  import { tenantPath } from '../../shell';
  import type { AdminScreenProps } from '../types';
  import TokenEditDialog from './TokenEditDialog.svelte';
  import {
    isManageable,
    prefixLabel,
    revokeErrorMessage,
    sendersText,
    sortTokens,
    statusView,
    tokenStatus,
    type ApiToken,
  } from './tokens';

  /** Path of the interactive API documentation, served by the application outside /admin. */
  const API_DOCS_PATH = '/api/docs';

  const { params, nav }: AdminScreenProps = $props();

  const tenantId = $derived(params['id'] ?? '');

  let tokens = $state.raw<ApiToken[]>([]);
  let now = $state.raw(new Date());
  let loading = $state(true);
  let loadError = $state('');
  let editing = $state.raw<ApiToken | undefined>(undefined);
  let editOpen = $state(false);
  let revoking = $state.raw<ApiToken | undefined>(undefined);
  let revokeOpen = $state(false);
  let revoked = false;
  let heading = $state<HTMLHeadingElement | undefined>();

  const rows = $derived(sortTokens(tokens, now));

  async function load(id: string): Promise<void> {
    loading = true;
    loadError = '';
    try {
      const res = await adminApi.get('/admin/tenants/{tenantId}/api-tokens', { path: { tenantId: id } });
      now = new Date();
      tokens = res.data;
    } catch (err) {
      loadError = describeError(i18n, err).message;
    } finally {
      loading = false;
    }
  }

  // Reload when the tenant changes; the loader itself (adminApi reads the locale) is untracked.
  $effect(() => {
    const id = tenantId;
    untrack(() => void load(id));
  });

  function replace(updated: ApiToken): void {
    tokens = tokens.map((tok) => (tok.id === updated.id ? updated : tok));
  }

  function startEdit(token: ApiToken): void {
    editing = token;
    editOpen = true;
  }

  function startRevoke(token: ApiToken): void {
    revoking = token;
    revoked = false;
    revokeOpen = true;
  }

  function saved(token: ApiToken): void {
    replace(token);
    announce(t('opsTokens.edit.saved'));
  }

  async function revoke(): Promise<string | void> {
    const token = revoking;
    if (token === undefined) {
      return;
    }
    try {
      await adminApi.delete('/admin/tenants/{tenantId}/api-tokens/{tokenId}', {
        path: { tenantId, tokenId: token.id },
      });
    } catch (err) {
      return revokeErrorMessage(describeError(i18n, err), t);
    }
    now = new Date();
    replace({ ...token, revokedAt: now.toISOString() });
    revoked = true;
    announce(t('opsTokens.revoke.done', { name: token.name }));
    // Reload to show the revocation date recorded by the server.
    void load(tenantId);
  }

  async function revokeClosed(): Promise<void> {
    // The Edit and Revoke buttons of the row are gone: the focus goes back to the page heading.
    if (revoked) {
      revoked = false;
      await tick();
      heading?.focus();
    }
  }

  const date = (value: string): string => formatDate(value, { dateStyle: 'medium', timeStyle: 'short' });
</script>

{#snippet nameCell(row: ApiToken)}
  <span class="tt-break">{row.name}</span>
{/snippet}

{#snippet prefixCell(row: ApiToken)}
  <code>{prefixLabel(row.prefix)}</code>
{/snippet}

{#snippet cidrsCell(row: ApiToken)}
  <ul class="tt-list-plain tt-tokens__values">
    {#each row.allowedCidrs as cidr (cidr)}
      <li><code>{cidr}</code></li>
    {/each}
  </ul>
{/snippet}

{#snippet sendersCell(row: ApiToken)}
  {#if row.allowedSenders.length === 0}
    <span class="tt-text-muted">{sendersText(row, t)}</span>
  {:else}
    <ul class="tt-list-plain tt-tokens__values">
      {#each row.allowedSenders as sender (sender)}
        <li class="tt-break">{sender}</li>
      {/each}
    </ul>
  {/if}
{/snippet}

{#snippet createdCell(row: ApiToken)}
  {t('opsTokens.list.createdBy', { date: date(row.createdAt), admin: row.createdBy })}
{/snippet}

{#snippet lastUsedCell(row: ApiToken)}
  {row.lastUsedAt ? date(row.lastUsedAt) : t('opsTokens.list.neverUsed')}
{/snippet}

{#snippet expiresCell(row: ApiToken)}
  {row.expiresAt ? date(row.expiresAt) : t('opsTokens.list.noExpiry')}
{/snippet}

{#snippet statusCell(row: ApiToken)}
  {@const view = statusView(tokenStatus(row, now))}
  <StatusBadge variant={view.variant} label={t(view.key)} />
  {#if row.revokedAt}
    <span class="tt-tokens__when">{date(row.revokedAt)}</span>
  {/if}
{/snippet}

{#snippet actionsCell(row: ApiToken)}
  {#if isManageable(row, now)}
    <div class="tt-cluster">
      <Button variant="secondary" onclick={() => startEdit(row)}>
        {t('opsTokens.list.edit')}<span class="visually-hidden"> {row.name}</span>
      </Button>
      <Button variant="danger" onclick={() => startRevoke(row)}>
        {t('opsTokens.list.revoke')}<span class="visually-hidden"> {row.name}</span>
      </Button>
    </div>
  {/if}
{/snippet}

<h1 tabindex="-1" bind:this={heading}>{t('adminOps.tokens.title')}</h1>
<p>{t('adminOps.tokens.intro')}</p>
<p>
  {t('opsTokens.list.docsIntro')}
  <a href={API_DOCS_PATH}>{t('opsTokens.list.docsLink')}</a>
</p>

<p>
  <a href={nav.href(`${tenantPath(tenantId, 'tokens')}/new`)} use:nav.link>{t('opsTokens.list.create')}</a>
</p>

{#if loadError !== ''}
  <Alert severity="error">
    <p>{loadError}</p>
    <Button variant="secondary" onclick={() => void load(tenantId)}>{t('common.retry')}</Button>
  </Alert>
{:else}
  <DataTable
    caption={t('opsTokens.list.caption')}
    captionHidden
    {rows}
    key={(row) => row.id}
    {loading}
    emptyText={t('opsTokens.list.empty')}
    columns={[
      { id: 'name', header: t('opsTokens.list.columns.name'), cell: nameCell, rowHeader: true },
      { id: 'prefix', header: t('opsTokens.list.columns.prefix'), cell: prefixCell },
      { id: 'cidrs', header: t('opsTokens.list.columns.cidrs'), cell: cidrsCell },
      { id: 'senders', header: t('opsTokens.list.columns.senders'), cell: sendersCell },
      { id: 'created', header: t('opsTokens.list.columns.created'), cell: createdCell },
      { id: 'lastUsed', header: t('opsTokens.list.columns.lastUsed'), cell: lastUsedCell },
      { id: 'expires', header: t('opsTokens.list.columns.expires'), cell: expiresCell },
      { id: 'status', header: t('opsTokens.list.columns.status'), cell: statusCell },
      { id: 'actions', header: t('opsTokens.list.columns.actions'), cell: actionsCell, headerHidden: true },
    ]}
  />
  {#if !loading && tokens.length > 0}
    <p class="tt-text-sm tt-text-muted">{t('opsTokens.list.lastUsedNote')}</p>
  {/if}
{/if}

{#if editing !== undefined}
  <TokenEditDialog
    bind:open={editOpen}
    token={editing}
    {tenantId}
    addGuard={(guard) => nav.addGuard(guard)}
    onsaved={saved}
  />
{/if}

<ConfirmDialog
  bind:open={revokeOpen}
  title={t('opsTokens.revoke.title', { name: revoking?.name ?? '' })}
  text={t('opsTokens.revoke.text')}
  confirmLabel={t('opsTokens.revoke.confirm')}
  confirmText={revoking?.name ?? ''}
  danger
  onconfirm={revoke}
  onclose={() => void revokeClosed()}
/>

<style>
  .tt-tokens__values {
    margin: 0;
  }

  .tt-tokens__when {
    display: block;
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }
</style>
