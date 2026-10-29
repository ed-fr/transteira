<script lang="ts">
  // Transfers in progress of the signed-in sender, most recent first, with cursor pagination.
  import { onMount } from 'svelte';
  import { api } from '../../shared/api/api';
  import { Alert, Button, Spinner, announce } from '../../shared/components';
  import { formatBytes, formatDate, t } from '../../shared/i18n/i18n.svelte';
  import { isSessionExpired, statusKey, type MyTransfer } from './logic';

  interface Props {
    /** Address of the session. */
    email: string;
    /** Opens the detail of a transfer. */
    onopen: (id: string) => void;
    /** The session ended (401). */
    onexpired: () => void;
    /** Ends the session. */
    onsignout: () => void;
    /** Signing out is in progress. */
    signingOut?: boolean;
  }

  let { email, onopen, onexpired, onsignout, signingOut = false }: Props = $props();

  const PAGE_SIZE = 20;
  let items = $state<MyTransfer[]>([]);
  let cursor = $state<string | undefined>();
  let loading = $state(true);
  let loadingMore = $state(false);
  let failed = $state(false);
  let heading: HTMLElement | undefined = $state();

  async function load(more: boolean): Promise<void> {
    if (more) {
      loadingMore = true;
    } else {
      loading = true;
    }
    failed = false;
    try {
      const { data } = await api.get('/me/transfers', {
        params: { limit: PAGE_SIZE, cursor: more ? cursor : undefined },
      });
      items = more ? [...items, ...data.items] : data.items;
      cursor = data.nextCursor;
      if (more) {
        announce(t('myTransfers.list.loadedMore', { count: data.items.length }));
      }
    } catch (err) {
      if (isSessionExpired(err)) {
        onexpired();
        return;
      }
      failed = true;
    } finally {
      loading = false;
      loadingMore = false;
    }
  }

  onMount(() => {
    heading?.focus();
    void load(false);
  });
</script>

<h1 tabindex="-1" bind:this={heading}>{t('myTransfers.title')}</h1>
<div class="tt-cluster tt-cluster--between">
  <p class="tt-break tt-mb-0">{t('myTransfers.session.as', { email })}</p>
  <Button variant="secondary" small loading={signingOut} onclick={onsignout}>
    {t('myTransfers.session.signOut')}
  </Button>
</div>
<p class="tt-text-muted tt-text-sm">{t('myTransfers.list.intro')}</p>

{#if loading}
  <Spinner showLabel />
{:else if failed}
  <Alert severity="error">{t('common.error.text')}</Alert>
  <Button variant="secondary" onclick={() => void load(false)}>{t('common.retry')}</Button>
{:else if items.length === 0}
  <p>{t('myTransfers.list.empty')}</p>
{:else}
  <div class="table-wrap">
    <table class="transfers">
      <caption>{t('myTransfers.list.caption')}</caption>
      <thead>
        <tr>
          <th scope="col">{t('myTransfers.list.recipients')}</th>
          <th scope="col">{t('myTransfers.list.files')}</th>
          <th scope="col">{t('myTransfers.list.status')}</th>
          <th scope="col">{t('myTransfers.list.expires')}</th>
          <th scope="col">{t('myTransfers.list.downloadedBy')}</th>
          <th scope="col"><span class="visually-hidden">{t('myTransfers.list.action')}</span></th>
        </tr>
      </thead>
      <tbody>
        {#each items as item (item.id)}
          <tr>
            <th scope="row" class="tt-break recipients">
              {item.recipients.join(', ')}
              {#if item.confidentialityLevel}
                <span class="level tt-text-sm">{item.confidentialityLevel.label}</span>
              {/if}
            </th>
            <td
              >{t('myTransfers.list.filesValue', {
                count: item.fileCount,
                size: formatBytes(item.totalBytes),
              })}</td
            >
            <td>{t(statusKey(item.status))}</td>
            <td>
              {#if item.expiresAt}
                {formatDate(item.expiresAt, { dateStyle: 'medium', timeStyle: 'short' })}
              {:else}
                <span class="tt-text-muted">{t('myTransfers.list.noExpiry')}</span>
              {/if}
            </td>
            <td>{item.downloadedBy}</td>
            <td>
              <Button variant="secondary" small onclick={() => onopen(item.id)}>
                {t('myTransfers.list.open')}<span class="visually-hidden">
                  {t('myTransfers.list.openFor', { recipients: item.recipients.join(', ') })}</span
                >
              </Button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
  {#if cursor !== undefined}
    <div class="tt-cluster">
      <Button variant="secondary" loading={loadingMore} onclick={() => void load(true)}>
        {t('myTransfers.list.loadMore')}
      </Button>
    </div>
  {/if}
{/if}

<style>
  .table-wrap {
    overflow-x: auto;
    margin: var(--tt-space-4) 0;
  }

  .transfers {
    width: 100%;
    border-collapse: collapse;
  }

  .transfers caption {
    margin-bottom: var(--tt-space-2);
    font-weight: var(--tt-font-weight-bold);
    text-align: left;
  }

  .transfers th,
  .transfers td {
    padding: var(--tt-space-2);
    border-bottom: 1px solid var(--tt-border);
    text-align: left;
    vertical-align: top;
  }

  .recipients {
    font-weight: var(--tt-font-weight-normal);
  }

  .level {
    display: block;
    color: var(--tt-text-muted);
  }
</style>
