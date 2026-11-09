<script lang="ts">
  // "My secrets" section of the signed-in sender (since 2.1): the one-time secrets created from
  // this address, most recent first, with cursor pagination. Metadata only (state, delivery,
  // recipient, expiry, read date): the content and the link of a secret are never available. A
  // pending or active secret can be deleted after a confirmation (DELETE /me/secrets/{id}, with
  // the CSRF token added by the client). The section stays out of the page while the sender has
  // no secret, and when the secrets are not offered (404, secrets-disabled). After a deletion, the
  // focus moves to the heading of the section (the delete button of the row is gone).
  import { onMount, tick } from 'svelte';
  import { api } from '../../shared/api/api';
  import { Alert, Button, Dialog, announce } from '../../shared/components';
  import { formatBytes, formatDate, i18n, t } from '../../shared/i18n/i18n.svelte';
  import { problemMessage } from '../../shared/api/problem';
  import { isSessionExpired } from './logic';
  import {
    canDeleteMySecret,
    markSecretDeleted,
    secretDeleteFailure,
    secretListSilent,
    secretDeliveryKey,
    secretStateKey,
    type MySecret,
  } from './secrets';

  interface Props {
    /** The session ended (401). */
    onexpired: () => void;
  }

  let { onexpired }: Props = $props();

  const PAGE_SIZE = 20;
  let items = $state.raw<MySecret[]>([]);
  let cursor = $state<string | undefined>();
  let loading = $state(true);
  let loadingMore = $state(false);
  let failed = $state(false);
  let target = $state.raw<MySecret | undefined>();
  let deleteOpen = $state(false);
  let deleting = $state(false);
  let deleteError = $state<string | undefined>();
  let loadError = $state<string | undefined>();
  let titleElement: HTMLHeadingElement | undefined = $state();
  // Set by a successful deletion: the closed dialog hands the focus to the heading.
  let focusTitle = false;

  const when = (iso: string): string => formatDate(iso, { dateStyle: 'medium', timeStyle: 'short' });

  async function load(more: boolean): Promise<void> {
    if (more) {
      loadingMore = true;
    } else {
      loading = true;
    }
    failed = false;
    try {
      const { data } = await api.get('/me/secrets', {
        params: { limit: PAGE_SIZE, cursor: more ? cursor : undefined },
      });
      items = more ? [...items, ...data.items] : data.items;
      cursor = data.nextCursor;
      if (more) {
        announce(t('myTransfers.secrets.loadedMore', { count: data.items.length }));
      }
    } catch (err) {
      if (isSessionExpired(err)) {
        onexpired();
        return;
      }
      if (secretListSilent(err)) {
        // No secrets on this tenant: the section stays out of the page.
        items = [];
        cursor = undefined;
        return;
      }
      loadError = problemMessage(i18n, err);
      failed = true;
    } finally {
      loading = false;
      loadingMore = false;
    }
  }

  onMount(() => {
    void load(false);
  });

  function ask(secret: MySecret): void {
    target = secret;
    deleteError = undefined;
    deleteOpen = true;
  }

  async function remove(): Promise<void> {
    const secret = target;
    if (secret === undefined || deleting) {
      return;
    }
    deleting = true;
    deleteError = undefined;
    try {
      await api.delete('/me/secrets/{secretId}', { path: { secretId: secret.id } });
    } catch (err) {
      const failure = secretDeleteFailure(err);
      if (failure === 'session-expired') {
        onexpired();
        return;
      }
      if (failure === 'error') {
        deleteError = problemMessage(i18n, err);
        deleting = false;
        return;
      }
      // 404: already gone (ended meanwhile): the row shows the deleted state all the same.
    }
    items = markSecretDeleted(items, secret.id, new Date().toISOString());
    focusTitle = true;
    deleteOpen = false;
    deleting = false;
    announce(t('myTransfers.secrets.delete.done'));
  }

  async function dialogClosed(): Promise<void> {
    if (!focusTitle) {
      return;
    }
    focusTitle = false;
    await tick();
    titleElement?.focus();
  }
</script>

{#if loading}
  <!-- Nothing yet: the section only appears once the sender is known to have secrets. -->
{:else if failed}
  <section aria-labelledby="my-secrets-title">
    <h2 id="my-secrets-title" class="tt-text-lg">{t('myTransfers.secrets.title')}</h2>
    <Alert severity="error">{loadError ?? t('common.error.text')}</Alert>
    <Button variant="secondary" onclick={() => void load(false)}>{t('common.retry')}</Button>
  </section>
{:else if items.length > 0}
  <section aria-labelledby="my-secrets-title">
    <h2 id="my-secrets-title" class="tt-text-lg" tabindex="-1" bind:this={titleElement}>
      {t('myTransfers.secrets.title')}
    </h2>
    <p class="tt-text-muted tt-text-sm">{t('myTransfers.secrets.intro')}</p>
    <div class="table-wrap">
      <table class="secrets">
        <caption class="visually-hidden">{t('myTransfers.secrets.caption')}</caption>
        <thead>
          <tr>
            <th scope="col">{t('myTransfers.secrets.created')}</th>
            <th scope="col">{t('myTransfers.secrets.deliveryColumn')}</th>
            <th scope="col">{t('myTransfers.secrets.state.column')}</th>
            <th scope="col">{t('myTransfers.secrets.expires')}</th>
            <th scope="col">{t('myTransfers.secrets.readAt')}</th>
            <th scope="col"><span class="visually-hidden">{t('myTransfers.list.action')}</span></th>
          </tr>
        </thead>
        <tbody>
          {#each items as item (item.id)}
            <tr>
              <th scope="row" class="created">{when(item.createdAt)}</th>
              <td class="tt-break">
                {#if item.delivery === 'email' && item.recipient !== undefined}
                  {t('myTransfers.secrets.delivery.emailTo', { recipient: item.recipient })}
                {:else}
                  {t(secretDeliveryKey(item.delivery))}
                {/if}
                {#if item.hasFile}
                  <span class="sub tt-text-sm">
                    {item.fileSize === undefined
                      ? t('myTransfers.secrets.file')
                      : t('myTransfers.secrets.fileSize', { size: formatBytes(item.fileSize) })}
                  </span>
                {/if}
              </td>
              <td>{t(secretStateKey(item.state))}</td>
              <td>
                {#if item.expiresAt}
                  {when(item.expiresAt)}
                {:else}
                  <span class="tt-text-muted">{t('myTransfers.list.noExpiry')}</span>
                {/if}
              </td>
              <td>
                {#if item.readAt}
                  {when(item.readAt)}
                {:else}
                  <span class="tt-text-muted">{t('myTransfers.secrets.notRead')}</span>
                {/if}
              </td>
              <td>
                {#if canDeleteMySecret(item)}
                  <Button variant="secondary" small onclick={() => ask(item)}>
                    {t('myTransfers.secrets.delete.button')}<span class="visually-hidden">
                      {t('myTransfers.secrets.delete.buttonFor', { date: when(item.createdAt) })}</span
                    >
                  </Button>
                {/if}
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
  </section>

  <Dialog
    bind:open={deleteOpen}
    title={t('myTransfers.secrets.delete.title')}
    hideCloseButton={deleting}
    onclose={() => void dialogClosed()}
  >
    <p>{t('myTransfers.secrets.delete.text')}</p>
    {#if deleteError}
      <Alert severity="error">{deleteError}</Alert>
    {/if}
    {#snippet actions()}
      <Button variant="danger" loading={deleting} onclick={() => void remove()}>
        {t('myTransfers.secrets.delete.confirmButton')}
      </Button>
      <Button variant="secondary" disabled={deleting} onclick={() => (deleteOpen = false)}>
        {t('myTransfers.secrets.delete.cancel')}
      </Button>
    {/snippet}
  </Dialog>
{/if}

<style>
  section {
    margin-top: var(--tt-space-6);
  }

  .table-wrap {
    overflow-x: auto;
    margin: var(--tt-space-4) 0;
  }

  .secrets {
    width: 100%;
    border-collapse: collapse;
  }

  .secrets th,
  .secrets td {
    padding: var(--tt-space-2);
    border-bottom: 1px solid var(--tt-border);
    text-align: left;
    vertical-align: top;
  }

  .created {
    font-weight: var(--tt-font-weight-normal);
  }

  .sub {
    display: block;
    color: var(--tt-text-muted);
  }
</style>
