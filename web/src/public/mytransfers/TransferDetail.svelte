<script lang="ts">
  // One transfer of the sender: message, options, files with SHA-256 and antivirus status,
  // per-recipient tracking, extension of the validity and deletion (with confirmation).
  import { onMount, tick } from 'svelte';
  import { api } from '../../shared/api/api';
  import { ApiProblem } from '../../shared/api/client';
  import { problemMessage } from '../../shared/api/problem';
  import { Alert, Button, Dialog, RadioGroup, Spinner, announce } from '../../shared/components';
  import { formatBytes, formatDate, i18n, t } from '../../shared/i18n/i18n.svelte';
  import {
    extendFailure,
    extensionOptions,
    isSessionExpired,
    statusKey,
    type MyTransferDetail,
  } from './logic';

  interface Props {
    /** Transfer to show. */
    id: string;
    /** Back to the list. */
    onback: () => void;
    /** The transfer was deleted (or does not exist any more). */
    ondeleted: () => void;
    /** The session ended (401). */
    onexpired: () => void;
  }

  let { id, onback, ondeleted, onexpired }: Props = $props();

  let transfer = $state<MyTransferDetail | undefined>();
  let loadFailed = $state(false);
  let heading: HTMLElement | undefined = $state();
  let extendDays = $state<number | undefined>();
  let extendError = $state<string | undefined>();
  let extending = $state(false);
  let extendedNotice = $state(false);
  let deleteOpen = $state(false);
  let deleting = $state(false);
  let deleteError = $state<string | undefined>();

  const options = $derived(
    transfer === undefined ? [] : extensionOptions(Date.now(), transfer.expiresAt, transfer.extendableTo),
  );
  const canExtend = $derived(transfer?.status === 'available' && options.length > 0);
  const fileNames = $derived(new Map((transfer?.files ?? []).map((f) => [f.id, f.name])));

  function pickDefault(): void {
    extendDays = options.includes(7) ? 7 : options[0];
  }

  async function load(): Promise<void> {
    loadFailed = false;
    try {
      const { data } = await api.get('/me/transfers/{transferId}', { path: { transferId: id } });
      transfer = data;
      pickDefault();
    } catch (err) {
      if (isSessionExpired(err)) {
        onexpired();
      } else if (err instanceof ApiProblem && err.status === 404) {
        ondeleted();
      } else {
        loadFailed = true;
      }
    }
  }

  onMount(() => {
    void load();
  });

  $effect(() => {
    if (transfer !== undefined) {
      void tick().then(() => heading?.focus());
    }
  });

  async function extend(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (extending || extendDays === undefined) {
      return;
    }
    extending = true;
    extendError = undefined;
    extendedNotice = false;
    try {
      const { data } = await api.post('/me/transfers/{transferId}/extension', {
        path: { transferId: id },
        body: { expiryDays: extendDays as 1 | 7 | 30 },
      });
      transfer = data;
      pickDefault();
      extendedNotice = true;
      announce(t('myTransfers.detail.extend.done'));
    } catch (err) {
      if (isSessionExpired(err)) {
        onexpired();
        return;
      }
      const failure = extendFailure(err);
      switch (failure.kind) {
        case 'limit-reached':
          extendError = t('errors.extension-limit-reached');
          await load();
          break;
        case 'conflict':
          extendError = t('myTransfers.detail.extend.conflict');
          await load();
          break;
        case 'not-allowed':
          extendError = t('myTransfers.detail.extend.notAllowed');
          await load();
          break;
        case 'not-found':
          ondeleted();
          return;
        default:
          extendError = problemMessage(i18n, err);
      }
    } finally {
      extending = false;
    }
  }

  async function remove(): Promise<void> {
    if (deleting) {
      return;
    }
    deleting = true;
    deleteError = undefined;
    try {
      await api.delete('/me/transfers/{transferId}', { path: { transferId: id } });
      deleteOpen = false;
      announce(t('myTransfers.detail.delete.done'));
      ondeleted();
    } catch (err) {
      if (isSessionExpired(err)) {
        onexpired();
        return;
      }
      deleteError = problemMessage(i18n, err);
    } finally {
      deleting = false;
    }
  }

  function when(value: string | null | undefined): string {
    return value
      ? formatDate(value, { dateStyle: 'medium', timeStyle: 'short' })
      : t('myTransfers.detail.never');
  }

  function scanLabel(status: string): string {
    const key = `myTransfers.scan.${status}`;
    return i18n.has(key) ? t(key) : t('myTransfers.scan.unknown');
  }
</script>

{#if transfer === undefined}
  {#if loadFailed}
    <h1 tabindex="-1">{t('myTransfers.detail.title')}</h1>
    <Alert severity="error">{t('common.error.text')}</Alert>
    <div class="tt-cluster">
      <Button variant="secondary" onclick={() => void load()}>{t('common.retry')}</Button>
      <Button variant="secondary" onclick={onback}>{t('myTransfers.detail.back')}</Button>
    </div>
  {:else}
    <h1 tabindex="-1">{t('myTransfers.detail.title')}</h1>
    <Spinner showLabel />
  {/if}
{:else}
  <div class="tt-mb-4">
    <Button variant="link" onclick={onback}>{t('myTransfers.detail.back')}</Button>
  </div>
  <h1 tabindex="-1" bind:this={heading}>{t('myTransfers.detail.title')}</h1>

  <dl class="tt-dl">
    <dt>{t('myTransfers.list.recipients')}</dt>
    <dd class="tt-break">{transfer.recipients.join(', ')}</dd>
    <dt>{t('myTransfers.list.status')}</dt>
    <dd>{t(statusKey(transfer.status))}</dd>
    <dt>{t('myTransfers.detail.created')}</dt>
    <dd>{when(transfer.createdAt)}</dd>
    <dt>{t('myTransfers.list.expires')}</dt>
    <dd>{transfer.expiresAt ? when(transfer.expiresAt) : t('myTransfers.list.noExpiry')}</dd>
    <dt>{t('myTransfers.detail.total')}</dt>
    <dd>
      {t('myTransfers.list.filesValue', {
        count: transfer.fileCount,
        size: formatBytes(transfer.totalBytes),
      })}
    </dd>
    {#if transfer.confidentialityLevel}
      <dt>{t('myTransfers.detail.level')}</dt>
      <dd>{transfer.confidentialityLevel.label}</dd>
    {/if}
    <dt>{t('myTransfers.detail.options')}</dt>
    <dd>
      <ul class="tt-list-plain">
        <li>
          {transfer.passwordProtected
            ? t('myTransfers.detail.option.password')
            : t('myTransfers.detail.option.noPassword')}
        </li>
        {#if transfer.recipientVerification}
          <li>{t('myTransfers.detail.option.verification')}</li>
        {/if}
        {#if transfer.deleteAfterFirstDownload}
          <li>{t('myTransfers.detail.option.deleteAfterFirst')}</li>
        {/if}
        {#if transfer.maxDownloads !== null}
          <li>{t('myTransfers.detail.option.maxDownloads', { count: transfer.maxDownloads })}</li>
        {/if}
      </ul>
    </dd>
    <dt>{t('myTransfers.detail.downloads')}</dt>
    <dd>{transfer.downloadCount}</dd>
  </dl>

  {#if transfer.message}
    <h2 class="tt-text-lg">{t('myTransfers.detail.message')}</h2>
    <p class="tt-break message">{transfer.message}</p>
  {/if}

  <h2 class="tt-text-lg">{t('myTransfers.detail.filesTitle')}</h2>
  {#if transfer.files.length === 0}
    <p>{t('myTransfers.detail.noFiles')}</p>
  {:else}
    <div class="table-wrap">
      <table class="grid">
        <caption class="visually-hidden">{t('myTransfers.detail.filesTitle')}</caption>
        <thead>
          <tr>
            <th scope="col">{t('myTransfers.detail.file.name')}</th>
            <th scope="col">{t('myTransfers.detail.file.size')}</th>
            <th scope="col">{t('myTransfers.detail.file.sha256')}</th>
            <th scope="col">{t('myTransfers.detail.file.scan')}</th>
          </tr>
        </thead>
        <tbody>
          {#each transfer.files as file (file.id)}
            <tr>
              <th scope="row" class="tt-break plain">{file.path ? `${file.path}/` : ''}{file.name}</th>
              <td class="nowrap">{formatBytes(file.size)}</td>
              <td>
                {#if file.sha256}<code class="tt-mono tt-break">{file.sha256}</code>{/if}
              </td>
              <td>{scanLabel(file.scanStatus)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}

  <h2 class="tt-text-lg">{t('myTransfers.detail.trackingTitle')}</h2>
  {#if transfer.recipientTracking.length === 0}
    <p class="tt-text-muted">{t('myTransfers.detail.trackingNone')}</p>
  {:else}
    <div class="table-wrap">
      <table class="grid">
        <caption class="visually-hidden">{t('myTransfers.detail.trackingTitle')}</caption>
        <thead>
          <tr>
            <th scope="col">{t('myTransfers.detail.tracking.recipient')}</th>
            <th scope="col">{t('myTransfers.detail.tracking.verified')}</th>
            <th scope="col">{t('myTransfers.detail.tracking.first')}</th>
            <th scope="col">{t('myTransfers.detail.tracking.last')}</th>
            <th scope="col">{t('myTransfers.detail.tracking.files')}</th>
          </tr>
        </thead>
        <tbody>
          {#each transfer.recipientTracking as track (track.email)}
            <tr>
              <th scope="row" class="tt-break plain">{track.email}</th>
              <td>{when(track.verifiedAt)}</td>
              <td>{when(track.firstDownloadedAt)}</td>
              <td>{when(track.lastDownloadedAt)}</td>
              <td>
                {#if track.downloads.length === 0}
                  {t('myTransfers.detail.tracking.noDownload')}
                {:else}
                  <ul class="tt-list-plain">
                    {#each track.downloads as dl, i (i)}
                      <li class="tt-break">
                        {dl.fileId
                          ? (fileNames.get(dl.fileId) ?? dl.fileId)
                          : t('myTransfers.detail.tracking.archive')}
                        <span class="tt-text-muted tt-text-sm">
                          {t('myTransfers.detail.tracking.count', { count: dl.count, last: when(dl.lastAt) })}
                        </span>
                      </li>
                    {/each}
                  </ul>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}

  <h2 class="tt-text-lg">{t('myTransfers.detail.extend.title')}</h2>
  {#if extendedNotice}
    <Alert severity="success">
      {t('myTransfers.detail.extend.doneUntil', { date: when(transfer.expiresAt) })}
    </Alert>
  {/if}
  {#if extendError}
    <Alert severity="error">{extendError}</Alert>
  {/if}
  {#if canExtend}
    <form class="tt-stack" onsubmit={extend}>
      <RadioGroup
        legend={t('myTransfers.detail.extend.legend')}
        hint={t('myTransfers.detail.extend.hint', {
          date: transfer.extendableTo ? when(transfer.extendableTo) : '',
        })}
        inline
        name="extend-days"
        options={options.map((d) => ({ value: d, label: t('myTransfers.detail.extend.days', { count: d }) }))}
        bind:value={extendDays}
      />
      <div class="tt-cluster">
        <Button type="submit" loading={extending}>{t('myTransfers.detail.extend.submit')}</Button>
      </div>
    </form>
  {:else}
    <p class="tt-text-muted">
      {transfer.status === 'available'
        ? t('myTransfers.detail.extend.unavailable')
        : t('myTransfers.detail.extend.unavailableState')}
    </p>
  {/if}

  <h2 class="tt-text-lg">{t('myTransfers.detail.delete.title')}</h2>
  <p>{t('myTransfers.detail.delete.text')}</p>
  <div class="tt-cluster">
    <Button variant="danger" onclick={() => (deleteOpen = true)}
      >{t('myTransfers.detail.delete.button')}</Button
    >
  </div>

  <Dialog bind:open={deleteOpen} title={t('myTransfers.detail.delete.title')} hideCloseButton={deleting}>
    <p>{t('myTransfers.detail.delete.confirm', { recipients: transfer.recipients.join(', ') })}</p>
    {#if deleteError}
      <Alert severity="error">{deleteError}</Alert>
    {/if}
    {#snippet actions()}
      <Button variant="danger" loading={deleting} onclick={() => void remove()}>
        {t('myTransfers.detail.delete.confirmButton')}
      </Button>
      <Button variant="secondary" disabled={deleting} onclick={() => (deleteOpen = false)}>
        {t('myTransfers.detail.delete.cancel')}
      </Button>
    {/snippet}
  </Dialog>
{/if}

<style>
  .message {
    white-space: pre-line;
  }

  .table-wrap {
    overflow-x: auto;
    margin: var(--tt-space-4) 0;
  }

  .grid {
    width: 100%;
    border-collapse: collapse;
  }

  .grid th,
  .grid td {
    padding: var(--tt-space-2);
    border-bottom: 1px solid var(--tt-border);
    text-align: left;
    vertical-align: top;
  }

  .plain {
    font-weight: var(--tt-font-weight-normal);
  }

  .nowrap {
    white-space: nowrap;
  }
</style>
