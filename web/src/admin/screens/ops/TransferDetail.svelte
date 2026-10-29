<script lang="ts">
  // One transfer of a tenant (GET /admin/tenants/{id}/transfers/{transferId}): metadata, sender
  // IP, options, invitation or API token of origin, recipients and files (size, type, SHA-256
  // with a copy button, antivirus result). Metadata only: the API never returns the download
  // link nor the file contents, and none is shown.
  // Actions, shown only when the status allows them:
  // - resend the notification (POST .../resend) to every recipient or to a selection; 409 not
  //   available, 429 limit of 5 per hour with a countdown, 503 no SMTP server (link to the SMTP
  //   screen);
  // - delete (DELETE, optional reason); 409 while an upload runs keeps the dialog open with the
  //   delay; on success, back to the list with an announcement.
  // The tenant sub-navigation is rendered by App.svelte.
  import { onDestroy, onMount, tick } from 'svelte';
  import { ApiProblem } from '../../../shared/api/client';
  import { describeError } from '../../../shared/api/problem';
  import {
    Alert,
    Button,
    Checkbox,
    CopyButton,
    Dialog,
    Spinner,
    TextArea,
    announce,
  } from '../../../shared/components';
  import { formatDate, formatNumber, i18n, locale, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import { createCountdown } from '../../auth/countdown.svelte';
  import ConfirmDialog from '../../components/ConfirmDialog.svelte';
  import DataTable from '../../components/DataTable.svelte';
  import StatusBadge from '../../components/StatusBadge.svelte';
  import { formatBytes as formatBinaryBytes } from '../../forms/bytes';
  import { tenantPath } from '../../shell';
  import type { AdminScreenProps } from '../types';
  import {
    REASON_MAX_LENGTH,
    auditPath,
    canDelete,
    canResend,
    createdVia,
    dateOr,
    deleteBody,
    deleteFailure,
    originLabel,
    rateLimitedText,
    resendBody,
    resendFailure,
    scanView,
    selectAll,
    selectedCount,
    senderIpText,
    statusView,
    trackedDownloads,
    type RecipientTracking,
    type ResendFailure,
    type TransferDetail,
    type TransferFile,
  } from './transfers';

  let { params, nav }: AdminScreenProps = $props();

  const uid = $props.id();
  const tenantId = $derived(params['id'] ?? '');
  const transferId = $derived(params['transferId'] ?? '');
  const listPath = $derived(tenantPath(tenantId, 'transfers'));
  const formatBytes = (n: number): string => formatBinaryBytes(n, locale.current);
  const dateTime = (d: string): string => formatDate(d, { dateStyle: 'medium', timeStyle: 'short' });

  let transfer = $state.raw<TransferDetail | undefined>(undefined);
  let loading = $state(true);
  let notFound = $state(false);
  let loadError = $state('');
  let heading = $state<HTMLHeadingElement | undefined>();

  // Resend.
  const countdown = createCountdown();
  let resendOpen = $state(false);
  let resendBusy = $state(false);
  let selected = $state<Record<string, boolean>>({});
  let resendError = $state<ResendFailure | undefined>(undefined);
  let selectionError = $state('');
  let resendDone = $state('');

  // Deletion.
  let deleteOpen = $state(false);
  let reason = $state('');

  const via = $derived(transfer === undefined ? undefined : createdVia(transfer));
  const resendMessage = $derived(
    resendError === undefined
      ? ''
      : resendError.kind === 'rate-limited' && resendError.retryAfterSeconds !== undefined
        ? rateLimitedText(countdown.remaining, t)
        : resendError.message,
  );

  async function load(): Promise<void> {
    loading = true;
    loadError = '';
    notFound = false;
    try {
      const res = await adminApi.get('/admin/tenants/{tenantId}/transfers/{transferId}', {
        path: { tenantId, transferId },
      });
      // Every recipient needs a defined entry before the resend dialog renders: its
      // checkboxes bind to selected[recipient], and Dialog renders its body while closed.
      selected = selectAll(res.data.recipients);
      transfer = res.data;
    } catch (err) {
      if (err instanceof ApiProblem && err.status === 404) {
        notFound = true;
      } else {
        loadError = describeError(i18n, err).message;
      }
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    void load();
  });

  onDestroy(() => {
    countdown.stop();
  });

  function openResend(): void {
    if (transfer === undefined) {
      return;
    }
    selected = selectAll(transfer.recipients);
    selectionError = '';
    // A rate-limit failure stays visible while its countdown runs (it explains the disabled
    // submit button); other failures are cleared.
    if (!(resendError?.kind === 'rate-limited' && countdown.remaining > 0)) {
      resendError = undefined;
    }
    resendDone = '';
    resendOpen = true;
  }

  async function resend(): Promise<void> {
    if (transfer === undefined || resendBusy) {
      return;
    }
    const count = selectedCount(transfer.recipients, selected);
    if (count === 0) {
      selectionError = t('opsTransfers.resend.noneSelected');
      return;
    }
    selectionError = '';
    resendError = undefined;
    resendBusy = true;
    try {
      const body = resendBody(transfer.recipients, selected);
      await adminApi.post('/admin/tenants/{tenantId}/transfers/{transferId}/resend', {
        path: { tenantId, transferId },
        ...(body === undefined ? {} : { body }),
      });
      resendOpen = false;
      resendDone = t('opsTransfers.resend.success', { count });
      await tick();
      announce(resendDone);
    } catch (err) {
      const failure = resendFailure(describeError(i18n, err), t);
      resendError = failure;
      if (failure.kind === 'rate-limited') {
        countdown.start(failure.retryAfterSeconds);
      } else if (failure.kind === 'not-available') {
        // The status changed meanwhile: refresh the metadata (the action disappears).
        void load();
      }
    } finally {
      resendBusy = false;
    }
  }

  async function resendClosed(): Promise<void> {
    // The resend button is gone (the status changed, 409 then reload): the focus goes to the
    // page heading instead of being lost.
    if (transfer !== undefined && !canResend(transfer.status)) {
      await tick();
      heading?.focus();
    }
  }

  function openDelete(): void {
    reason = '';
    deleteOpen = true;
  }

  async function remove(): Promise<string | void> {
    const body = deleteBody(reason);
    try {
      await adminApi.delete('/admin/tenants/{tenantId}/transfers/{transferId}', {
        path: { tenantId, transferId },
        ...(body === undefined ? {} : { body }),
      });
    } catch (err) {
      return deleteFailure(describeError(i18n, err), t);
    }
    await nav.navigate(listPath);
    announce(t('opsTransfers.delete.done'));
  }
</script>

{#snippet nameCell(file: TransferFile)}
  <span class="tt-break">{file.name}</span>
{/snippet}

{#snippet sizeCell(file: TransferFile)}
  {formatBytes(file.size)}
{/snippet}

{#snippet typeCell(file: TransferFile)}
  <span class="tt-break">{file.mediaType ?? t('opsTransfers.detail.unknownMediaType')}</span>
{/snippet}

{#snippet shaCell(file: TransferFile)}
  {#if file.sha256}
    <span class="tt-sha">
      <code class="tt-break">{file.sha256}</code>
      <CopyButton
        small
        text={file.sha256}
        ariaLabel={t('opsTransfers.detail.copySha256', { name: file.name })}
      />
    </span>
  {:else}
    {t('opsTransfers.detail.noSha256')}
  {/if}
{/snippet}

{#snippet trackedEmailCell(row: RecipientTracking)}
  <span class="tt-break">{row.email}</span>
{/snippet}

{#snippet trackedVerifiedCell(row: RecipientTracking)}
  {dateOr(row.verifiedAt, t('opsTransfers.detail.tracking.noVerified'), dateTime)}
{/snippet}

{#snippet trackedFirstCell(row: RecipientTracking)}
  {dateOr(row.firstDownloadedAt, t('opsTransfers.detail.never'), dateTime)}
{/snippet}

{#snippet trackedLastCell(row: RecipientTracking)}
  {dateOr(row.lastDownloadedAt, t('opsTransfers.detail.never'), dateTime)}
{/snippet}

{#snippet trackedFilesCell(row: RecipientTracking)}
  {@const lines = trackedDownloads(row, transfer?.files ?? [], t('opsTransfers.detail.tracking.archive'))}
  {#if lines.length === 0}
    {t('opsTransfers.detail.tracking.noDownloads')}
  {:else}
    <ul class="tt-lines">
      {#each lines as line, i (i)}
        <li class="tt-break">
          {t('opsTransfers.detail.tracking.downloadLine', {
            name: line.label,
            count: formatNumber(line.count),
            first: dateTime(line.firstAt),
            last: dateTime(line.lastAt),
          })}
        </li>
      {/each}
    </ul>
  {/if}
{/snippet}

{#snippet scanCell(file: TransferFile)}
  {@const view = scanView(file.scanStatus, t)}
  <StatusBadge variant={view.variant} label={view.label} />
{/snippet}

{#if notFound}
  <h1 tabindex="-1">{t('opsTransfers.detail.notFoundTitle')}</h1>
  <p>{t('opsTransfers.detail.notFoundText')}</p>
  <p><a href={nav.href(listPath)} use:nav.link>{t('opsTransfers.detail.backToList')}</a></p>
{:else}
  <h1 tabindex="-1" bind:this={heading}>{t('adminOps.transfers.detailTitle')}</h1>
  <p><a href={nav.href(listPath)} use:nav.link>{t('opsTransfers.detail.backToList')}</a></p>

  {#if loading && transfer === undefined}
    <p><Spinner showLabel label={t('opsTransfers.detail.loadingLabel')} /></p>
  {:else if loadError !== '' && transfer === undefined}
    <Alert severity="error">
      <p>{loadError}</p>
      <Button variant="secondary" onclick={() => void load()}>{t('common.retry')}</Button>
    </Alert>
  {:else if transfer}
    {@const status = statusView(transfer.status, t)}
    {#if loadError !== ''}
      <!-- A refresh failed: the transfer shown may be out of date. -->
      <Alert severity="error">
        <p>{loadError}</p>
        <Button variant="secondary" onclick={() => void load()}>{t('common.retry')}</Button>
      </Alert>
    {/if}
    <section aria-labelledby="{uid}-meta">
      <h2 id="{uid}-meta">{t('opsTransfers.detail.metadataTitle')}</h2>
      <dl class="tt-dl">
        <dt>{t('opsTransfers.detail.status')}</dt>
        <dd><StatusBadge variant={status.variant} label={status.label} /></dd>
        <dt>{t('opsTransfers.detail.created')}</dt>
        <dd>{dateTime(transfer.createdAt)}</dd>
        <dt>{t('opsTransfers.detail.expires')}</dt>
        <dd>{dateOr(transfer.expiresAt, t('opsTransfers.detail.noExpiry'), dateTime)}</dd>
        <dt>{t('opsTransfers.detail.firstDownload')}</dt>
        <dd>{dateOr(transfer.firstDownloadedAt, t('opsTransfers.detail.never'), dateTime)}</dd>
        <dt>{t('opsTransfers.detail.downloadCount')}</dt>
        <dd>
          {#if transfer.maxDownloads != null}
            {t('opsTransfers.detail.downloadsOfMax', {
              count: formatNumber(transfer.downloadCount),
              max: formatNumber(transfer.maxDownloads),
            })}
          {:else}
            {formatNumber(transfer.downloadCount)}
          {/if}
        </dd>
        {#if transfer.confidentialityLevel}
          <dt>{t('opsTransfers.detail.confidentialityLevel')}</dt>
          <dd>{transfer.confidentialityLevel.label}</dd>
        {/if}
        <dt>{t('opsTransfers.detail.sender')}</dt>
        <dd class="tt-break">{transfer.senderEmail}</dd>
        <dt>{t('opsTransfers.detail.senderIp')}</dt>
        <dd class="tt-break">{senderIpText(transfer.senderIp, t)}</dd>
        <dt>{t('opsTransfers.detail.origin')}</dt>
        <dd>{originLabel(transfer.origin, t)}</dd>
        {#if via?.kind === 'invitation'}
          <dt>{t('opsTransfers.detail.invitation')}</dt>
          <dd><code class="tt-break">{via.id}</code></dd>
        {:else if via?.kind === 'token'}
          <dt>{t('opsTransfers.detail.apiToken')}</dt>
          <dd><code class="tt-break">{via.id}</code></dd>
        {/if}
        <dt>{t('opsTransfers.detail.passwordProtected')}</dt>
        <dd>{transfer.passwordProtected ? t('opsTransfers.detail.yes') : t('opsTransfers.detail.no')}</dd>
        <dt>{t('opsTransfers.detail.deleteAfterFirstDownload')}</dt>
        <dd>
          {transfer.deleteAfterFirstDownload ? t('opsTransfers.detail.yes') : t('opsTransfers.detail.no')}
        </dd>
      </dl>
      <p>
        <a href={nav.href(auditPath(tenantId, transfer.createdAt))} use:nav.link>
          {t('opsTransfers.detail.auditLink')}
        </a>
        <br /><span class="tt-hint">{t('opsTransfers.detail.auditHint')}</span>
      </p>
    </section>

    <section aria-labelledby="{uid}-recipients">
      <h2 id="{uid}-recipients">{t('opsTransfers.detail.recipientsTitle')}</h2>
      <!-- recipientTracking is absent for a single shared link (before 1.1),
           empty for per-recipient links not created yet. -->
      {#if transfer.recipientTracking && transfer.recipientVerification !== undefined}
        <p>
          <strong>{t('opsTransfers.detail.tracking.verificationTitle')}</strong>
          {transfer.recipientVerification
            ? t('opsTransfers.detail.tracking.verificationOn')
            : t('opsTransfers.detail.tracking.verificationOff')}
        </p>
      {/if}
      {#if transfer.recipientTracking?.length}
        <DataTable
          caption={t('opsTransfers.detail.tracking.trackingCaption')}
          captionHidden
          rows={transfer.recipientTracking}
          key={(row) => row.email}
          columns={[
            {
              id: 'email',
              header: t('opsTransfers.detail.tracking.recipient'),
              cell: trackedEmailCell,
              rowHeader: true,
            },
            ...(transfer.recipientVerification
              ? [
                  {
                    id: 'verified',
                    header: t('opsTransfers.detail.tracking.verified'),
                    cell: trackedVerifiedCell,
                  },
                ]
              : []),
            { id: 'first', header: t('opsTransfers.detail.tracking.firstDl'), cell: trackedFirstCell },
            { id: 'last', header: t('opsTransfers.detail.tracking.lastDl'), cell: trackedLastCell },
            { id: 'files', header: t('opsTransfers.detail.tracking.downloadsCol'), cell: trackedFilesCell },
          ]}
        />
      {:else}
        <ul>
          {#each transfer.recipients as recipient (recipient)}
            <li class="tt-break">{recipient}</li>
          {/each}
        </ul>
        <p class="tt-hint">
          {transfer.recipientTracking
            ? t('opsTransfers.detail.tracking.trackingPending')
            : t('opsTransfers.detail.tracking.trackingNone')}
        </p>
      {/if}
    </section>

    <section aria-labelledby="{uid}-files">
      <h2 id="{uid}-files">{t('opsTransfers.detail.filesTitle')}</h2>
      <p>{t('opsTransfers.detail.noContent')}</p>
      <DataTable
        caption={t('opsTransfers.detail.filesCaption')}
        captionHidden
        rows={transfer.files}
        key={(file) => file.id}
        columns={[
          { id: 'name', header: t('opsTransfers.detail.filesColumns.name'), cell: nameCell, rowHeader: true },
          { id: 'size', header: t('opsTransfers.detail.filesColumns.size'), cell: sizeCell, align: 'end' },
          { id: 'type', header: t('opsTransfers.detail.filesColumns.mediaType'), cell: typeCell },
          { id: 'sha256', header: t('opsTransfers.detail.filesColumns.sha256'), cell: shaCell },
          { id: 'scan', header: t('opsTransfers.detail.filesColumns.scan'), cell: scanCell },
        ]}
      />
    </section>

    {#if canResend(transfer.status) || canDelete(transfer.status) || resendDone !== ''}
      <section aria-labelledby="{uid}-actions">
        <h2 id="{uid}-actions">{t('opsTransfers.detail.actionsTitle')}</h2>
        {#if resendDone !== ''}
          <Alert severity="success" live={false}>{resendDone}</Alert>
        {/if}
        <div class="tt-actions">
          {#if canResend(transfer.status)}
            <Button variant="secondary" onclick={openResend}>{t('opsTransfers.resend.button')}</Button>
          {/if}
          {#if canDelete(transfer.status)}
            <Button variant="danger" onclick={openDelete}>{t('opsTransfers.delete.button')}</Button>
          {/if}
        </div>
      </section>
    {/if}

    <Dialog
      bind:open={resendOpen}
      title={t('opsTransfers.resend.title')}
      hideCloseButton={resendBusy}
      onclose={() => void resendClosed()}
    >
      <p>{t('opsTransfers.resend.text')}</p>
      <fieldset
        class="tt-recipients"
        aria-describedby={selectionError !== '' ? `${uid}-selection` : undefined}
      >
        <legend>{t('opsTransfers.resend.legend')}</legend>
        {#each transfer.recipients as recipient (recipient)}
          <Checkbox label={recipient} bind:checked={selected[recipient]} />
        {/each}
        {#if selectionError !== ''}
          <p class="tt-error" id="{uid}-selection">{selectionError}</p>
        {/if}
      </fieldset>
      {#if resendMessage !== ''}
        <Alert severity="error">
          <p>{resendMessage}</p>
          {#if resendError?.kind === 'mail-unavailable'}
            <p>
              <a href={nav.href(tenantPath(tenantId, 'smtp'))} use:nav.link>
                {t('opsTransfers.resend.errors.smtpLink')}
              </a>
            </p>
          {/if}
        </Alert>
      {/if}
      {#snippet actions()}
        <Button
          variant="secondary"
          disabled={resendBusy}
          onclick={() => {
            resendOpen = false;
          }}
        >
          {t('admin.common.cancel')}
        </Button>
        <Button
          loading={resendBusy}
          loadingLabel={t('opsTransfers.resend.submitting')}
          disabled={countdown.remaining > 0}
          onclick={resend}
        >
          {t('opsTransfers.resend.submit')}
        </Button>
      {/snippet}
    </Dialog>

    <ConfirmDialog
      bind:open={deleteOpen}
      title={t('opsTransfers.delete.title')}
      text={t('opsTransfers.delete.text')}
      confirmLabel={t('opsTransfers.delete.confirm')}
      busyLabel={t('admin.common.deleting')}
      danger
      onconfirm={remove}
    >
      <TextArea
        label={t('opsTransfers.delete.reasonLabel')}
        hint={t('opsTransfers.delete.reasonHint')}
        maxlength={REASON_MAX_LENGTH}
        rows={3}
        bind:value={reason}
      />
    </ConfirmDialog>
  {/if}
{/if}

<style>
  .tt-sha {
    display: inline-flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--tt-space-2);
  }

  .tt-hint {
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }

  .tt-lines {
    margin: 0;
    padding-left: var(--tt-space-4);
  }

  .tt-actions {
    display: flex;
    flex-wrap: wrap;
    gap: var(--tt-space-3);
  }

  .tt-recipients {
    margin: 0 0 var(--tt-space-4);
    padding: 0;
    border: 0;
  }

  .tt-recipients legend {
    margin-bottom: var(--tt-space-2);
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-error {
    margin: 0;
    color: var(--tt-danger);
    font-weight: var(--tt-font-weight-bold);
  }
</style>
