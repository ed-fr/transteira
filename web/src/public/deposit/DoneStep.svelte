<script lang="ts">
  // Recap of a finalized transfer: recipients notified, expiry date, options, files with their
  // antivirus status and SHA-256. The download link is never shown to the depositor (design
  // decision D2): the recipients receive it by mail. The one exception is a link-only transfer
  // (since 2.0): no mail is sent, and the link received once in the answer of the finalization
  // is shown here with a Copy button and a warning that it will not be shown again.
  // For an end-to-end encrypted transfer (since 2.0) the decryption key is shown once, to be sent
  // through another channel; a link-only transfer then shows its full link, key included
  // (".../d/<token>#k=<key>"). The key only lives in the flow until this step is left.
  import { Alert, Button, CopyButton } from '../../shared/components';
  import { formatDate, t } from '../../shared/i18n/i18n.svelte';
  import type { DepositFlow } from './flow.svelte';
  import ScanList from './ScanList.svelte';
  import SessionBar from './SessionBar.svelte';

  interface Props {
    flow: DepositFlow;
    onnavigate?: ((path: string) => void) | undefined;
  }

  let { flow, onnavigate }: Props = $props();

  const transfer = $derived(flow.transfer);
  const available = $derived(flow.outcome === 'available');
  const linkOnly = $derived(available && transfer?.linkOnly === true);
  const e2eKey = $derived(available ? flow.e2eKey : undefined);
  const fullLink = $derived(
    flow.linkOnlyUrl === undefined || e2eKey === undefined
      ? flow.linkOnlyUrl
      : `${flow.linkOnlyUrl}#k=${e2eKey}`,
  );
</script>

<SessionBar {flow} {onnavigate} />

<h1 tabindex="-1">{available ? t('deposit.done.title') : t('deposit.done.rejectedTitle')}</h1>

{#if available}
  <Alert severity="success"
    >{t(linkOnly ? 'upload.finalize.availableLinkOnly' : 'upload.finalize.available')}</Alert
  >
{:else}
  <Alert severity="error">{t('upload.finalize.rejected')}</Alert>
{/if}

{#if linkOnly}
  <section aria-labelledby="tt-done-link-title" class="tt-stack">
    <h2 id="tt-done-link-title">{t('deposit.done.linkOnly.title')}</h2>
    {#if flow.linkOnlyUrl}
      <p>{t('deposit.done.linkOnly.intro')}</p>
      <Alert severity="warning" live={false}>
        <p class="tt-text-bold tt-mb-0">{t('deposit.done.linkOnly.shownOnce')}</p>
      </Alert>
      <p class="tt-mb-0" id="tt-done-link-label">
        {e2eKey ? t('deposit.e2e.done.linkLabel') : t('deposit.done.linkOnly.label')}
      </p>
      <code class="tt-done-link" aria-labelledby="tt-done-link-label" data-testid="deposit-done-link"
        >{fullLink}</code
      >
      {#if e2eKey}
        <p class="tt-text-sm tt-mb-0">{t('deposit.e2e.done.linkNote')}</p>
      {/if}
      <div>
        <CopyButton text={fullLink ?? ''} label={t('deposit.done.linkOnly.copy')} />
      </div>
    {:else}
      <Alert severity="info" live={false}>
        {t('deposit.done.linkOnly.missing')}
        {#if onnavigate}
          <Button variant="link" onclick={() => onnavigate('/me')}
            >{t('deposit.done.linkOnly.myTransfers')}</Button
          >
        {/if}
      </Alert>
    {/if}
  </section>
{/if}

{#if e2eKey}
  <section aria-labelledby="tt-done-key-title" class="tt-stack" data-testid="deposit-e2e-key-section">
    <h2 id="tt-done-key-title">{t('deposit.e2e.done.title')}</h2>
    <p>{t('deposit.e2e.done.intro')}</p>
    <Alert severity="warning" live={false}>
      <p class="tt-text-bold tt-mb-0">{t('deposit.e2e.done.shownOnce')}</p>
    </Alert>
    <p class="tt-mb-0" id="tt-done-key-label">{t('deposit.e2e.done.label')}</p>
    <code
      class="tt-done-link"
      id="tt-done-key"
      aria-labelledby="tt-done-key-label"
      data-testid="deposit-e2e-key">{e2eKey}</code
    >
    <div>
      <CopyButton text={e2eKey} label={t('deposit.e2e.done.copy')} />
    </div>
  </section>
{/if}

{#if transfer}
  <dl class="tt-dl">
    {#if transfer.dropLinkLabel}
      <!-- The recipients of a drop link are never shown to its depositor (T-311). -->
      <dt>{t('deposit.done.dropLink')}</dt>
      <dd class="tt-break">{transfer.dropLinkLabel}</dd>
    {/if}
    {#if available && transfer.recipients.length > 0}
      <dt>{linkOnly ? t('deposit.done.recipientsLinkOnly') : t('deposit.done.recipients')}</dt>
      <dd>
        <ul class="tt-list-plain">
          {#each transfer.recipients as recipient, i (i)}
            <li class="tt-break">{recipient}</li>
          {/each}
        </ul>
      </dd>
    {/if}
    {#if available && transfer.expiresAt}
      <dt>{t('deposit.done.expires')}</dt>
      <dd>{formatDate(transfer.expiresAt, { dateStyle: 'full', timeStyle: 'short' })}</dd>
    {/if}
    {#if transfer.endToEndEncrypted}
      <dt>{t('deposit.e2e.done.encryption')}</dt>
      <dd>{t('deposit.e2e.done.encryptionNote')}</dd>
    {/if}
    {#if transfer.passwordProtected}
      <dt>{t('deposit.done.password')}</dt>
      <dd>{t('deposit.done.passwordNote')}</dd>
    {/if}
    {#if transfer.deleteAfterFirstDownload}
      <dt>{t('deposit.done.deleteAfterFirstDownload')}</dt>
      <dd>{t('deposit.done.deleteAfterFirstDownloadNote')}</dd>
    {/if}
  </dl>

  <h2>{t('deposit.done.files')}</h2>
  <ScanList {transfer} e2eFiles={flow.e2eFiles} />
{/if}

<div class="tt-cluster">
  <Button onclick={() => flow.newTransfer()}>{t('deposit.newTransfer')}</Button>
  {#if flow.reply}
    <Button
      variant="secondary"
      onclick={() => onnavigate?.(`/d/${encodeURIComponent(flow.reply?.token ?? '')}`)}
    >
      {t('download.reply.page.doneBack')}
    </Button>
  {/if}
  <Button variant="secondary" loading={flow.busy} onclick={() => void flow.endSession()}>
    {t('deposit.session.end')}
  </Button>
</div>

<style>
  .tt-done-link {
    display: block;
    padding: var(--tt-space-3);
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius-sm);
    background: var(--tt-surface-muted);
    color: var(--tt-text);
    font-family: var(--tt-font-mono);
    word-break: break-all;
    user-select: all;
  }
</style>
