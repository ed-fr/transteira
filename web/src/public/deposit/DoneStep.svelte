<script lang="ts">
  // Recap of a finalized transfer: recipients notified, expiry date, options, files with their
  // antivirus status and SHA-256. The download link is never shown to the depositor (design
  // decision D2): the recipients receive it by mail.
  import { Alert, Button } from '../../shared/components';
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
</script>

<SessionBar {flow} {onnavigate} />

<h1 tabindex="-1">{available ? t('deposit.done.title') : t('deposit.done.rejectedTitle')}</h1>

{#if available}
  <Alert severity="success">{t('upload.finalize.available')}</Alert>
{:else}
  <Alert severity="error">{t('upload.finalize.rejected')}</Alert>
{/if}

{#if transfer}
  <dl class="tt-dl">
    {#if available}
      <dt>{t('deposit.done.recipients')}</dt>
      <dd>
        <ul class="tt-list-plain">
          {#each transfer.recipients as recipient, i (i)}
            <li class="tt-break">{recipient}</li>
          {/each}
        </ul>
      </dd>
      {#if transfer.expiresAt}
        <dt>{t('deposit.done.expires')}</dt>
        <dd>{formatDate(transfer.expiresAt, { dateStyle: 'full', timeStyle: 'short' })}</dd>
      {/if}
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
  <ScanList {transfer} />
{/if}

<div class="tt-cluster">
  <Button onclick={() => flow.newTransfer()}>{t('deposit.newTransfer')}</Button>
  <Button variant="secondary" loading={flow.busy} onclick={() => void flow.endSession()}>
    {t('deposit.session.end')}
  </Button>
</div>
