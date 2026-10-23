<script lang="ts">
  // Finalization: the files are uploaded, the antivirus analyses them (asynchronously, the page
  // may be closed: the sender is notified by mail). Shows refused files (blocklist) and
  // finalization failures.
  import { Alert, Button, Spinner } from '../../shared/components';
  import { t } from '../../shared/i18n/i18n.svelte';
  import type { DepositFlow } from './flow.svelte';
  import ScanList from './ScanList.svelte';

  interface Props {
    flow: DepositFlow;
  }

  let { flow }: Props = $props();
</script>

<h1 tabindex="-1">{t('deposit.finalizing.title')}</h1>

{#if flow.blockedFiles}
  <Alert severity="error" title={t('upload.finalize.blocked')}>
    <ul class="tt-mb-0">
      {#each flow.blockedFiles as name, i (i)}
        <li class="tt-break">{name}</li>
      {/each}
    </ul>
  </Alert>
  <Button onclick={() => void flow.abandonTransfer()}>{t('deposit.newTransfer')}</Button>
{:else if flow.finalizeError}
  <Alert severity="error">{t(flow.finalizeError.key, flow.finalizeError.params)}</Alert>
  <div class="tt-cluster">
    {#if flow.finalizeRetryable}
      <Button onclick={() => void flow.retryFinalize()}>{t('deposit.finalizing.retry')}</Button>
    {/if}
    <Button
      variant={flow.finalizeRetryable ? 'secondary' : 'primary'}
      onclick={() => void flow.abandonTransfer()}
    >
      {t('deposit.newTransfer')}
    </Button>
  </div>
{:else}
  <Spinner label={t('deposit.finalizing.spinner')} showLabel />
  <p>{t('upload.finalize.scanning')}</p>
  {#if flow.transfer}
    <ScanList transfer={flow.transfer} />
  {/if}
{/if}
