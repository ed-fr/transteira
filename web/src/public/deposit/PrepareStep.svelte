<script lang="ts">
  // Preparation of an end-to-end encrypted transfer: the browser reads every file once to compute
  // its SHA-256 (sealed in the metadata) before the transfer is created. The bar has a visible
  // label and a textual value (RGAA 3.1); the flow announces the progress every 10 % through the
  // shared live region. The files do not leave the computer during this step. After a reload the
  // same step checks that the reselected files are exactly those hashed before (kind resume).
  import { Button, ProgressBar } from '../../shared/components';
  import { formatBytes, t } from '../../shared/i18n/i18n.svelte';
  import type { DepositFlow } from './flow.svelte';

  interface Props {
    flow: DepositFlow;
  }

  let { flow }: Props = $props();

  const preparation = $derived(flow.preparation);
  const resuming = $derived(preparation?.kind === 'resume');
</script>

<h1 tabindex="-1">{t(resuming ? 'deposit.e2e.preparing.resumeTitle' : 'deposit.e2e.preparing.title')}</h1>

<p>{t(resuming ? 'deposit.e2e.preparing.resumeText' : 'deposit.e2e.preparing.text')}</p>

{#if preparation}
  <div data-testid="deposit-e2e-preparing">
    <ProgressBar
      label={t('deposit.e2e.preparing.progress')}
      value={preparation.hashedBytes}
      max={preparation.totalBytes || 1}
      valueText={t('deposit.e2e.preparing.value', {
        hashed: formatBytes(preparation.hashedBytes),
        total: formatBytes(preparation.totalBytes),
        percent: preparation.percent,
      })}
    />
  </div>
{/if}

<div class="tt-cluster">
  <Button variant="secondary" onclick={() => flow.cancelPreparing()}
    >{t('deposit.e2e.preparing.cancel')}</Button
  >
</div>
