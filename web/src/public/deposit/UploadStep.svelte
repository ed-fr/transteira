<script lang="ts">
  // Upload step (CLAUDE.md section 8.6): overall and per-file progress, pause / resume / retry,
  // cancellation after confirmation. Progress is announced by the flow through announce()
  // (throttled by the engine); the bars themselves are not live regions.
  import { Alert, Button, Dialog, FileList, ProgressBar } from '../../shared/components';
  import { formatBytes, t } from '../../shared/i18n/i18n.svelte';
  import type { FileProgress } from '../../shared/upload/engine';
  import Countdown from './Countdown.svelte';
  import type { DepositFlow } from './flow.svelte';

  interface Props {
    flow: DepositFlow;
  }

  let { flow }: Props = $props();
  let confirmOpen = $state(false);

  const snapshot = $derived(flow.upload);
  const phase = $derived(snapshot?.phase ?? 'idle');
  const running = $derived(phase === 'uploading' || phase === 'retrying');

  function fileText(file: FileProgress): string {
    return file.done
      ? t('upload.fileDone', { name: file.name })
      : t('upload.fileProgress', {
          name: file.name,
          uploaded: formatBytes(file.uploadedBytes),
          size: formatBytes(file.size),
        });
  }

  async function confirmCancel(): Promise<void> {
    confirmOpen = false;
    await flow.cancelUpload();
  }
</script>

<h1 tabindex="-1">{t('upload.title')}</h1>

{#if flow.notice}
  <Alert severity="info">{t(flow.notice.key, flow.notice.params)}</Alert>
{/if}

{#if snapshot}
  <p class="tt-text-bold">{t(`upload.phase.${phase}`)}</p>

  <ProgressBar
    label={t('deposit.upload.overall')}
    value={snapshot.uploadedBytes}
    max={snapshot.totalBytes || 1}
    valueText={t('upload.totalProgress', {
      uploaded: formatBytes(snapshot.uploadedBytes),
      total: formatBytes(snapshot.totalBytes),
      percent: snapshot.percent,
    })}
  />

  {#if phase === 'retrying'}
    <Countdown until={snapshot.retryAt} messageKey="upload.retryIn" />
  {:else if phase === 'paused'}
    <Alert severity={snapshot.pauseReason === 'failures' ? 'warning' : 'info'}>
      {snapshot.pauseReason === 'failures' ? t('upload.paused.failures') : t('upload.paused.user')}
    </Alert>
  {:else if phase === 'failed' && snapshot.error}
    <Alert severity="error">{t(`upload.error.${snapshot.error.code}`)}</Alert>
  {/if}

  <FileList files={snapshot.files} label={t('deposit.upload.files')}>
    {#snippet details(file)}
      <ProgressBar label={fileText(file)} value={file.uploadedBytes} max={file.size || 1} />
    {/snippet}
  </FileList>

  <div class="tt-cluster">
    {#if running}
      <Button variant="secondary" onclick={() => flow.pause()}>{t('upload.actions.pause')}</Button>
    {/if}
    {#if phase === 'retrying'}
      <Button onclick={() => flow.resume()}>{t('upload.actions.retryNow')}</Button>
    {:else if phase === 'paused'}
      <Button onclick={() => flow.resume()}>{t('upload.actions.resume')}</Button>
    {/if}
    {#if phase === 'failed'}
      <Button onclick={() => void flow.abandonTransfer()}>{t('deposit.newTransfer')}</Button>
    {:else if phase !== 'completed' && phase !== 'cancelled'}
      <Button variant="danger" loading={flow.busy} onclick={() => (confirmOpen = true)}>
        {t('upload.actions.cancel')}
      </Button>
    {/if}
  </div>

  {#if running || phase === 'paused'}
    <p class="tt-text-muted tt-text-sm">{t('upload.leaveWarning')}</p>
  {/if}
{/if}

<Dialog bind:open={confirmOpen} title={t('upload.actions.cancel')}>
  <p>{t('upload.actions.confirmCancel')}</p>
  {#snippet actions()}
    <Button variant="danger" onclick={() => void confirmCancel()}>{t('deposit.upload.confirmCancel')}</Button>
    <Button variant="secondary" onclick={() => (confirmOpen = false)}
      >{t('deposit.upload.keepUploading')}</Button
    >
  {/snippet}
</Dialog>
