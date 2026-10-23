<script lang="ts">
  // Files of a transfer with their antivirus status, SHA-256 fingerprint and warnings
  // (scanning and done steps). Every value from the API is rendered as text; the ClamAV
  // signature of an infected file is shown to its sender only, as text.
  import { CopyButton, FileList } from '../../shared/components';
  import { i18n, t } from '../../shared/i18n/i18n.svelte';
  import type { SenderTransfer } from '../../shared/upload/finalize';
  import { scanStatusKey, scanWarningKey } from './flow.svelte';

  interface Props {
    transfer: SenderTransfer;
  }

  let { transfer }: Props = $props();
</script>

<FileList files={transfer.files} label={t('deposit.scan.files')} key={(f) => f.id}>
  {#snippet details(file)}
    {@const warning = scanWarningKey(file.scanStatus)}
    <p class="tt-text-sm tt-mb-0">
      {t('deposit.scan.status', { status: t(scanStatusKey(i18n, file.scanStatus)) })}
    </p>
    {#if file.scanStatus === 'infected' && file.scanSignature}
      <p class="tt-text-sm tt-mb-0 tt-break">
        {t('deposit.scan.signature', { signature: file.scanSignature })}
      </p>
    {/if}
    {#if warning}
      <p class="tt-text-sm tt-text-danger tt-mb-0">{t(warning)}</p>
    {/if}
    {#if file.sha256}
      <div class="tt-cluster tt-text-sm">
        <span>{t('deposit.scan.sha256')}</span>
        <code class="tt-mono tt-break">{file.sha256}</code>
        <CopyButton text={file.sha256} small ariaLabel={t('deposit.scan.copySha256', { name: file.name })} />
      </div>
    {/if}
  {/snippet}
</FileList>
