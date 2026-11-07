<script lang="ts">
  // Files of a transfer with their antivirus status, SHA-256 fingerprint and warnings
  // (scanning and done steps). Every value from the API is rendered as text; the ClamAV
  // signature of an infected file is shown to its sender only, as text. For an end-to-end
  // encrypted transfer the server only knows generic names (file-<n>.tte2) and the SHA-256 of the
  // ciphertext: the real names and the plaintext SHA-256 known to this page are shown instead.
  import { CopyButton, FileList } from '../../shared/components';
  import { fullName } from '../../shared/components/folders';
  import { i18n, t } from '../../shared/i18n/i18n.svelte';
  import type { SenderTransfer } from '../../shared/upload/finalize';
  import { scanStatusKey, scanWarningKey, type E2EFileInfo } from './flow.svelte';

  interface Props {
    transfer: SenderTransfer;
    /** Real names of the files of an end-to-end encrypted transfer, in the declared order. */
    e2eFiles?: readonly E2EFileInfo[] | undefined;
  }

  let { transfer, e2eFiles }: Props = $props();

  const e2e = $derived(transfer.endToEndEncrypted === true);
  const files = $derived(
    transfer.files.map((file, i) => {
      const info = e2e ? e2eFiles?.[i] : undefined;
      if (!e2e) return file;
      // The SHA-256 of the server is that of the ciphertext: only the plaintext one is shown.
      return { ...file, name: info?.name ?? file.name, path: info?.path ?? '', sha256: info?.sha256 };
    }),
  );
</script>

<FileList {files} label={t('deposit.scan.files')} key={(f) => f.id}>
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
      <p
        class="tt-text-sm tt-mb-0"
        class:tt-text-danger={file.scanStatus !== 'not_scanned_e2e'}
        class:tt-text-muted={file.scanStatus === 'not_scanned_e2e'}
      >
        {t(warning)}
      </p>
    {/if}
    {#if file.sha256}
      <div class="tt-cluster tt-text-sm">
        <span>{t('deposit.scan.sha256')}</span>
        <code class="tt-mono tt-break">{file.sha256}</code>
        <CopyButton
          text={file.sha256}
          small
          ariaLabel={t('deposit.scan.copySha256', { name: fullName(file.path, file.name) })}
        />
      </div>
    {/if}
  {/snippet}
</FileList>
