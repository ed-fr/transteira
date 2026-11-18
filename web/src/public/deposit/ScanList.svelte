<script lang="ts">
  // Files of a transfer with their antivirus status, SHA-256 fingerprint and warnings
  // (scanning and done steps), as file cards (CLAUDE.md section 13.2). Every value from the API is
  // rendered as text; the ClamAV signature of an infected file is shown to its sender only, as
  // text. The status is a sentence ("Antivirus: no threat found") after an icon in the status
  // colour (never the colour alone). The full fingerprint stays visible (the sender compares it)
  // with a Copy button. For an end-to-end encrypted transfer the server only knows generic names
  // (file-<n>.tte2) and the SHA-256 of the ciphertext: the real names and the plaintext SHA-256
  // known to this page are shown instead.
  import { CopyButton, FileList, Icon } from '../../shared/components';
  import { fullName } from '../../shared/components/folders';
  import { i18n, t } from '../../shared/i18n/i18n.svelte';
  import type { SenderTransfer } from '../../shared/upload/finalize';
  import { scanStatusKey, scanWarningKey, type E2EFileInfo } from './flow.svelte';
  import { scanStatusIcon } from './view';

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

<FileList {files} label={t('deposit.scan.files')} key={(f) => f.id} variant="cards">
  {#snippet details(file)}
    {@const warning = scanWarningKey(file.scanStatus)}
    {@const status = scanStatusIcon(file.scanStatus)}
    <p class="tt-scan__status">
      <span class="tt-scan__icon tt-scan__icon--{status.tone}"><Icon name={status.icon} size="sm" /></span>
      <span>{t('deposit.scan.status', { status: t(scanStatusKey(i18n, file.scanStatus)) })}</span>
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
      <div class="tt-scan__hash">
        <span class="tt-text-muted">{t('deposit.scan.sha256')}</span>
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

<style>
  .tt-scan__status {
    display: flex;
    align-items: center;
    gap: var(--tt-space-1);
    margin: 0;
    font-size: var(--tt-font-size-sm);
  }

  .tt-scan__icon {
    display: inline-flex;
    flex: none;
  }

  .tt-scan__icon--success {
    color: var(--tt-success);
  }

  .tt-scan__icon--warning {
    color: var(--tt-warning);
  }

  .tt-scan__icon--danger {
    color: var(--tt-danger);
  }

  .tt-scan__icon--muted {
    color: var(--tt-muted);
  }

  .tt-scan__hash {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--tt-space-1) var(--tt-space-2);
    margin-top: var(--tt-space-1);
    font-size: var(--tt-font-size-sm);
  }

  .tt-scan__hash code {
    min-width: 0;
  }
</style>
