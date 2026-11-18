<script lang="ts">
  // One file of the download page (CLAUDE.md sections 10 and 13.2), an item of the list "Files of
  // this transfer": the extension badge (decorative), the name (folder prefix muted), the antivirus
  // badge ("Scanned", or "Not scanned: …" whose full explanation is read by screen readers), the
  // size, the abbreviated SHA-256 fingerprint with its Copy button (the full value stays in the
  // page for screen readers and as tooltip) and, at the end of the row, a download control of
  // 44 × 44 px named "Download <folder/name>".
  // An end-to-end encrypted file shows two fingerprints: the one of the original file declared by
  // the sender, and the one of the encrypted file computed by the server.
  //
  // Props:
  //   name, path          file name and folder ('' or absent for the root)
  //   size                size in bytes
  //   scanStatus          antivirus status (badge from scanBadge)
  //   sha256              SHA-256 of the file (plaintext declared by the sender when encrypted)
  //   cipherSha256        end-to-end encryption: SHA-256 of the encrypted file
  //   href                download link (filtered by safeApiHref); "Link unavailable" when absent
  //   action              control replacing the link (end-to-end encryption: a decrypting button);
  //                       give it the class "tt-dlrow__action" for the 44 px square look
  import type { Snippet } from 'svelte';
  import { AbbreviatedHash, Badge, FileTypeBadge, Icon } from '../../../shared/components';
  import { fullName } from '../../../shared/components/folders';
  import { formatBytes, t } from '../../../shared/i18n/i18n.svelte';
  import { scanBadge, type ScanStatus } from '../outcomes';

  interface Props {
    /** File name. */
    name: string;
    /** Folder of the file; '' or absent for the root. */
    path?: string | undefined;
    /** Size in bytes. */
    size: number;
    /** Antivirus status. */
    scanStatus: ScanStatus;
    /** SHA-256 of the file (declared plaintext fingerprint when encrypted end to end). */
    sha256: string;
    /** End-to-end encryption: SHA-256 of the encrypted file. */
    cipherSha256?: string | undefined;
    /** Download link; "Link unavailable" when absent and without action. */
    href?: string | undefined;
    /** Control replacing the download link. */
    action?: Snippet | undefined;
  }

  let { name, path, size, scanStatus, sha256, cipherSha256, href, action }: Props = $props();

  const full = $derived(fullName(path, name));
  const badge = $derived(scanBadge(scanStatus));
  const downloadLabel = $derived(t('download.files.downloadFile', { name: full }));
</script>

<li class="tt-dlrow">
  <FileTypeBadge {name} size="lg" class="tt-dlrow__type" />
  <div class="tt-dlrow__main">
    <div class="tt-dlrow__title">
      <span class="tt-dlrow__name"
        >{#if path}<span class="tt-dlrow__path">{path}/</span>{/if}{name}</span
      >
      {#if badge}
        <Badge variant={badge.variant} icon={badge.variant === 'success' ? 'check' : 'alert'}>
          {#if badge.detail}
            <span aria-hidden="true">{t(badge.label)}</span><span class="visually-hidden"
              >{t(badge.detail)}</span
            >
          {:else}
            {t(badge.label)}
          {/if}
        </Badge>
      {/if}
    </div>
    <div class="tt-dlrow__meta">
      <span class="tt-dlrow__size">{formatBytes(size)}</span>
      {#if cipherSha256 === undefined}
        <AbbreviatedHash hash={sha256} name={full} />
      {/if}
    </div>
    {#if cipherSha256 !== undefined}
      <div class="tt-dlrow__meta">
        <AbbreviatedHash hash={sha256} name={full} label={t('download.e2e.sha256Plain')} />
      </div>
      <div class="tt-dlrow__meta">
        <AbbreviatedHash
          hash={cipherSha256}
          name={full}
          label={t('download.e2e.sha256Cipher')}
          copyLabel={t('download.e2e.copyCipherSha', { name: full })}
        />
      </div>
    {/if}
  </div>
  <div class="tt-dlrow__end">
    {#if action}
      {@render action()}
    {:else if href}
      <a class="tt-dlrow__action" {href} download title={downloadLabel}
        ><Icon name="download" /><span class="visually-hidden">{downloadLabel}</span></a
      >
    {:else}
      <span class="tt-dlrow__unavailable">{t('download.files.unavailable')}</span>
    {/if}
  </div>
</li>

<style>
  .tt-dlrow {
    display: grid;
    grid-template-columns: auto minmax(0, 1fr) auto;
    align-items: center;
    gap: var(--tt-space-3) var(--tt-space-4);
    padding: var(--tt-space-4) 0;
    border-bottom: var(--tt-border-width) solid var(--tt-separator);
  }

  .tt-dlrow__main {
    display: flex;
    flex-direction: column;
    gap: var(--tt-space-1);
    min-width: 0;
  }

  .tt-dlrow__title {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--tt-space-1) var(--tt-space-2);
  }

  .tt-dlrow__name {
    min-width: 0;
    font-weight: var(--tt-font-weight-bold);
    overflow-wrap: anywhere;
  }

  .tt-dlrow__path {
    color: var(--tt-text-muted);
    font-weight: var(--tt-font-weight-normal);
  }

  /* The badge text may wrap on a narrow screen rather than overflow the row. */
  .tt-dlrow__title :global(.tt-badge) {
    white-space: normal;
  }

  .tt-dlrow__meta {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--tt-space-1) var(--tt-space-4);
    color: var(--tt-text-muted);
    font-size: var(--tt-font-size-sm);
  }

  .tt-dlrow__size {
    white-space: nowrap;
  }

  .tt-dlrow__end {
    display: flex;
    justify-content: flex-end;
  }

  .tt-dlrow__unavailable {
    color: var(--tt-text-muted);
    font-size: var(--tt-font-size-sm);
  }

  /* Download control: a square of 44 × 44 px (the link here, or the decrypting Button). */
  .tt-dlrow :global(.tt-dlrow__action) {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: var(--tt-control-height);
    min-width: var(--tt-control-height);
    height: var(--tt-control-height);
    min-height: var(--tt-control-height);
    padding: 0;
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius);
    background: var(--tt-surface);
    color: var(--tt-text);
  }

  .tt-dlrow :global(.tt-dlrow__action:hover:not(:disabled, [aria-disabled='true'])) {
    background: var(--tt-surface-muted);
  }

  @media (max-width: 40rem) {
    .tt-dlrow {
      grid-template-columns: minmax(0, 1fr) auto;
    }

    /* Decorative: the room goes to the name on a phone. */
    .tt-dlrow :global(.tt-dlrow__type) {
      display: none;
    }
  }

  @media (forced-colors: active) {
    .tt-dlrow :global(.tt-dlrow__action) {
      border-color: ButtonText;
    }

    .tt-dlrow :global(a.tt-dlrow__action) {
      border-color: LinkText;
    }
  }
</style>
