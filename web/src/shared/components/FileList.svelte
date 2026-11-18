<script
  lang="ts"
  generics="F extends { name: string; size: number; path?: string | undefined; hidden?: boolean | undefined }"
>
  // List of files with their size, an optional remove button per file (accessible name
  // "Remove <file name>") and an optional total. File names are rendered as text.
  //
  // Variants:
  //   'default'  bordered list, one row per file (administration, legacy screens)
  //   'cards'    one card per file (CLAUDE.md section 13.2): file type badge (FileTypeBadge), name
  //              with its folder path, size under it, the details snippet, and a 44 px remove
  //              button (x icon, same accessible name "Remove <file name>")
  import type { Snippet } from 'svelte';
  import { formatBytes, t } from '../i18n/i18n.svelte';
  import FileTypeBadge from './FileTypeBadge.svelte';
  import { fullName } from './folders';
  import { totalBytes } from './helpers';
  import Icon from './Icon.svelte';

  interface Props {
    /** Files to list (File objects or API file descriptions). */
    files: readonly F[];
    /** Accessible name of the list; defaults to "Selected files". */
    label?: string;
    /** Called with the index of the file to remove; no remove button when absent. */
    onremove?: (index: number, file: F) => void;
    /** Disables the remove buttons (e.g. during the upload). */
    disabled?: boolean;
    /** Shows the number of files and their total size under the list. */
    showTotal?: boolean;
    /** Key of a file for the keyed each block (index by default). */
    key?: (file: F, index: number) => string | number;
    /** Extra content per file (scan status, SHA-256, download link...). */
    details?: Snippet<[F, number]>;
    /** Look of the list: default (bordered rows) or cards (one card per file). */
    variant?: 'default' | 'cards';
    class?: string;
  }

  let {
    files,
    label,
    onremove,
    disabled = false,
    showTotal = false,
    key = (_file: F, index: number) => index,
    details,
    variant = 'default',
    class: className = '',
  }: Props = $props();

  const total = $derived(totalBytes(files));
</script>

{#snippet hiddenBadge(file: F)}
  {#if file.hidden}
    <span class="tt-files__hidden"
      ><span aria-hidden="true">{t('components.fileList.hiddenShort')}</span><span class="visually-hidden"
        >{t('components.fileList.hidden')}</span
      ></span
    >
  {/if}
{/snippet}

{#if files.length > 0}
  {#if variant === 'cards'}
    <ul class="tt-files tt-files--cards {className}" aria-label={label ?? t('components.fileList.label')}>
      {#each files as file, index (key(file, index))}
        <li class="tt-files__card">
          <FileTypeBadge name={file.name} />
          <div class="tt-files__body">
            <span class="tt-files__name">
              {#if file.path}<span class="tt-files__path">{file.path}/</span>{/if}{file.name}
              {@render hiddenBadge(file)}
            </span>
            <span class="tt-files__size">{formatBytes(file.size)}</span>
            {#if details}
              <div class="tt-files__details">{@render details(file, index)}</div>
            {/if}
          </div>
          {#if onremove}
            <button
              type="button"
              class="tt-files__remove tt-files__remove--card"
              {disabled}
              aria-label={t('components.fileList.remove', { name: fullName(file.path, file.name) })}
              onclick={() => onremove(index, file)}
            >
              <Icon name="x" />
            </button>
          {/if}
        </li>
      {/each}
    </ul>
  {:else}
    <ul class="tt-files {className}" aria-label={label ?? t('components.fileList.label')}>
      {#each files as file, index (key(file, index))}
        <li class="tt-files__item">
          <div class="tt-files__main">
            <span class="tt-files__name">
              {#if file.path}<span class="tt-files__path">{file.path}/</span>{/if}{file.name}
              {@render hiddenBadge(file)}
            </span>
            <span class="tt-files__size">{formatBytes(file.size)}</span>
            {#if onremove}
              <button
                type="button"
                class="tt-files__remove"
                {disabled}
                aria-label={t('components.fileList.remove', { name: fullName(file.path, file.name) })}
                onclick={() => onremove(index, file)}
              >
                <span aria-hidden="true">×</span>
              </button>
            {/if}
          </div>
          {#if details}
            <div class="tt-files__details">{@render details(file, index)}</div>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
  {#if showTotal}
    <p class="tt-files__total">
      {t('components.fileList.total', { count: files.length, size: formatBytes(total) })}
    </p>
  {/if}
{/if}

<style>
  .tt-files {
    margin: 0 0 var(--tt-space-2);
    padding: 0;
    list-style: none;
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius);
  }

  .tt-files__item {
    padding: var(--tt-space-2) var(--tt-space-3);
  }

  .tt-files__item + .tt-files__item {
    border-top: var(--tt-border-width) solid var(--tt-surface-muted);
  }

  .tt-files__main {
    display: flex;
    align-items: center;
    gap: var(--tt-space-3);
  }

  .tt-files__name {
    flex: 1;
    min-width: 0;
    overflow-wrap: anywhere;
  }

  .tt-files__path {
    color: var(--tt-muted);
  }

  .tt-files__hidden {
    display: inline-block;
    margin-left: var(--tt-space-2);
    padding: 0 var(--tt-space-2);
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius-sm);
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
    white-space: nowrap;
  }

  .tt-files__size {
    flex: none;
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
    white-space: nowrap;
  }

  .tt-files__remove {
    flex: none;
    width: 2rem;
    height: 2rem;
    padding: 0;
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius-sm);
    background: var(--tt-surface);
    color: var(--tt-danger);
    font-size: var(--tt-font-size-lg);
    line-height: 1;
    cursor: pointer;
  }

  .tt-files__remove:disabled {
    cursor: not-allowed;
    opacity: 0.65;
  }

  .tt-files__details {
    margin-top: var(--tt-space-1);
    font-size: var(--tt-font-size-sm);
  }

  /* Cards variant. */
  .tt-files--cards {
    display: flex;
    flex-direction: column;
    gap: var(--tt-space-2);
    border: 0;
    border-radius: 0;
  }

  /* Top-aligned: the badge and the remove button stay next to the name on tall cards (scan status,
     SHA-256 and warnings in the details). */
  .tt-files__card {
    display: flex;
    align-items: flex-start;
    gap: var(--tt-space-3);
    padding: var(--tt-space-2) var(--tt-space-2) var(--tt-space-2) var(--tt-space-3);
    border: var(--tt-border-width) solid var(--tt-separator);
    border-radius: var(--tt-radius-lg);
    background: var(--tt-surface);
  }

  .tt-files__body {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
  }

  .tt-files--cards .tt-files__name {
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-files--cards .tt-files__size {
    white-space: normal;
  }

  .tt-files__remove--card {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 2.75rem;
    height: 2.75rem;
    border-color: transparent;
    border-radius: var(--tt-radius);
    background: none;
    color: var(--tt-muted);
  }

  .tt-files__remove--card:hover:not(:disabled) {
    border-color: var(--tt-border);
    color: var(--tt-danger);
  }

  :global(.tt-page--public) .tt-files__remove {
    width: 2.75rem;
    height: 2.75rem;
  }

  @media (forced-colors: active) {
    .tt-files__card {
      border-color: CanvasText;
    }
  }

  .tt-files__total {
    margin: 0 0 var(--tt-space-4);
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }
</style>
