<script
  lang="ts"
  generics="F extends { name: string; size: number; path?: string | undefined; hidden?: boolean | undefined }"
>
  // List of files with their size, an optional remove button per file (accessible name
  // "Remove <file name>") and an optional total. File names are rendered as text.
  import type { Snippet } from 'svelte';
  import { formatBytes, t } from '../i18n/i18n.svelte';
  import { fullName } from './folders';
  import { totalBytes } from './helpers';

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
    class: className = '',
  }: Props = $props();

  const total = $derived(totalBytes(files));
</script>

{#if files.length > 0}
  <ul class="tt-files {className}" aria-label={label ?? t('components.fileList.label')}>
    {#each files as file, index (key(file, index))}
      <li class="tt-files__item">
        <div class="tt-files__main">
          <span class="tt-files__name">
            {#if file.path}<span class="tt-files__path">{file.path}/</span>{/if}{file.name}
            {#if file.hidden}
              <span class="tt-files__hidden"
                ><span aria-hidden="true">{t('components.fileList.hiddenShort')}</span><span
                  class="visually-hidden">{t('components.fileList.hidden')}</span
                ></span
              >
            {/if}
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

  .tt-files__total {
    margin: 0 0 var(--tt-space-4);
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }
</style>
