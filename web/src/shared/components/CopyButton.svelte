<script lang="ts">
  // Copies a value to the clipboard (Clipboard API, execCommand fallback) and announces the
  // result through its own polite live region; the button label shows it for a few seconds.
  import { onDestroy } from 'svelte';
  import { t } from '../i18n/i18n.svelte';
  import { copyText } from './helpers';
  import LiveRegion from './LiveRegion.svelte';

  interface Props {
    /** Value to copy. */
    text: string;
    /** Visible label; defaults to "Copy". */
    label?: string;
    /** Accessible name when the visible label is not explicit enough (e.g. "Copy the SHA-256 of report.pdf"). */
    ariaLabel?: string;
    /** Smaller button. */
    small?: boolean;
    class?: string;
  }

  let { text, label, ariaLabel, small = false, class: className = '' }: Props = $props();

  let status = $state<'idle' | 'copied' | 'failed'>('idle');
  let timer: ReturnType<typeof setTimeout> | undefined;

  const message = $derived(
    status === 'copied'
      ? t('components.copy.copied')
      : status === 'failed'
        ? t('components.copy.failed')
        : '',
  );

  async function copy(): Promise<void> {
    clearTimeout(timer);
    status = 'idle';
    status = (await copyText(text)) ? 'copied' : 'failed';
    timer = setTimeout(() => {
      status = 'idle';
    }, 4000);
  }

  onDestroy(() => clearTimeout(timer));
</script>

<button
  type="button"
  class="tt-copy {className}"
  class:tt-copy--small={small}
  aria-label={ariaLabel}
  onclick={copy}
>
  {label ?? t('components.copy.label')}
</button>
<LiveRegion {message} />
{#if status === 'failed'}
  <span class="tt-copy__failed">{message}</span>
{/if}

<style>
  .tt-copy {
    min-height: 2.25rem;
    padding: var(--tt-space-1) var(--tt-space-3);
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius-sm);
    background: var(--tt-surface);
    color: var(--tt-text);
    cursor: pointer;
  }

  .tt-copy--small {
    min-height: 1.75rem;
    padding: 0 var(--tt-space-2);
    font-size: var(--tt-font-size-sm);
  }

  .tt-copy__failed {
    display: block;
    margin-top: var(--tt-space-1);
    color: var(--tt-danger);
    font-size: var(--tt-font-size-sm);
  }
</style>
