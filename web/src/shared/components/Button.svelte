<script lang="ts">
  // Button with variants and a loading state. While loading, the button keeps the focus
  // (aria-disabled rather than disabled), is marked aria-busy and ignores clicks.
  import type { Snippet } from 'svelte';
  import type { HTMLButtonAttributes } from 'svelte/elements';
  import { t } from '../i18n/i18n.svelte';
  import Spinner from './Spinner.svelte';

  interface Props extends Omit<HTMLButtonAttributes, 'type' | 'style' | 'children' | 'onclick'> {
    /** Visual variant. */
    variant?: 'primary' | 'secondary' | 'danger' | 'link';
    /** Button type; "button" by default (never submits by accident). */
    type?: 'button' | 'submit' | 'reset';
    /** Loading state: spinner, aria-busy, clicks ignored. */
    loading?: boolean;
    /** Text read while loading; defaults to "Please wait…". */
    loadingLabel?: string;
    /** Disabled state (native disabled attribute). */
    disabled?: boolean;
    /** Takes the full width of its container. */
    fullWidth?: boolean;
    /** Smaller button (lists, inline actions). */
    small?: boolean;
    /** Click handler, not called while loading or disabled. */
    onclick?: (event: MouseEvent) => void;
    /** The button element, for focus management. */
    element?: HTMLButtonElement | undefined;
    children: Snippet;
  }

  let {
    variant = 'primary',
    type = 'button',
    loading = false,
    loadingLabel,
    disabled = false,
    fullWidth = false,
    small = false,
    onclick,
    element = $bindable(),
    children,
    class: className = '',
    ...rest
  }: Props = $props();

  function handleClick(event: MouseEvent): void {
    if (loading) {
      event.preventDefault();
      return;
    }
    onclick?.(event);
  }
</script>

<button
  {...rest}
  bind:this={element}
  {type}
  class="tt-button tt-button--{variant} {className}"
  class:tt-button--full={fullWidth}
  class:tt-button--small={small}
  {disabled}
  aria-busy={loading ? 'true' : undefined}
  aria-disabled={loading ? 'true' : undefined}
  onclick={handleClick}
>
  {#if loading}
    <Spinner small label={loadingLabel ?? t('components.button.loading')} />
  {/if}
  <span class="tt-button__label">{@render children()}</span>
</button>

<style>
  .tt-button {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: var(--tt-space-2);
    min-height: var(--tt-control-height);
    padding: var(--tt-space-2) var(--tt-space-5);
    border: 2px solid transparent;
    border-radius: var(--tt-radius);
    font-weight: var(--tt-font-weight-bold);
    line-height: var(--tt-line-height-tight);
    text-align: center;
    cursor: pointer;
  }

  .tt-button--small {
    min-height: 2rem;
    padding: var(--tt-space-1) var(--tt-space-3);
    font-size: var(--tt-font-size-sm);
  }

  .tt-button--full {
    width: 100%;
  }

  .tt-button--primary {
    background: var(--tt-primary);
    border-color: var(--tt-primary);
    color: var(--tt-on-primary);
  }

  .tt-button--secondary {
    background: var(--tt-surface);
    border-color: var(--tt-border);
    color: var(--tt-text);
  }

  .tt-button--danger {
    background: var(--tt-danger);
    border-color: var(--tt-danger);
    color: var(--tt-on-danger);
  }

  .tt-button--link {
    min-height: auto;
    padding: 0;
    background: none;
    color: var(--tt-link);
    font-weight: var(--tt-font-weight-normal);
    text-decoration: underline;
  }

  .tt-button:hover:not(:disabled, [aria-disabled='true']) .tt-button__label {
    text-decoration: underline;
  }

  .tt-button:disabled,
  .tt-button[aria-disabled='true'] {
    cursor: not-allowed;
    opacity: 0.65;
  }

  .tt-button[aria-busy='true'] {
    cursor: progress;
  }
</style>
