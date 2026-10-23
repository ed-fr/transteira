<script lang="ts">
  // Busy indicator: the animated circle is hidden from assistive technologies, the label is
  // read instead (set label to '' when the surrounding text already says it).
  import { t } from '../i18n/i18n.svelte';

  interface Props {
    /** Text read by screen readers; defaults to "Loading…". Empty: decorative spinner. */
    label?: string;
    /** Shows the label visually next to the spinner instead of only to screen readers. */
    showLabel?: boolean;
    /** Smaller spinner, for buttons. */
    small?: boolean;
  }

  let { label, showLabel = false, small = false }: Props = $props();
  const text = $derived(label ?? t('components.spinner.loading'));
</script>

<span class="spinner-wrap">
  <span class="spinner" class:small aria-hidden="true"></span>
  {#if text !== ''}
    <span class:visually-hidden={!showLabel}>{text}</span>
  {/if}
</span>

<style>
  .spinner-wrap {
    display: inline-flex;
    align-items: center;
    gap: var(--tt-space-2);
  }

  .spinner {
    display: inline-block;
    width: 1.5rem;
    height: 1.5rem;
    border: 3px solid currentColor;
    border-right-color: transparent;
    border-radius: 50%;
    animation: tt-spin 0.8s linear infinite;
  }

  .spinner.small {
    width: 1rem;
    height: 1rem;
    border-width: 2px;
  }

  @keyframes tt-spin {
    to {
      transform: rotate(360deg);
    }
  }

  /* Reduced motion: a static ring (the label still says the page is busy). */
  @media (prefers-reduced-motion: reduce) {
    .spinner {
      animation: none;
      border-right-color: currentColor;
      opacity: 0.6;
    }
  }
</style>
