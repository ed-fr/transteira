<script lang="ts">
  // Native <progress> with a visible label and a textual value (the bar alone is not enough,
  // RGAA 3.1). Without value, the bar is indeterminate. Pair it with announce() for periodic
  // screen reader updates: the bar itself is not a live region.
  import { t } from '../i18n/i18n.svelte';
  import { percentOf } from './helpers';

  interface Props {
    /** Visible label (e.g. "Upload of report.pdf"). */
    label: string;
    /** Current value; undefined for an indeterminate bar. */
    value?: number | undefined;
    /** Maximum (default 100). */
    max?: number;
    /** Text shown next to the bar; defaults to the percentage. */
    valueText?: string;
    class?: string;
  }

  let { label, value, max = 100, valueText, class: className = '' }: Props = $props();

  const uid = $props.id();
  const percent = $derived(value === undefined ? undefined : percentOf(value, max));
  const text = $derived(
    valueText ??
      (percent === undefined ? '' : t('components.progress.value', { percent: Math.floor(percent) })),
  );
</script>

<div class="tt-progress {className}">
  <div class="tt-progress__header">
    <label class="tt-progress__label" for="{uid}-bar">{label}</label>
    {#if text}<span class="tt-progress__value" id="{uid}-value">{text}</span>{/if}
  </div>
  <progress
    id="{uid}-bar"
    class="tt-progress__bar"
    value={value === undefined ? undefined : Math.min(Math.max(0, value), max)}
    {max}
    aria-describedby={text ? `${uid}-value` : undefined}
  ></progress>
</div>

<style>
  .tt-progress {
    margin-bottom: var(--tt-space-4);
  }

  .tt-progress__header {
    display: flex;
    justify-content: space-between;
    gap: var(--tt-space-3);
    margin-bottom: var(--tt-space-1);
  }

  .tt-progress__label {
    min-width: 0;
    overflow-wrap: anywhere;
  }

  .tt-progress__value {
    flex: none;
    font-variant-numeric: tabular-nums;
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-progress__bar {
    display: block;
    width: 100%;
    height: 0.75rem;
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius);
    background: var(--tt-surface-muted);
    accent-color: var(--tt-graphic);
    appearance: none;
    overflow: hidden;
  }

  .tt-progress__bar::-webkit-progress-bar {
    background: var(--tt-surface-muted);
  }

  .tt-progress__bar::-webkit-progress-value {
    background: var(--tt-graphic);
  }

  .tt-progress__bar::-moz-progress-bar {
    background: var(--tt-graphic);
  }
</style>
