<script lang="ts">
  // Key figure of a dashboard: a label, a preformatted value and an optional hint (e.g. a
  // variation or a period). Headingless, so that it fits any heading structure. The warning and
  // danger variants add a written prefix read by screen readers and a visible border, never
  // colour alone.
  //
  //   <StatCard label={transfersLabel} value={formatNumber(stats.transfers)} hint={periodText} />
  import { t } from '../../shared/i18n/i18n.svelte';

  interface Props {
    /** What the figure measures. */
    label: string;
    /** The figure, already formatted. */
    value: string;
    /** Extra information under the figure. */
    hint?: string | undefined;
    /** Emphasis of the card (default "default"). */
    variant?: 'default' | 'warning' | 'danger';
    class?: string;
  }

  let { label, value, hint, variant = 'default', class: className = '' }: Props = $props();
</script>

<div class="tt-stat tt-stat--{variant} {className}">
  <p class="tt-stat__label">
    {#if variant !== 'default'}<span class="tt-stat__flag" aria-hidden="true">!</span>
      <span class="visually-hidden">{t(`adminComponents.stat.${variant}`)}</span>{/if}
    {label}
  </p>
  <p class="tt-stat__value">{value}</p>
  {#if hint}
    <p class="tt-stat__hint">{hint}</p>
  {/if}
</div>

<style>
  .tt-stat {
    padding: var(--tt-space-4);
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius);
    background: var(--tt-surface);
  }

  .tt-stat--warning {
    border: 2px solid var(--tt-warning);
    background: var(--tt-warning-bg);
  }

  .tt-stat--danger {
    border: 2px solid var(--tt-danger);
    background: var(--tt-danger-bg);
  }

  .tt-stat p {
    margin: 0;
  }

  .tt-stat__label {
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }

  .tt-stat__flag {
    display: inline-block;
    margin-right: var(--tt-space-1);
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-stat--warning .tt-stat__flag {
    color: var(--tt-warning);
  }

  .tt-stat--danger .tt-stat__flag {
    color: var(--tt-danger);
  }

  .tt-stat .tt-stat__value {
    margin-top: var(--tt-space-1);
    color: var(--tt-text);
    font-size: var(--tt-font-size-2xl);
    font-weight: var(--tt-font-weight-bold);
    line-height: var(--tt-line-height-tight);
    font-variant-numeric: tabular-nums;
    overflow-wrap: anywhere;
  }

  .tt-stat .tt-stat__hint {
    margin-top: var(--tt-space-1);
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }
</style>
