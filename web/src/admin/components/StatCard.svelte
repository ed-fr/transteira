<script lang="ts">
  // KPI tile of a dashboard (CLAUDE.md section 13.2: transfers, volume, viruses blocked, disk): a
  // label, a preformatted value, an optional trend against the previous period (neutral text,
  // never green or red: trend.ts, plan deviation 10), optional content under the value (e.g. a
  // Gauge) and an optional hint. A card of its own (radius 16 px, decorative --tt-separator
  // border). Headingless, so that it fits any heading structure. The warning and danger variants
  // add a written prefix read by screen readers and a visible border, never colour alone.
  //
  //   <StatCard label={transfersLabel} value={formatNumber(stats.transferCount)}
  //             trend={trendText(trend(now, before), 30, t, formatPercent)} />
  //   <StatCard label={diskLabel} value={percentText}>
  //     <Gauge value={used} max={total} threshold={alert} label={diskLabel} text={alertText} />
  //   </StatCard>
  //
  // Props:
  //   label     what the figure measures
  //   value     the figure, already formatted
  //   trend     trend text (trendText), shown under the value
  //   hint      extra information, last line (e.g. a period)
  //   variant   default | warning | danger
  //   children  optional content under the value (gauge, link)
  import type { Snippet } from 'svelte';
  import { t } from '../../shared/i18n/i18n.svelte';

  interface Props {
    /** What the figure measures. */
    label: string;
    /** The figure, already formatted. */
    value: string;
    /** Trend against the previous period (trendText of trend.ts), neutral text. */
    trend?: string | undefined;
    /** Extra information under the figure. */
    hint?: string | undefined;
    /** Emphasis of the card (default "default"). */
    variant?: 'default' | 'warning' | 'danger';
    /** Content under the value (e.g. a Gauge). */
    children?: Snippet;
    class?: string;
  }

  let { label, value, trend, hint, variant = 'default', children, class: className = '' }: Props = $props();
</script>

<div class="tt-stat tt-stat--{variant} {className}">
  <p class="tt-stat__label">
    {#if variant !== 'default'}<span class="tt-stat__flag" aria-hidden="true">!</span>
      <span class="visually-hidden">{t(`adminComponents.stat.${variant}`)}</span>{/if}
    {label}
  </p>
  <p class="tt-stat__value">{value}</p>
  {#if trend}
    <p class="tt-stat__trend">{trend}</p>
  {/if}
  {#if children}
    <div class="tt-stat__extra">{@render children()}</div>
  {/if}
  {#if hint}
    <p class="tt-stat__hint">{hint}</p>
  {/if}
</div>

<style>
  .tt-stat {
    display: flex;
    flex-direction: column;
    gap: 0.375rem;
    min-width: 0;
    padding: var(--tt-space-5);
    border: var(--tt-border-width) solid var(--tt-separator);
    border-radius: var(--tt-radius-lg);
    background: var(--tt-surface);
    color: var(--tt-text);
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
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-stat--warning .tt-stat__label,
  .tt-stat--danger .tt-stat__label {
    color: var(--tt-text);
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
    color: var(--tt-text);
    font-size: var(--tt-font-size-2xl);
    font-weight: var(--tt-font-weight-heading);
    letter-spacing: -0.02em;
    line-height: var(--tt-line-height-tight);
    font-variant-numeric: tabular-nums;
    overflow-wrap: anywhere;
  }

  .tt-stat .tt-stat__trend,
  .tt-stat .tt-stat__hint {
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }

  .tt-stat--warning .tt-stat__trend,
  .tt-stat--warning .tt-stat__hint,
  .tt-stat--danger .tt-stat__trend,
  .tt-stat--danger .tt-stat__hint {
    color: var(--tt-text);
  }

  .tt-stat__extra {
    margin-top: var(--tt-space-1);
  }

  @media (forced-colors: active) {
    .tt-stat {
      border-color: CanvasText;
    }
  }
</style>
