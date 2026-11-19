<script lang="ts">
  // Storage quota meter (RGAA 3.1; CLAUDE.md section 13.2): a native <meter> (Gauge.svelte: low at
  // the warning ratio, 80 % by default, high at the quota, optimum 0) labelled by the visible label,
  // followed by the visible usage text "12 GiB of 100 GiB (12 %)" (read once: neither repeated as
  // fallback content nor as a description of the meter), and a status pill (OK, nearly full from
  // the warning ratio, full from 100 %) written out in text, never conveyed by colour alone; the
  // fill turns to the warning, then danger colour at those levels. showLevel={false} hides the
  // pill when the screen shows its own state next to the meter (e.g. the disk alert);
  // showLevel="alert" shows it only for the nearly full and full levels (dense tables: those
  // levels are still written out, never conveyed by the colour of the fill alone). The root keeps
  // the class tt-quota (the screenshots mask the disk meter through it).
  //
  //   <QuotaMeter label={storageLabel} used={tenant.storageUsedBytes}
  //               quota={tenant.storageQuotaBytes} />
  //
  // Options (all optional):
  //   labelHidden    the label is read by screen readers only (e.g. in a table row, "Storage of
  //                  Entity A"); the usage text stays visible
  //   compact        thin bar, usage text above it, no bottom margin (table rows)
  //   showThreshold  marks the warning ratio on the track (e.g. the disk alert threshold)
  import { formatNumber, locale, t } from '../../shared/i18n/i18n.svelte';
  import { formatBytes as formatBinaryBytes } from '../forms/bytes';
  import Gauge from './Gauge.svelte';
  import StatusBadge from './StatusBadge.svelte';
  import {
    quotaBadgeVariant,
    quotaGaugeLevel,
    quotaLevel,
    quotaMeterAttributes,
    quotaRatio,
    quotaTexts,
    showsQuotaLevel,
    type QuotaLevelDisplay,
  } from './quota';

  interface Props {
    /** Bytes used. */
    used: number;
    /** Quota in bytes. */
    quota: number;
    /** Visible label of the meter (default "Storage used"). */
    label?: string;
    /** Formats a size (default: binary units in the current language). */
    formatBytes?: (n: number) => string;
    /**
     * Ratio from which the level is "nearly full" (default QUOTA_WARNING_RATIO, 0.8), e.g. the
     * disk alert threshold.
     */
    warningRatio?: number;
    /** Shows the level badge: always (default true), never, or 'alert' (nearly full and full only). */
    showLevel?: QuotaLevelDisplay;
    /** Hides the label visually (it still names the meter). */
    labelHidden?: boolean;
    /** Thin bar for table rows, usage text above it. */
    compact?: boolean;
    /** Marks the warning ratio on the track. */
    showThreshold?: boolean;
    class?: string;
  }

  let {
    used,
    quota,
    label,
    formatBytes,
    warningRatio,
    showLevel = true,
    labelHidden = false,
    compact = false,
    showThreshold = false,
    class: className = '',
  }: Props = $props();

  const uid = $props.id();
  const format = $derived(formatBytes ?? ((n: number) => formatBinaryBytes(n, locale.current)));
  const attrs = $derived(quotaMeterAttributes(used, quota, warningRatio));
  const level = $derived(quotaLevel(quotaRatio(used, quota), warningRatio));
  const levelShown = $derived(showsQuotaLevel(showLevel, level));
  const texts = $derived(
    quotaTexts(
      used,
      quota,
      format,
      (r) => formatNumber(r, { style: 'percent', maximumFractionDigits: 1 }),
      t,
      warningRatio,
    ),
  );
</script>

<div class="tt-quota {className}" class:tt-quota--compact={compact}>
  <div class="tt-quota__head" class:visually-hidden={labelHidden && !levelShown}>
    <span class="tt-quota__label" class:visually-hidden={labelHidden} id="{uid}-label"
      >{label ?? t('adminComponents.quota.label')}</span
    >
    {#if levelShown}
      <StatusBadge variant={quotaBadgeVariant(level)} label={texts.level} />
    {/if}
  </div>
  {#if compact}
    <p class="tt-quota__usage">{texts.usage}</p>
  {/if}
  <Gauge
    min={attrs.min}
    max={attrs.max}
    value={attrs.value}
    low={attrs.low}
    high={attrs.high}
    optimum={attrs.optimum}
    labelledBy="{uid}-label"
    level={quotaGaugeLevel(level)}
    size={compact ? 'sm' : 'md'}
    threshold={showThreshold ? attrs.low : undefined}
  />
  {#if !compact}
    <p class="tt-quota__usage">{texts.usage}</p>
  {/if}
</div>

<style>
  .tt-quota {
    margin-bottom: var(--tt-space-4);
  }

  .tt-quota--compact {
    display: flex;
    flex-direction: column;
    gap: 0.375rem;
    min-width: 10rem;
    margin-bottom: 0;
  }

  .tt-quota__head {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: var(--tt-space-2);
    margin-bottom: var(--tt-space-1);
  }

  .tt-quota--compact .tt-quota__head {
    margin-bottom: 0;
  }

  .tt-quota__label {
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-quota__usage {
    margin: var(--tt-space-1) 0 0;
    font-size: var(--tt-font-size-sm);
    color: var(--tt-muted);
  }

  .tt-quota--compact .tt-quota__usage {
    margin: 0;
    color: var(--tt-text);
  }
</style>
