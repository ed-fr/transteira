<script lang="ts">
  // Storage quota meter (RGAA 3.1): a native <meter> (low at the warning ratio, 80 % by default,
  // high at the quota, optimum 0) labelled by the visible label, followed by the visible usage
  // text "12 GiB of 100 GiB (12 %)" (read once: neither repeated as fallback content nor as a
  // description of the meter), and a status badge (OK, nearly full from the warning ratio, full
  // from 100 %) written out in text, never conveyed by colour alone. showLevel={false} hides the
  // badge when the screen shows its own state next to the meter (e.g. the disk alert).
  //
  //   <QuotaMeter label={storageLabel} used={tenant.storageUsedBytes}
  //               quota={tenant.storageQuotaBytes} />
  import { formatNumber, locale, t } from '../../shared/i18n/i18n.svelte';
  import { formatBytes as formatBinaryBytes } from '../forms/bytes';
  import StatusBadge from './StatusBadge.svelte';
  import { quotaBadgeVariant, quotaLevel, quotaMeterAttributes, quotaRatio, quotaTexts } from './quota';

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
    /** Shows the level badge (default true). */
    showLevel?: boolean;
    class?: string;
  }

  let {
    used,
    quota,
    label,
    formatBytes,
    warningRatio,
    showLevel = true,
    class: className = '',
  }: Props = $props();

  const uid = $props.id();
  const format = $derived(formatBytes ?? ((n: number) => formatBinaryBytes(n, locale.current)));
  const attrs = $derived(quotaMeterAttributes(used, quota, warningRatio));
  const level = $derived(quotaLevel(quotaRatio(used, quota), warningRatio));
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

<div class="tt-quota {className}">
  <div class="tt-quota__head">
    <span class="tt-quota__label" id="{uid}-label">{label ?? t('adminComponents.quota.label')}</span>
    {#if showLevel}
      <StatusBadge variant={quotaBadgeVariant(level)} label={texts.level} />
    {/if}
  </div>
  <meter
    class="tt-quota__meter"
    min={attrs.min}
    max={attrs.max}
    value={attrs.value}
    low={attrs.low}
    high={attrs.high}
    optimum={attrs.optimum}
    aria-labelledby="{uid}-label"
  ></meter>
  <p class="tt-quota__usage">{texts.usage}</p>
</div>

<style>
  .tt-quota {
    margin-bottom: var(--tt-space-4);
  }

  .tt-quota__head {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: var(--tt-space-2);
    margin-bottom: var(--tt-space-1);
  }

  .tt-quota__label {
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-quota__meter {
    display: block;
    width: 100%;
    height: 1rem;
  }

  .tt-quota__usage {
    margin: var(--tt-space-1) 0 0;
    font-size: var(--tt-font-size-sm);
    color: var(--tt-muted);
  }
</style>
