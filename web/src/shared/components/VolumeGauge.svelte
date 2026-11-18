<script lang="ts">
  // Volume gauge of a transfer (CLAUDE.md section 13.2, deposit files column): the number of files
  // and their total size ("3 files · 4.2 GB"), the share of the limit ("21% of the limit") and a
  // native <meter> (role meter, named "Volume of the transfer", value text "4.2 GB of 20 GB"). Over
  // the limit, the bar turns to the danger colour and the text says so ("Over the limit of 20 GB",
  // with an alert icon): never colour alone. The bar is a graphic: its fill (--tt-graphic, or
  // --tt-danger) reaches 3:1 on its --tt-surface track, outlined by --tt-border. Without a positive
  // limit, only the summary is shown. Changes are not announced here (the screen announces them).
  //
  // Props:
  //   used    total size of the files, in bytes
  //   count   number of files
  //   limit   size limit of the transfer, in bytes (optional)
  //   label   accessible name of the meter (default "Volume of the transfer")
  import { formatBytes, t } from '../i18n/i18n.svelte';
  import Icon from './Icon.svelte';
  import { volumeState } from './helpers';

  interface Props {
    /** Total size of the files, in bytes. */
    used: number;
    /** Number of files. */
    count: number;
    /** Size limit of the transfer, in bytes. */
    limit?: number | undefined;
    /** Accessible name of the meter. */
    label?: string | undefined;
    class?: string;
  }

  let { used, count, limit, label, class: className = '' }: Props = $props();

  const gauge = $derived(volumeState(used, limit));
  const size = $derived(formatBytes(used));
  const limitText = $derived(limit !== undefined && limit > 0 ? formatBytes(limit) : '');
</script>

<div class="tt-gauge {className}" class:tt-gauge--over={gauge.over}>
  <p class="tt-gauge__text">
    <span>{t('components.volumeGauge.summary', { count, size })}</span>
    {#if gauge.percent !== undefined}
      {#if gauge.over}
        <span class="tt-gauge__over">
          <Icon name="alert" size="sm" />
          {t('components.volumeGauge.over', { limit: limitText })}
        </span>
      {:else}
        <span>{t('components.volumeGauge.percent', { percent: gauge.percent })}</span>
      {/if}
    {/if}
  </p>
  {#if gauge.percent !== undefined}
    <meter
      class="tt-gauge__meter"
      min="0"
      max={limit}
      value={gauge.value}
      aria-label={label ?? t('components.volumeGauge.label')}
      aria-valuetext={t('components.volumeGauge.value', { size, limit: limitText })}
    ></meter>
  {/if}
</div>

<style>
  .tt-gauge {
    display: flex;
    flex-direction: column;
    gap: var(--tt-space-1);
  }

  .tt-gauge__text {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    gap: var(--tt-space-1) var(--tt-space-3);
    margin: 0;
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }

  .tt-gauge__over {
    display: inline-flex;
    align-items: center;
    gap: var(--tt-space-1);
    color: var(--tt-danger);
    font-weight: var(--tt-font-weight-bold);
  }

  /*
   * Native meter, drawn with its pseudo-elements: a --tt-surface track outlined by --tt-border and
   * a --tt-graphic fill (--tt-danger over the limit), whatever the low / high / optimum state.
   * Chromium and WebKit draw the track on ::-webkit-meter-bar (a percentage height does not apply
   * there, hence the fixed height); Firefox draws it on the element itself.
   */
  .tt-gauge__meter {
    display: block;
    width: 100%;
    height: 0.75rem;
    border: 0;
    background: none;
  }

  .tt-gauge__meter::-webkit-meter-bar {
    box-sizing: border-box;
    height: 0.75rem;
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius-full);
    background: var(--tt-surface);
  }

  .tt-gauge__meter::-webkit-meter-optimum-value,
  .tt-gauge__meter::-webkit-meter-suboptimum-value,
  .tt-gauge__meter::-webkit-meter-even-less-good-value {
    border-radius: var(--tt-radius-full);
    background: var(--tt-graphic);
  }

  @supports selector(::-moz-meter-bar) {
    .tt-gauge__meter {
      border: var(--tt-border-width) solid var(--tt-border);
      border-radius: var(--tt-radius-full);
      background: var(--tt-surface);
    }
  }

  .tt-gauge__meter::-moz-meter-bar {
    border-radius: var(--tt-radius-full);
    background: var(--tt-graphic);
  }

  .tt-gauge--over .tt-gauge__meter::-webkit-meter-optimum-value,
  .tt-gauge--over .tt-gauge__meter::-webkit-meter-suboptimum-value,
  .tt-gauge--over .tt-gauge__meter::-webkit-meter-even-less-good-value {
    background: var(--tt-danger);
  }

  .tt-gauge--over .tt-gauge__meter::-moz-meter-bar {
    background: var(--tt-danger);
  }

  /* Forced colours: system colours for the track and the fill (backgrounds would be dropped). */
  @media (forced-colors: active) {
    .tt-gauge__meter {
      forced-color-adjust: none;
    }

    .tt-gauge__meter::-webkit-meter-bar {
      border-color: CanvasText;
      background: Canvas;
    }

    /* Separate rules: a selector list with a pseudo-element unknown to the engine is dropped whole. */
    .tt-gauge__meter::-webkit-meter-optimum-value,
    .tt-gauge__meter::-webkit-meter-suboptimum-value,
    .tt-gauge__meter::-webkit-meter-even-less-good-value {
      background: Highlight;
    }

    .tt-gauge__meter::-moz-meter-bar {
      background: Highlight;
    }
  }
</style>
