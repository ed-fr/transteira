<script lang="ts">
  // Gauge of the administration (CLAUDE.md section 13.2: storage of the entities, disk tile; plan
  // of step 3c, deviation 5): a native <meter> (role meter, named by label or labelledBy, value
  // text valueText) drawn as a thin bar, a --tt-graphic fill on a decorative --tt-separator track
  // (.tt-meter of styles/admin.css), the fill turning to --tt-warning or --tt-danger with level.
  // An optional threshold (e.g. the disk alert at 85 %) is marked by a --tt-warning tick drawn in
  // an aria-hidden SVG and positioned by its x attribute only (no inline style: strict CSP); the
  // tick is decorative, so the visible text (text) must say the threshold, e.g. "Alert at 85 % ·
  // 940 GB free". The level is never conveyed by colour alone: say it in text too.
  //
  //   <Gauge value={used} max={total} threshold={total * 0.85} label={diskLabel}
  //          valueText={usedText} level={gaugeLevel(used, total, total * 0.85)} text={alertText} />
  //
  // Props:
  //   value, min (0), max   native meter range
  //   low, high, optimum    native meter attributes (optional; they do not change the colour)
  //   label                 accessible name (aria-label), unless labelledBy is given
  //   labelledBy            id of a visible element naming the meter (aria-labelledby)
  //   valueText             aria-valuetext (e.g. "47 % of 2 TB used")
  //   threshold             value of the threshold marker (in value units), optional
  //   level                 default | warning | danger: colour of the fill
  //   size                  md (8 px bar, default) | sm (6 px, table rows)
  //   text                  visible text under the bar (the text alternative of the marker)
  import { markerPercent, type GaugeLevel } from './gauge';

  interface Props {
    value: number;
    min?: number;
    max: number;
    low?: number | undefined;
    high?: number | undefined;
    optimum?: number | undefined;
    /** Accessible name of the meter (aria-label), when labelledBy is not given. */
    label?: string | undefined;
    /** Id of a visible element naming the meter (aria-labelledby). */
    labelledBy?: string | undefined;
    /** aria-valuetext of the meter. */
    valueText?: string | undefined;
    /** Threshold marked on the track (value units). */
    threshold?: number | undefined;
    /** Colour of the fill. */
    level?: GaugeLevel;
    /** Thickness of the bar. */
    size?: 'sm' | 'md';
    /** Visible text under the bar. */
    text?: string | undefined;
    class?: string;
  }

  let {
    value,
    min = 0,
    max,
    low,
    high,
    optimum,
    label,
    labelledBy,
    valueText,
    threshold,
    level = 'default',
    size = 'md',
    text,
    class: className = '',
  }: Props = $props();

  const marker = $derived(markerPercent(threshold, min, max));
</script>

<div class="tt-gauge-bar tt-gauge-bar--{size} {className}">
  <div class="tt-gauge-bar__track">
    <meter
      class="tt-meter tt-meter--{level}"
      class:tt-meter--sm={size === 'sm'}
      {min}
      {max}
      {value}
      {low}
      {high}
      {optimum}
      aria-label={labelledBy === undefined ? label : undefined}
      aria-labelledby={labelledBy}
      aria-valuetext={valueText}
    ></meter>
    {#if marker !== undefined}
      <svg class="tt-gauge-bar__marker" aria-hidden="true" focusable="false" width="100%" height="16">
        <rect x="{marker}%" y="0" width="3" height="16" rx="1.5" transform="translate(-1.5 0)" />
      </svg>
    {/if}
  </div>
  {#if text}
    <p class="tt-gauge-bar__text">{text}</p>
  {/if}
</div>

<style>
  .tt-gauge-bar {
    display: flex;
    flex-direction: column;
    gap: var(--tt-space-2);
    min-width: 0;
  }

  .tt-gauge-bar__track {
    position: relative;
    padding: 0.25rem 0;
  }

  .tt-gauge-bar--sm .tt-gauge-bar__track {
    padding: 0;
  }

  /* The tick overflows the 8 px bar by 4 px above and below (16 px high, centred on the bar). */
  .tt-gauge-bar__marker {
    position: absolute;
    top: 0;
    left: 0;
    overflow: visible;
    pointer-events: none;
  }

  .tt-gauge-bar__marker rect {
    fill: var(--tt-warning);
  }

  .tt-gauge-bar__text {
    margin: 0;
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }

  @media (forced-colors: active) {
    .tt-gauge-bar__marker rect {
      fill: CanvasText;
    }
  }
</style>
