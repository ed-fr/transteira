<script lang="ts">
  // Vertical bar chart in SVG (RGAA 1.1, 1.3, 3.2). The geometry comes from charts.ts and is
  // applied by SVG attributes (no inline style, CSP style-src 'self'); colours come from the
  // theme variables through CSS classes. The chart is one image (role="img") named by its title
  // and a summary of the series (count, minimum, maximum, total); a toggle reveals an
  // equivalent table with every value. The SVG scales to its container (viewBox, width 100 %).
  //
  //   <BarChart title={dailyTitle} series={days.map((d) => ({ label: d.date, value: d.bytes }))}
  //             formatValue={(n) => formatBytes(n)} formatLabel={(d) => formatDate(d)} />
  import { t } from '../../shared/i18n/i18n.svelte';
  import { barLayout, chartSummaryText, labelIndexes, type ChartPoint } from './charts';

  interface Props {
    /** Title of the chart: visible caption of the figure, accessible name, <title> and caption of the table. */
    title: string;
    /** Points of the series, in display order. */
    series: readonly ChartPoint[];
    /** Formats a value (axis, table, summary). */
    formatValue: (n: number) => string;
    /** Formats a point label (x axis, table, summary); identity by default. */
    formatLabel?: (label: string) => string;
    /** Height of the chart in SVG units (default 240; the width is 640, scaled to the container). */
    height?: number;
    /** Header of the label column of the table (default "Period"). */
    labelHeader?: string;
    /** Header of the value column of the table (default "Value"). */
    valueHeader?: string;
    class?: string;
  }

  let {
    title,
    series,
    formatValue,
    formatLabel = (label: string) => label,
    height = 240,
    labelHeader,
    valueHeader,
    class: className = '',
  }: Props = $props();

  const WIDTH = 640;
  const uid = $props.id();
  const tableId = `${uid}-table`;
  let showTable = $state(false);

  const layout = $derived(barLayout(series, { width: WIDTH, height, left: 72, bottom: 28 }));
  const summary = $derived(chartSummaryText(title, series, formatValue, t, formatLabel));
  // About one x-axis label every 80 units, so that they do not overlap.
  const shown = $derived(new Set(labelIndexes(series.length, Math.floor(layout.plot.width / 80))));
</script>

<figure class="tt-chart {className}">
  <figcaption class="tt-chart__title">{title}</figcaption>
  <svg
    class="tt-chart__svg"
    viewBox="0 0 {WIDTH} {height}"
    width="100%"
    preserveAspectRatio="xMidYMid meet"
    role="img"
    aria-label={summary}
  >
    <title>{summary}</title>
    {#each layout.ticks as tick (tick.value)}
      <line
        class="tt-chart__grid"
        x1={layout.plot.x}
        x2={layout.plot.x + layout.plot.width}
        y1={tick.y}
        y2={tick.y}
      />
      <text
        class="tt-chart__tick"
        x={layout.plot.x - 8}
        y={tick.y}
        text-anchor="end"
        dominant-baseline="middle"
      >
        {formatValue(tick.value)}
      </text>
    {/each}
    {#each layout.bars as bar, index (index)}
      <rect class="tt-chart__bar" x={bar.x} y={bar.y} width={bar.width} height={bar.height} />
      {#if shown.has(index)}
        <text
          class="tt-chart__label"
          x={bar.cx}
          y={layout.plot.y + layout.plot.height + 18}
          text-anchor="middle"
        >
          {formatLabel(bar.label)}
        </text>
      {/if}
    {/each}
    <line
      class="tt-chart__axis"
      x1={layout.plot.x}
      x2={layout.plot.x + layout.plot.width}
      y1={layout.plot.y + layout.plot.height}
      y2={layout.plot.y + layout.plot.height}
    />
  </svg>
  <button
    type="button"
    class="tt-chart__toggle"
    aria-expanded={showTable}
    aria-controls={tableId}
    onclick={() => {
      showTable = !showTable;
    }}
  >
    {showTable ? t('adminComponents.chart.hideTable') : t('adminComponents.chart.showTable')}
  </button>
  <div id={tableId} class="tt-chart__table-wrap" hidden={!showTable}>
    {#if showTable}
      <table class="tt-chart__table">
        <caption>{title}</caption>
        <thead>
          <tr>
            <th scope="col">{labelHeader ?? t('adminComponents.chart.label')}</th>
            <th scope="col" class="tt-chart__num">{valueHeader ?? t('adminComponents.chart.value')}</th>
          </tr>
        </thead>
        <tbody>
          {#each series as point, index (index)}
            <tr>
              <th scope="row">{formatLabel(point.label)}</th>
              <td class="tt-chart__num">{formatValue(point.value)}</td>
            </tr>
          {:else}
            <tr>
              <td colspan="2">{t('adminComponents.chart.empty')}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>
</figure>

<style>
  .tt-chart {
    margin: 0 0 var(--tt-space-6);
  }

  .tt-chart__title {
    margin-bottom: var(--tt-space-2);
    font-weight: 600;
  }

  .tt-chart__svg {
    display: block;
    max-width: 100%;
    height: auto;
  }

  .tt-chart__bar {
    fill: var(--tt-primary);
  }

  .tt-chart__grid {
    stroke: var(--tt-surface-muted);
    stroke-width: 1;
  }

  .tt-chart__axis {
    stroke: var(--tt-border);
    stroke-width: 1;
  }

  .tt-chart__tick,
  .tt-chart__label {
    fill: var(--tt-muted);
    font-size: 12px;
  }

  .tt-chart__toggle {
    margin-top: var(--tt-space-2);
    padding: var(--tt-space-1) var(--tt-space-3);
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius-sm);
    background: var(--tt-surface);
    color: var(--tt-text);
    cursor: pointer;
  }

  .tt-chart__table-wrap {
    margin-top: var(--tt-space-3);
    overflow-x: auto;
  }

  .tt-chart__table {
    width: 100%;
    border-collapse: collapse;
  }

  .tt-chart__table caption {
    text-align: left;
    font-weight: var(--tt-font-weight-bold);
    margin-bottom: var(--tt-space-2);
  }

  .tt-chart__table th,
  .tt-chart__table td {
    padding: var(--tt-space-1) var(--tt-space-2);
    border-bottom: var(--tt-border-width) solid var(--tt-surface-muted);
    text-align: left;
  }

  .tt-chart__table .tt-chart__num {
    text-align: right;
    font-variant-numeric: tabular-nums;
  }
</style>
