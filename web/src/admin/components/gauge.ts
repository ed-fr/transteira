// Logic of Gauge.svelte (CLAUDE.md section 13.2: storage gauges of the entities, disk tile with
// its alert threshold; plan of step 3c, deviation 5): position of the threshold marker drawn over
// the native <meter>, as a percentage of the track.

/**
 * Position of a threshold on a gauge from min to max, as a percentage of the track (0 to 100,
 * clamped), or undefined when there is no threshold or the range is empty or not finite.
 */
export function markerPercent(threshold: number | undefined, min: number, max: number): number | undefined {
  if (
    threshold === undefined ||
    !Number.isFinite(threshold) ||
    !Number.isFinite(min) ||
    !Number.isFinite(max) ||
    max <= min
  ) {
    return undefined;
  }
  const percent = ((threshold - min) / (max - min)) * 100;
  return Math.min(100, Math.max(0, Math.round(percent * 100) / 100));
}

/** Colour level of a gauge fill (the text next to the gauge always says it too). */
export type GaugeLevel = 'default' | 'warning' | 'danger';

/**
 * Level of a value against an optional threshold: danger from max, warning from the threshold,
 * default otherwise (or when the range is empty).
 */
export function gaugeLevel(value: number, max: number, threshold?: number): GaugeLevel {
  if (!Number.isFinite(value) || !Number.isFinite(max) || max <= 0) {
    return 'default';
  }
  if (value >= max) {
    return 'danger';
  }
  return threshold !== undefined && Number.isFinite(threshold) && value >= threshold ? 'warning' : 'default';
}
