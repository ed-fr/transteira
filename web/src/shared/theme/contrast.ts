// WCAG 2.x contrast computations, mirroring internal/branding/contrast.go so that the interface
// and the administration API agree on the same ratios, levels and reference colours.

/** An sRGB colour with 8 bits per channel. */
export interface Rgb {
  r: number;
  g: number;
  b: number;
}

/** Pattern of a tenant colour, matching the HexColor schema of the API. */
export const HEX_COLOR = /^#[0-9a-fA-F]{6}$/;

/** Page background of the light theme (branding.LightBackground). V1.1 adds the dark one. */
export const LIGHT_BACKGROUND: Readonly<Rgb> = { r: 0xff, g: 0xff, b: 0xff };

/** Colour of text written on the primary colour (branding.TextOnPrimary). */
export const TEXT_ON_PRIMARY: Readonly<Rgb> = { r: 0xff, g: 0xff, b: 0xff };

/** Minimum contrast ratio of the AAA level for normal text (branding.MinRatioAAA). */
export const MIN_RATIO_AAA = 7.0;
/** Minimum contrast ratio of the AA level for normal text (branding.MinRatioAA). */
export const MIN_RATIO_AA = 4.5;
/** Minimum contrast ratio of non-text elements such as focus indicators (WCAG 1.4.11). */
export const MIN_RATIO_NON_TEXT = 3.0;

/** WCAG conformance level for normal text, matching the ContrastResult schema of the API. */
export type ContrastLevel = 'AAA' | 'AA' | 'fail';

/** Checked foreground / background pairs, matching the ContrastResult schema. */
export type ContrastPair = 'primary-on-light' | 'accent-on-light' | 'text-on-primary';

/** Contrast check of one pair. */
export interface ContrastResult {
  pair: ContrastPair;
  /** Ratio truncated (never rounded up) to two decimals. */
  ratio: number;
  level: ContrastLevel;
}

/** Parses a #RRGGBB colour (either case); returns null when the value is not one. */
export function parseHexColor(value: string): Rgb | null {
  if (!HEX_COLOR.test(value)) {
    return null;
  }
  return {
    r: parseInt(value.slice(1, 3), 16),
    g: parseInt(value.slice(3, 5), 16),
    b: parseInt(value.slice(5, 7), 16),
  };
}

/** Returns the colour in the #RRGGBB form, uppercase. */
export function toHex(c: Readonly<Rgb>): string {
  return (
    '#' +
    [c.r, c.g, c.b]
      .map((v) => v.toString(16).padStart(2, '0'))
      .join('')
      .toUpperCase()
  );
}

/** Converts an 8-bit sRGB channel to linear light. */
function linear(v: number): number {
  const s = v / 255;
  return s <= 0.04045 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
}

/** Returns the WCAG 2.x relative luminance, between 0 (black) and 1 (white). */
export function relativeLuminance(c: Readonly<Rgb>): number {
  return 0.2126 * linear(c.r) + 0.7152 * linear(c.g) + 0.0722 * linear(c.b);
}

/** Returns the WCAG 2.x contrast ratio of a and b, between 1 and 21, whatever their order. */
export function contrastRatio(a: Readonly<Rgb>, b: Readonly<Rgb>): number {
  const la = relativeLuminance(a);
  const lb = relativeLuminance(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

/** Returns the level reached by a contrast ratio. */
export function levelFor(ratio: number): ContrastLevel {
  if (ratio >= MIN_RATIO_AAA) {
    return 'AAA';
  }
  if (ratio >= MIN_RATIO_AA) {
    return 'AA';
  }
  return 'fail';
}

/** Truncates a ratio to two decimals, as the API does (the epsilon absorbs float noise). */
export function truncateRatio(ratio: number): number {
  return Math.floor(ratio * 100 + 1e-9) / 100;
}

function result(pair: ContrastPair, fg: Readonly<Rgb>, bg: Readonly<Rgb>): ContrastResult {
  const ratio = truncateRatio(contrastRatio(fg, bg));
  return { pair, ratio, level: levelFor(ratio) };
}

/**
 * Returns the contrast of the tenant colours for each pair checked by the API (branding.Check):
 * primary and accent on the light background, and text on the primary colour.
 */
export function checkContrast(primary: Readonly<Rgb>, accent: Readonly<Rgb>): ContrastResult[] {
  return [
    result('primary-on-light', primary, LIGHT_BACKGROUND),
    result('accent-on-light', accent, LIGHT_BACKGROUND),
    result('text-on-primary', TEXT_ON_PRIMARY, primary),
  ];
}
