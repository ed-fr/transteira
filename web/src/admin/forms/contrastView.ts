// Contrast badges of the branding form: computed live from the edited colours (contrast.ts),
// and replaced by the results of the server (Branding.contrast), which are authoritative, as long
// as the edited colours are the saved ones.

import {
  checkContrast,
  parseHexColor,
  type ContrastLevel,
  type ContrastResult,
} from '../../shared/theme/contrast';

/** A pair checked by the server; a later version may add pairs unknown to this client. */
export interface ServerContrastResult {
  pair: string;
  ratio: number;
  level: ContrastLevel;
}

/** One displayed contrast result. */
export interface ContrastRow {
  pair: string;
  ratio: number;
  level: ContrastLevel;
  /** Where the result comes from: the saved settings (server) or a live computation. */
  source: 'server' | 'live';
}

/** Edited colours of the form. */
export interface ColorPair {
  primaryColor: string;
  accentColor: string;
}

/** Saved branding, with the contrast results computed by the server. */
export interface SavedBranding extends ColorPair {
  contrast: readonly ServerContrastResult[];
}

function sameColor(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}

/**
 * Returns the contrast rows of the edited colours. When they are the saved ones, the server
 * results replace the live ones pair by pair, and server pairs unknown to the client are
 * appended. Invalid colours give no live rows.
 */
export function contrastView(edited: ColorPair, saved?: SavedBranding | null): ContrastRow[] {
  const primary = parseHexColor(edited.primaryColor);
  const accent = parseHexColor(edited.accentColor);
  const live: ContrastResult[] = primary && accent ? checkContrast(primary, accent) : [];
  const rows: ContrastRow[] = live.map((r) => ({ ...r, source: 'live' }));
  if (
    !saved ||
    !sameColor(saved.primaryColor, edited.primaryColor) ||
    !sameColor(saved.accentColor, edited.accentColor)
  ) {
    return rows;
  }
  for (const s of saved.contrast) {
    const row: ContrastRow = { pair: s.pair, ratio: s.ratio, level: s.level, source: 'server' };
    const i = rows.findIndex((r) => r.pair === s.pair);
    if (i >= 0) {
      rows[i] = row;
    } else {
      rows.push(row);
    }
  }
  return rows;
}

/**
 * Reports whether pair is checked against the dark background (*-on-dark). Below AA, such a pair
 * is not a readability problem: the dark theme then keeps its accessible link and focus colours
 * (theme.ts), so the form shows an informational note instead of the warning.
 */
export function isDarkPair(pair: string): boolean {
  return pair.endsWith('-on-dark');
}

/** Rows of the light theme that fail the AA level, shown as a non-blocking warning. */
export function contrastFailures(rows: readonly ContrastRow[]): ContrastRow[] {
  return rows.filter((r) => r.level === 'fail' && !isDarkPair(r.pair));
}

/** Reports whether a light-theme row fails the AA level (dark pairs never count). */
export function hasContrastFailure(rows: readonly ContrastRow[]): boolean {
  return contrastFailures(rows).length > 0;
}

/** Dark-theme rows below AA, for which the dark theme falls back to its default colours. */
export function darkFallbacks(rows: readonly ContrastRow[]): ContrastRow[] {
  return rows.filter((r) => r.level === 'fail' && isDarkPair(r.pair));
}
