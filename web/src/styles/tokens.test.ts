// Contrast of the design tokens (CLAUDE.md sections 13 and 13.1, RGAA 3.2 and 3.3): reads
// tokens.css and checks, in the light and dark palettes, every text / background pair the
// components use (4.5:1) and the non-text colours (3:1), with the default tenant colours.
import { describe, expect, it } from 'vitest';
import {
  MIN_RATIO_AA,
  MIN_RATIO_NON_TEXT,
  contrastRatio,
  parseHexColor,
  type Rgb,
} from '../shared/theme/contrast';

const source = Object.values(
  import.meta.glob<string>('./tokens.css', { query: '?raw', import: 'default', eager: true }),
)[0] as string;
const css = source.replace(/\/\*[\s\S]*?\*\//g, '');

/** Declarations of the rule whose selector list is exactly selector. */
function block(selector: string): Map<string, string> {
  const rules = [...css.matchAll(/([^{}]+)\{([^{}]*)\}/g)];
  const rule = rules.find((m) => (m[1] ?? '').replace(/\s+/g, ' ').trim() === selector);
  if (rule === undefined) {
    throw new Error(`no rule ${selector} in tokens.css`);
  }
  const decls = new Map<string, string>();
  for (const d of (rule[2] ?? '').matchAll(/(--tt-[a-z0-9-]+)\s*:\s*([^;]+);/g)) {
    decls.set(d[1] ?? '', (d[2] ?? '').trim());
  }
  return decls;
}

/**
 * Resolves a token of a palette to a colour: var(--tt-brand-*, default) gives the default (no
 * tenant colour), var(--tt-x) the token x of the same palette.
 */
function resolve(palette: Map<string, string>, name: string): Rgb {
  const value = palette.get(name);
  if (value === undefined) {
    throw new Error(`${name} is not declared`);
  }
  const brand = /^var\(--tt-brand-[a-z-]+,\s*(#[0-9a-fA-F]{6})\)$/.exec(value);
  if (brand) {
    return parseHexColor(brand[1] ?? '') as Rgb;
  }
  const alias = /^var\((--tt-[a-z0-9-]+)\)$/.exec(value);
  if (alias) {
    return resolve(palette, alias[1] ?? '');
  }
  const color = parseHexColor(value);
  if (color === null) {
    throw new Error(`${name}: ${value} is not a #RRGGBB colour`);
  }
  return color;
}

const palettes = {
  light: block(":root, [data-theme='light']"),
  dark: block("[data-theme='dark']"),
};

// [foreground, background] pairs of text, at least 4.5:1.
const TEXT_PAIRS: [string, string][] = [
  ['--tt-text', '--tt-surface'],
  ['--tt-text', '--tt-surface-muted'],
  ['--tt-muted', '--tt-surface'],
  ['--tt-muted', '--tt-surface-muted'],
  ['--tt-text-muted', '--tt-surface'],
  ['--tt-link', '--tt-surface'],
  ['--tt-link', '--tt-surface-muted'],
  ['--tt-on-primary', '--tt-primary'],
  ['--tt-on-danger', '--tt-danger'],
  ['--tt-logo-text', '--tt-logo-surface'],
  ...(['success', 'warning', 'danger', 'info'] as const).flatMap((s): [string, string][] => [
    [`--tt-${s}`, '--tt-surface'],
    [`--tt-${s}`, `--tt-${s}-bg`],
  ]),
];

// Non-text colours, at least 3:1 on the surface (WCAG 1.4.11).
const NON_TEXT = ['--tt-border', '--tt-focus', '--tt-graphic'];

describe.each(Object.entries(palettes))('tokens.css, %s palette', (_name, palette) => {
  it.each(TEXT_PAIRS)('%s on %s reaches AA', (fg, bg) => {
    expect(contrastRatio(resolve(palette, fg), resolve(palette, bg))).toBeGreaterThanOrEqual(MIN_RATIO_AA);
  });

  it.each(NON_TEXT)('%s reaches 3:1 on the surface', (name) => {
    expect(contrastRatio(resolve(palette, name), resolve(palette, '--tt-surface'))).toBeGreaterThanOrEqual(
      MIN_RATIO_NON_TEXT,
    );
  });

  it('declares every colour token of the other palette', () => {
    const other = palette === palettes.light ? palettes.dark : palettes.light;
    expect([...palette.keys()].sort()).toEqual([...other.keys()].sort());
  });

  it('maps the tenant colours through --tt-brand-* only, never the status colours', () => {
    for (const [name, value] of palette) {
      const tenant = [
        '--tt-primary',
        '--tt-on-primary',
        '--tt-accent',
        '--tt-link',
        '--tt-focus',
        '--tt-graphic',
      ];
      expect(value.includes('--tt-brand-'), name).toBe(tenant.includes(name));
    }
  });
});

describe('tokens.css, dark palette', () => {
  it('uses the dark background of the contrast check as surface', () => {
    expect(palettes.dark.get('--tt-surface')).toBe('#111827');
  });
});
