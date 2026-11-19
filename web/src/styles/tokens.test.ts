// Contrast of the design tokens (CLAUDE.md sections 13, 13.1 and 13.2, RGAA 3.2 and 3.3): reads
// tokens.css and checks, in the light and dark palettes, every text / background pair the
// components use (4.5:1) and the non-text colours (3:1), with the default tenant colours. The
// glass of the public header and footer is translucent: it is composited over a pure white and a
// pure black background image, under the veil, as browsers do (sRGB alpha blending), and its text
// and focus colours are checked on the result.
import { describe, expect, it } from 'vitest';
import {
  DARK_BACKGROUND,
  DARK_MUTED_BACKGROUND,
  LIGHT_BACKGROUND,
  LIGHT_MUTED_BACKGROUND,
  MIN_RATIO_AA,
  MIN_RATIO_NON_TEXT,
  contrastRatio,
  parseHexColor,
  toHex,
  type Rgb,
} from '../shared/theme/contrast';

const source = Object.values(
  import.meta.glob<string>('./tokens.css', { query: '?raw', import: 'default', eager: true }),
)[0] as string;
const css = source.replace(/\/\*[\s\S]*?\*\//g, '');

/** A colour with its opacity (alpha between 0 and 1). */
interface Rgba extends Rgb {
  a: number;
}

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

/** Parses one alpha value: a number between 0 and 1, or a percentage. */
function parseAlpha(value: string): number | null {
  const percent = /^(\d+(?:\.\d+)?)%$/.exec(value);
  const n = percent ? Number(percent[1]) / 100 : /^\d*\.?\d+$/.test(value) ? Number(value) : NaN;
  return Number.isFinite(n) && n >= 0 && n <= 1 ? n : null;
}

/**
 * Parses a CSS colour of the forms used in tokens.css: #RRGGBB, rgb(r g b), rgb(r g b / a),
 * rgb(r, g, b), rgba(r, g, b, a), alpha as a number or a percentage. Returns null otherwise.
 */
function parseCssColor(value: string): Rgba | null {
  const hex = parseHexColor(value);
  if (hex !== null) {
    return { ...hex, a: 1 };
  }
  const fn = /^rgba?\(\s*([^)]*)\)$/.exec(value.trim());
  if (fn === null) {
    return null;
  }
  const body = (fn[1] ?? '').trim();
  let channels: string[];
  let alpha = '1';
  if (body.includes(',')) {
    channels = body.split(',').map((p) => p.trim());
    if (channels.length === 4) {
      alpha = channels.pop() as string;
    }
  } else {
    const [color, slash, ...extra] = body.split('/').map((p) => p.trim());
    if (extra.length > 0) {
      return null;
    }
    channels = (color ?? '').split(/\s+/);
    alpha = slash ?? '1';
  }
  if (channels.length !== 3 || !channels.every((c) => /^\d{1,3}$/.test(c) && Number(c) <= 255)) {
    return null;
  }
  const a = parseAlpha(alpha);
  if (a === null) {
    return null;
  }
  const [r, g, b] = channels.map(Number) as [number, number, number];
  return { r, g, b, a };
}

/**
 * Composites a translucent colour over an opaque background, per sRGB channel, as browsers do
 * (source-over in the gamma-encoded space).
 */
function over(fg: Readonly<Rgba>, bg: Readonly<Rgb>): Rgb {
  const mix = (f: number, b: number): number => fg.a * f + (1 - fg.a) * b;
  return { r: mix(fg.r, bg.r), g: mix(fg.g, bg.g), b: mix(fg.b, bg.b) };
}

/**
 * Resolves a token of a palette to a colour with its alpha: var(--tt-brand-*, default) gives the
 * default (no tenant colour), var(--tt-x) the token x of the same palette.
 */
function resolveRgba(palette: Map<string, string>, name: string): Rgba {
  const value = palette.get(name);
  if (value === undefined) {
    throw new Error(`${name} is not declared`);
  }
  const brand = /^var\(--tt-brand-[a-z-]+,\s*(#[0-9a-fA-F]{6})\)$/.exec(value);
  if (brand) {
    return { ...(parseHexColor(brand[1] ?? '') as Rgb), a: 1 };
  }
  const alias = /^var\((--tt-[a-z0-9-]+)\)$/.exec(value);
  if (alias) {
    return resolveRgba(palette, alias[1] ?? '');
  }
  const color = parseCssColor(value);
  if (color === null) {
    throw new Error(`${name}: ${value} is not a colour`);
  }
  return color;
}

/** Resolves a token that must be opaque (text, surfaces, focus) to a colour. */
function resolve(palette: Map<string, string>, name: string): Rgb {
  const { a, ...rgb } = resolveRgba(palette, name);
  if (a !== 1) {
    throw new Error(`${name} is translucent`);
  }
  return rgb;
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
  // Neutral chips and badges (file type badge, neutral Badge, icon discs).
  ['--tt-chip-text', '--tt-chip-bg'],
  ...(['success', 'warning', 'danger', 'info'] as const).flatMap((s): [string, string][] => [
    [`--tt-${s}`, '--tt-surface'],
    [`--tt-${s}`, `--tt-${s}-bg`],
  ]),
];

// Non-text colours, at least 3:1 on the surface and on the muted surface (WCAG 1.4.11): fields,
// switches and focus rings also sit on the muted surface (deposit files column, plain page).
const NON_TEXT = ['--tt-border', '--tt-focus', '--tt-graphic'];
const SURFACES = ['--tt-surface', '--tt-surface-muted'];
const NON_TEXT_PAIRS: [string, string][] = NON_TEXT.flatMap((n) =>
  SURFACES.map((s): [string, string] => [n, s]),
);

// Tokens of the glass of the public header and footer, and their plain-page fallbacks.
const GLASS_FALLBACKS: Record<string, string> = {
  '--tt-glass-bg': 'var(--tt-surface)',
  '--tt-glass-text': 'var(--tt-text)',
  '--tt-glass-border': 'var(--tt-border)',
  '--tt-glass-focus': 'var(--tt-focus)',
  '--tt-glass-ring': 'var(--tt-focus-ring)',
};

const WHITE: Rgb = { r: 255, g: 255, b: 255 };
const BLACK: Rgb = { r: 0, g: 0, b: 0 };
const IMAGES: [string, Rgb][] = [
  ['a white image', WHITE],
  ['a black image', BLACK],
];

describe('parseCssColor', () => {
  it.each([
    ['#1D4ED8', { r: 29, g: 78, b: 216, a: 1 }],
    ['rgb(17 24 39 / 55%)', { r: 17, g: 24, b: 39, a: 0.55 }],
    ['rgb(0 0 0 / 0.7)', { r: 0, g: 0, b: 0, a: 0.7 }],
    ['rgb(255 255 255)', { r: 255, g: 255, b: 255, a: 1 }],
    ['rgba(1, 2, 3, 0.5)', { r: 1, g: 2, b: 3, a: 0.5 }],
    ['rgb(1, 2, 3)', { r: 1, g: 2, b: 3, a: 1 }],
  ])('parses %s', (value, expected) => {
    expect(parseCssColor(value)).toEqual(expected);
  });

  it.each([
    'red',
    'rgb(1 2)',
    'rgb(1 2 300)',
    'rgb(1 2 3 / 150%)',
    'rgb(1 2 3 / x)',
    'rgb(1 2 3 / 1 / 2)',
    'hsl(0 0% 0%)',
  ])('rejects %s', (value) => {
    expect(parseCssColor(value)).toBeNull();
  });

  it('composites like a browser', () => {
    const veil = over({ r: 17, g: 24, b: 39, a: 0.55 }, WHITE);
    expect(veil.r).toBeCloseTo(124.1, 9);
    expect(veil.g).toBeCloseTo(127.95, 9);
    expect(veil.b).toBeCloseTo(136.2, 9);
    expect(over({ r: 9, g: 9, b: 9, a: 1 }, WHITE)).toEqual({ r: 9, g: 9, b: 9 });
    expect(over({ r: 9, g: 9, b: 9, a: 0 }, BLACK)).toEqual(BLACK);
  });
});

describe.each(Object.entries(palettes))('tokens.css, %s palette', (_name, palette) => {
  it.each(TEXT_PAIRS)('%s on %s reaches AA', (fg, bg) => {
    expect(contrastRatio(resolve(palette, fg), resolve(palette, bg))).toBeGreaterThanOrEqual(MIN_RATIO_AA);
  });

  it.each(NON_TEXT_PAIRS)('%s reaches 3:1 on %s', (name, surface) => {
    expect(contrastRatio(resolve(palette, name), resolve(palette, surface))).toBeGreaterThanOrEqual(
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

  it('declares every glass token, with an opaque text, focus and ring', () => {
    for (const name of Object.keys(GLASS_FALLBACKS)) {
      expect(palette.has(name), name).toBe(true);
    }
    expect(resolveRgba(palette, '--tt-glass-bg').a).toBeLessThan(1);
    for (const name of ['--tt-glass-text', '--tt-glass-focus', '--tt-glass-ring']) {
      expect(resolveRgba(palette, name).a, name).toBe(1);
    }
  });

  describe.each(IMAGES)('glass over %s', (_image, image) => {
    // What is behind the header buttons and the footer: the image, the veil, then the glass.
    const veiled = over(resolveRgba(palette, '--tt-veil'), image);
    const glass = over(resolveRgba(palette, '--tt-glass-bg'), veiled);

    it('keeps the glass text at AA', () => {
      expect(contrastRatio(resolve(palette, '--tt-glass-text'), glass)).toBeGreaterThanOrEqual(MIN_RATIO_AA);
    });

    it('keeps the glass focus outline at 3:1 on the glass and on the veil around it', () => {
      const focus = resolve(palette, '--tt-glass-focus');
      expect(contrastRatio(focus, glass)).toBeGreaterThanOrEqual(MIN_RATIO_NON_TEXT);
      expect(contrastRatio(focus, veiled)).toBeGreaterThanOrEqual(MIN_RATIO_NON_TEXT);
    });
  });

  it('separates the glass focus outline from its ring', () => {
    expect(
      contrastRatio(resolve(palette, '--tt-glass-focus'), resolve(palette, '--tt-glass-ring')),
    ).toBeGreaterThanOrEqual(MIN_RATIO_NON_TEXT);
  });
});

describe('tokens.css, plain page (no background image)', () => {
  const plain = block('.tt-page--plain');

  it('maps every glass token to the plain surface colours', () => {
    expect(Object.fromEntries(plain)).toEqual(GLASS_FALLBACKS);
  });

  it.each(Object.entries(palettes))('keeps the plain glass readable in the %s palette', (_name, palette) => {
    const merged = new Map([...palette, ...plain]);
    expect(
      contrastRatio(resolve(merged, '--tt-glass-text'), resolve(merged, '--tt-glass-bg')),
    ).toBeGreaterThanOrEqual(MIN_RATIO_AA);
    // The plain page background is the muted surface: the focus outline sits on it.
    expect(
      contrastRatio(resolve(merged, '--tt-glass-focus'), resolve(merged, '--tt-surface-muted')),
    ).toBeGreaterThanOrEqual(MIN_RATIO_NON_TEXT);
  });
});

describe('tokens.css, reference colours of the contrast module', () => {
  it('uses the dark background of the contrast check as surface', () => {
    expect(palettes.dark.get('--tt-surface')).toBe('#111827');
    expect(toHex(DARK_BACKGROUND)).toBe(palettes.dark.get('--tt-surface')?.toUpperCase());
    expect(toHex(LIGHT_BACKGROUND)).toBe(palettes.light.get('--tt-surface')?.toUpperCase());
  });

  it('uses the muted surfaces checked by theme.ts', () => {
    expect(toHex(LIGHT_MUTED_BACKGROUND)).toBe(palettes.light.get('--tt-surface-muted')?.toUpperCase());
    expect(toHex(DARK_MUTED_BACKGROUND)).toBe(palettes.dark.get('--tt-surface-muted')?.toUpperCase());
  });
});

describe('tokens.css, layout tokens', () => {
  const root = block(':root');

  it('declares the public card radius and widths', () => {
    expect(root.get('--tt-radius-xl')).toBe('1.5rem');
    expect(root.get('--tt-card-narrow')).toBe('36rem');
    expect(root.get('--tt-card-medium')).toBe('52rem');
    expect(root.get('--tt-card-split')).toBe('70rem');
    expect(root.get('--tt-card-wide')).toBe('72rem');
  });
});

// Administration console palette: the default palette of the same theme with the TransTeira
// greens of html[data-app='admin'] (and its dark variant) in place of the tenant colours.
const ADMIN_TOKENS = ['--tt-primary', '--tt-link', '--tt-focus', '--tt-graphic'];
const adminOverrides = {
  light: block("html[data-app='admin']"),
  dark: block("html[data-app='admin'][data-theme='dark']"),
};

describe.each(Object.entries(adminOverrides))('tokens.css, administration %s palette', (name, overrides) => {
  const palette = new Map([...palettes[name as keyof typeof palettes], ...overrides]);

  it('replaces exactly the tenant colours the console uses', () => {
    expect([...overrides.keys()].sort()).toEqual([...ADMIN_TOKENS].sort());
  });

  it.each(TEXT_PAIRS)('%s on %s reaches AA', (fg, bg) => {
    expect(contrastRatio(resolve(palette, fg), resolve(palette, bg))).toBeGreaterThanOrEqual(MIN_RATIO_AA);
  });

  it.each(NON_TEXT_PAIRS)('%s reaches 3:1 on %s', (token, surface) => {
    expect(contrastRatio(resolve(palette, token), resolve(palette, surface))).toBeGreaterThanOrEqual(
      MIN_RATIO_NON_TEXT,
    );
  });
});

describe.each(Object.entries(adminOverrides))('tokens.css, administration %s gauges', (name, overrides) => {
  const palette = new Map([...palettes[name as keyof typeof palettes], ...overrides]);

  // Gauge (Gauge, QuotaMeter, plan of step 3c, deviation 5): the fill on its --tt-separator track,
  // the alert threshold marker in --tt-warning over the track and the muted surface around it.
  it.each([
    ['--tt-graphic', '--tt-separator'],
    ['--tt-warning', '--tt-separator'],
    ['--tt-danger', '--tt-separator'],
    ['--tt-warning', '--tt-surface-muted'],
    ['--tt-warning', '--tt-surface'],
  ])('%s reaches 3:1 on %s', (fg, bg) => {
    expect(contrastRatio(resolve(palette, fg), resolve(palette, bg))).toBeGreaterThanOrEqual(
      MIN_RATIO_NON_TEXT,
    );
  });
});

describe('tokens.css, administration sidebar', () => {
  const sidebar = block("html[data-app='admin'] .tt-admin-sidebar");
  const darkSidebar = block("html[data-app='admin'][data-theme='dark'] .tt-admin-sidebar");
  const background = resolve(sidebar, '--tt-sidebar-bg');
  // Translucent backgrounds of the sidebar, composited over its background as browsers do.
  const backgrounds: [string, Rgb][] = [
    ['the sidebar background', background],
    ['the current link background', over(resolveRgba(sidebar, '--tt-sidebar-active-bg'), background)],
    ['the user block and hover background', over(resolveRgba(sidebar, '--tt-sidebar-raised-bg'), background)],
  ];

  it('keeps the dark green of the mockup', () => {
    expect(sidebar.get('--tt-sidebar-bg')).toBe('#0b1f17');
    expect(sidebar.get('--tt-focus-ring')).toBe(sidebar.get('--tt-sidebar-bg'));
  });

  describe.each(backgrounds)('on %s', (_name, bg) => {
    it.each([
      '--tt-sidebar-text',
      '--tt-sidebar-strong',
      '--tt-sidebar-muted',
      '--tt-sidebar-link',
      '--tt-link',
    ])('%s reaches AA', (token) => {
      expect(contrastRatio(resolve(sidebar, token), bg)).toBeGreaterThanOrEqual(MIN_RATIO_AA);
    });

    it.each(['--tt-focus', '--tt-sidebar-active-icon'])('%s reaches 3:1', (token) => {
      expect(contrastRatio(resolve(sidebar, token), bg)).toBeGreaterThanOrEqual(MIN_RATIO_NON_TEXT);
    });
  });

  it('separates the focus outline from its ring', () => {
    expect(
      contrastRatio(resolve(sidebar, '--tt-focus'), resolve(sidebar, '--tt-focus-ring')),
    ).toBeGreaterThanOrEqual(MIN_RATIO_NON_TEXT);
  });

  it('keeps its palette in the dark theme, only adding a separating border', () => {
    expect([...darkSidebar.keys()]).toEqual(['--tt-sidebar-border']);
    expect(resolveRgba(darkSidebar, '--tt-sidebar-border').a).toBeGreaterThan(0);
  });
});
