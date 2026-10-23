// Tenant theme: applies the tenant colours to the design tokens of src/styles/tokens.css.
// Values are written through the CSSOM (style.setProperty), which the CSP style-src 'self' does
// not govern, and only after strict #RRGGBB validation: an invalid colour keeps the default.
import {
  LIGHT_BACKGROUND,
  MIN_RATIO_AA,
  MIN_RATIO_NON_TEXT,
  TEXT_ON_PRIMARY,
  contrastRatio,
  parseHexColor,
  toHex,
  type Rgb,
} from './contrast';

/** Tenant colours, as in PublicTenant.branding. */
export interface TenantColors {
  primaryColor: string;
  accentColor: string;
}

/** The part of an element used by the theme (document.documentElement, or a fake in tests). */
export interface ThemeTarget {
  style: Pick<CSSStyleDeclaration, 'setProperty' | 'removeProperty'>;
}

/** Dark text used on light primary colours when white text would not be readable (--tt-text). */
export const DARK_TEXT: Readonly<Rgb> = { r: 0x11, g: 0x18, b: 0x27 };

/** Custom properties written by applyTenantTheme and removed by resetTenantTheme. */
export const THEME_PROPERTIES = [
  '--tt-primary',
  '--tt-on-primary',
  '--tt-accent',
  '--tt-link',
  '--tt-focus',
] as const;

/** Name of a custom property managed by the tenant theme. */
export type ThemeProperty = (typeof THEME_PROPERTIES)[number];

/** Computed tenant theme: the value of each custom property, or null to keep the default. */
export type TenantTheme = Record<ThemeProperty, string | null>;

/**
 * Returns the text colour to write on a background: TEXT_ON_PRIMARY (white, the colour checked
 * by the administration) when it reaches AA, otherwise whichever of white and dark text
 * contrasts most.
 */
export function textColorOn(background: Readonly<Rgb>): Readonly<Rgb> {
  const light = contrastRatio(TEXT_ON_PRIMARY, background);
  if (light >= MIN_RATIO_AA) {
    return TEXT_ON_PRIMARY;
  }
  return contrastRatio(DARK_TEXT, background) > light ? DARK_TEXT : TEXT_ON_PRIMARY;
}

/**
 * Computes the theme of a tenant. Invalid colours yield null (default kept). The primary colour
 * is also used for links when it reaches AA on the light background, and for the focus
 * indicator when it reaches 3:1 (WCAG 1.4.11); otherwise the accessible defaults stay.
 */
export function computeTenantTheme(colors: TenantColors): TenantTheme {
  const primary = parseHexColor(colors.primaryColor);
  const accent = parseHexColor(colors.accentColor);
  const theme: TenantTheme = {
    '--tt-primary': null,
    '--tt-on-primary': null,
    '--tt-accent': null,
    '--tt-link': null,
    '--tt-focus': null,
  };
  if (primary !== null) {
    const ratio = contrastRatio(primary, LIGHT_BACKGROUND);
    theme['--tt-primary'] = toHex(primary);
    theme['--tt-on-primary'] = toHex(textColorOn(primary));
    theme['--tt-link'] = ratio >= MIN_RATIO_AA ? toHex(primary) : null;
    theme['--tt-focus'] = ratio >= MIN_RATIO_NON_TEXT ? toHex(primary) : null;
  }
  if (accent !== null) {
    theme['--tt-accent'] = toHex(accent);
  }
  return theme;
}

/**
 * Applies the tenant colours to root (document.documentElement by default) and returns the
 * computed theme. Properties left null are removed, so that the defaults of tokens.css apply.
 */
export function applyTenantTheme(colors: TenantColors, root?: ThemeTarget): TenantTheme {
  const target = root ?? document.documentElement;
  const theme = computeTenantTheme(colors);
  for (const name of THEME_PROPERTIES) {
    const value = theme[name];
    if (value === null) {
      target.style.removeProperty(name);
    } else {
      target.style.setProperty(name, value);
    }
  }
  return theme;
}

/** Removes every tenant colour from root, back to the defaults of tokens.css. */
export function resetTenantTheme(root?: ThemeTarget): void {
  const target = root ?? document.documentElement;
  for (const name of THEME_PROPERTIES) {
    target.style.removeProperty(name);
  }
}
