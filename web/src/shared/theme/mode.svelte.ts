// Light / dark theme of the interface (CLAUDE.md section 13.1). The theme follows the system
// setting (prefers-color-scheme) unless the user picked one with the theme switch, stored in the
// technical cookie tt_theme (light or dark, one year, per host, never read by the server).
// web/static/theme-init.js applies the same rule before the first paint; this module then keeps
// data-theme on <html> up to date: it follows the system changes while nothing is stored, and
// toggleTheme() switches theme. A choice equal to the system setting deletes the cookie, so that
// the theme follows the system again. The cookie is a closed list (threat model T-231): any other
// value is ignored and never copied into the page.

/** A theme of the interface, as set in data-theme. */
export type ThemeName = 'light' | 'dark';

/** Name of the cookie holding the chosen theme. */
export const THEME_COOKIE = 'tt_theme';

/** Lifetime of the cookie, in seconds (one year). */
export const THEME_COOKIE_MAX_AGE = 31536000;

/** Media query of the system dark setting. */
export const DARK_QUERY = '(prefers-color-scheme: dark)';

/** The part of a MediaQueryList used by the theme (or a fake in tests). */
export interface ThemeMediaQuery {
  readonly matches: boolean;
  addEventListener(type: 'change', listener: () => void): void;
  removeEventListener(type: 'change', listener: () => void): void;
}

/** Browser dependencies of the theme mode, injected for tests. */
export interface ThemeEnv {
  /** document.cookie (read and written). */
  cookies: { cookie: string };
  /** Element receiving data-theme (document.documentElement). */
  root: { dataset: DOMStringMap };
  /** window.matchMedia(DARK_QUERY), or null when unavailable. */
  media: ThemeMediaQuery | null;
  /** location.protocol, to add Secure to the cookie over HTTPS. */
  protocol: string;
}

/** Theme mode: the resolved theme, the stored choice and the switch. */
export interface ThemeMode {
  /** Theme shown (reactive). */
  readonly current: ThemeName;
  /** Theme chosen by the user, or null when following the system (reactive). */
  readonly stored: ThemeName | null;
  /** Switches to the other theme and returns it. */
  toggle(): ThemeName;
  /** Stops following the system changes. */
  destroy(): void;
}

/** Returns the theme stored in a cookie header, or null when absent or not light / dark. */
export function parseStoredTheme(cookieHeader: string): ThemeName | null {
  for (const part of cookieHeader.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0 || part.slice(0, eq).trim() !== THEME_COOKIE) {
      continue;
    }
    const value = part.slice(eq + 1).trim();
    return value === 'light' || value === 'dark' ? value : null;
  }
  return null;
}

/** Returns the cookie string writing theme, or deleting the cookie when theme is null. */
export function themeCookie(theme: ThemeName | null, secure: boolean): string {
  const value = theme ?? '';
  const maxAge = theme === null ? 0 : THEME_COOKIE_MAX_AGE;
  return `${THEME_COOKIE}=${value}; Path=/; Max-Age=${maxAge}; SameSite=Lax${secure ? '; Secure' : ''}`;
}

/** Creates the theme mode on env and applies the resolved theme to the root. */
export function createThemeMode(env: ThemeEnv): ThemeMode {
  const system = (): ThemeName => (env.media?.matches ? 'dark' : 'light');
  const state = $state<{ current: ThemeName; stored: ThemeName | null }>({
    current: 'light',
    stored: parseStoredTheme(env.cookies.cookie),
  });
  const apply = (theme: ThemeName): void => {
    state.current = theme;
    env.root.dataset.theme = theme;
  };
  const onSystemChange = (): void => {
    if (state.stored === null) {
      apply(system());
    }
  };
  apply(state.stored ?? system());
  env.media?.addEventListener('change', onSystemChange);
  return {
    get current() {
      return state.current;
    },
    get stored() {
      return state.stored;
    },
    toggle() {
      const next: ThemeName = state.current === 'dark' ? 'light' : 'dark';
      state.stored = next === system() ? null : next;
      env.cookies.cookie = themeCookie(state.stored, env.protocol === 'https:');
      apply(next);
      return next;
    },
    destroy() {
      env.media?.removeEventListener('change', onSystemChange);
    },
  };
}

let shared: ThemeMode | undefined;

/** Returns the theme mode of the page, created on first use from the browser globals. */
export function themeMode(): ThemeMode {
  shared ??= createThemeMode({
    cookies: document,
    root: document.documentElement,
    media: typeof window.matchMedia === 'function' ? window.matchMedia(DARK_QUERY) : null,
    protocol: window.location.protocol,
  });
  return shared;
}

/** Switches the theme of the page and returns the new one. */
export function toggleTheme(): ThemeName {
  return themeMode().toggle();
}
