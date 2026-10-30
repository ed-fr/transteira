import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  DARK_QUERY,
  THEME_COOKIE,
  createThemeMode,
  parseStoredTheme,
  themeCookie,
  type ThemeEnv,
  type ThemeMediaQuery,
} from './mode.svelte';

/** A fake system setting, whose change listeners can be fired. */
function fakeMedia(
  dark: boolean,
): ThemeMediaQuery & { set(dark: boolean): void; listeners: Set<() => void> } {
  const listeners = new Set<() => void>();
  let matches = dark;
  return {
    get matches() {
      return matches;
    },
    listeners,
    addEventListener: (_type, listener) => listeners.add(listener),
    removeEventListener: (_type, listener) => listeners.delete(listener),
    set(next: boolean) {
      matches = next;
      for (const l of listeners) l();
    },
  };
}

/** A fake browser: the cookie keeps the last string written, as the tests check what is written. */
function fakeEnv(cookie: string, media: ThemeMediaQuery | null, protocol = 'https:'): ThemeEnv {
  return { cookies: { cookie }, root: { dataset: {} }, media, protocol };
}

// Cookie headers and the theme they store, shared by the module and theme-init.js.
const STORED: [string, 'light' | 'dark' | null][] = [
  ['', null],
  ['tt_theme=dark', 'dark'],
  ['a=1; tt_theme=light; b=2', 'light'],
  [' tt_theme = dark ', 'dark'],
  ['tt_theme=Dark', null],
  ['tt_theme=darkx', null],
  ['tt_theme=dark;tt_theme=light', 'dark'],
  ['tt_theme=<script>', null],
  ['tt_theme="dark"', null],
  ['xtt_theme=dark', null],
  ['tt_theme', null],
  ['tt_theme=', null],
];

afterEach(() => {
  vi.unstubAllGlobals();
  vi.resetModules();
});

describe('parseStoredTheme', () => {
  it.each(STORED)('reads %j as %j', (header, want) => {
    expect(parseStoredTheme(header)).toBe(want);
  });
});

describe('themeCookie', () => {
  it('writes a one-year technical cookie, Secure over HTTPS', () => {
    expect(themeCookie('dark', true)).toBe('tt_theme=dark; Path=/; Max-Age=31536000; SameSite=Lax; Secure');
    expect(themeCookie('light', false)).toBe('tt_theme=light; Path=/; Max-Age=31536000; SameSite=Lax');
  });

  it('deletes the cookie', () => {
    expect(themeCookie(null, true)).toBe('tt_theme=; Path=/; Max-Age=0; SameSite=Lax; Secure');
  });
});

describe('createThemeMode', () => {
  it('follows the system while nothing is stored', () => {
    const media = fakeMedia(true);
    const env = fakeEnv('', media);
    const mode = createThemeMode(env);
    expect(mode.current).toBe('dark');
    expect(mode.stored).toBeNull();
    expect(env.root.dataset.theme).toBe('dark');
    media.set(false);
    expect(mode.current).toBe('light');
    expect(env.root.dataset.theme).toBe('light');
    mode.destroy();
    expect(media.listeners.size).toBe(0);
  });

  it('keeps the stored theme when the system changes', () => {
    const media = fakeMedia(false);
    const env = fakeEnv('tt_theme=dark', media);
    const mode = createThemeMode(env);
    expect(mode.current).toBe('dark');
    expect(mode.stored).toBe('dark');
    media.set(true);
    media.set(false);
    expect(env.root.dataset.theme).toBe('dark');
  });

  it('ignores an unknown stored value', () => {
    const env = fakeEnv('tt_theme=purple', fakeMedia(false));
    const mode = createThemeMode(env);
    expect(mode.current).toBe('light');
    expect(mode.stored).toBeNull();
    expect(env.root.dataset.theme).toBe('light');
  });

  it('stores a choice that differs from the system, and deletes it when back to the system', () => {
    const env = fakeEnv('', fakeMedia(false));
    const mode = createThemeMode(env);
    expect(mode.toggle()).toBe('dark');
    expect(mode.stored).toBe('dark');
    expect(env.cookies.cookie).toBe('tt_theme=dark; Path=/; Max-Age=31536000; SameSite=Lax; Secure');
    expect(env.root.dataset.theme).toBe('dark');
    expect(mode.toggle()).toBe('light');
    expect(mode.stored).toBeNull();
    expect(env.cookies.cookie).toBe('tt_theme=; Path=/; Max-Age=0; SameSite=Lax; Secure');
    expect(env.root.dataset.theme).toBe('light');
  });

  it('stores light on a dark system, without Secure over HTTP', () => {
    const env = fakeEnv('', fakeMedia(true), 'http:');
    const mode = createThemeMode(env);
    expect(mode.toggle()).toBe('light');
    expect(env.cookies.cookie).toBe('tt_theme=light; Path=/; Max-Age=31536000; SameSite=Lax');
  });

  it('works without matchMedia (light system)', () => {
    const env = fakeEnv('', null);
    const mode = createThemeMode(env);
    expect(mode.current).toBe('light');
    expect(mode.toggle()).toBe('dark');
    mode.destroy();
  });
});

describe('themeMode (browser globals)', () => {
  it('is created once from document and window', async () => {
    const root = { dataset: {} as DOMStringMap };
    const doc = { cookie: `${THEME_COOKIE}=dark`, documentElement: root };
    const matchMedia = vi.fn(() => fakeMedia(false));
    vi.stubGlobal('document', doc);
    vi.stubGlobal('window', { matchMedia, location: { protocol: 'https:' } });
    const mod = await import('./mode.svelte');
    expect(mod.themeMode().current).toBe('dark');
    expect(mod.themeMode()).toBe(mod.themeMode());
    expect(matchMedia).toHaveBeenCalledExactlyOnceWith(DARK_QUERY);
    expect(mod.toggleTheme()).toBe('light');
    expect(doc.cookie).toBe('tt_theme=; Path=/; Max-Age=0; SameSite=Lax; Secure');
    expect(root.dataset.theme).toBe('light');
  });

  it('works without window.matchMedia', async () => {
    const root = { dataset: {} as DOMStringMap };
    vi.stubGlobal('document', { cookie: '', documentElement: root });
    vi.stubGlobal('window', { location: { protocol: 'http:' } });
    const mod = await import('./mode.svelte');
    expect(mod.themeMode().current).toBe('light');
  });
});

describe('web/static/theme-init.js', () => {
  const source = Object.values(
    import.meta.glob<string>('../../../static/theme-init.js', {
      query: '?raw',
      import: 'default',
      eager: true,
    }),
  )[0] as string;

  /** Runs the script in a fresh context and returns the data-theme it set (null if none). */
  function run(cookie: string | (() => string), dark: boolean | null): string | null {
    let theme: string | null = null;
    const document = {
      get cookie() {
        return typeof cookie === 'function' ? cookie() : cookie;
      },
      documentElement: {
        setAttribute: (name: string, value: string) => {
          expect(name).toBe('data-theme');
          theme = value;
        },
      },
    };
    const window =
      dark === null ? {} : { matchMedia: (q: string) => ({ matches: q === DARK_QUERY && dark }) };
    // The classic script runs against fakes in Node; the CSP that forbids new Function only
    // governs the browser.
    // eslint-disable-next-line no-restricted-syntax
    new Function('document', 'window', source)(document, window);
    return theme;
  }

  it.each(STORED)('applies the same rule as the module for %j', (header, stored) => {
    expect(run(header, false)).toBe(stored ?? 'light');
    expect(run(header, true)).toBe(stored ?? 'dark');
  });

  it('defaults to light without matchMedia', () => {
    expect(run('', null)).toBe('light');
  });

  it('never throws', () => {
    expect(
      run(() => {
        throw new Error('cookies blocked');
      }, true),
    ).toBeNull();
  });

  it('stays an ES2017 classic script', () => {
    expect(source).not.toMatch(/\b(import|export)\b|\?\?|\?\.|catch\s*\{/);
  });
});
