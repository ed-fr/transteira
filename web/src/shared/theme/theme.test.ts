import { afterEach, describe, expect, it, vi } from 'vitest';
import { parseHexColor, type Rgb } from './contrast';
import {
  DARK_TEXT,
  THEME_PROPERTIES,
  applyTenantTheme,
  computeTenantTheme,
  resetTenantTheme,
  textColorOn,
  type ThemeTarget,
} from './theme';

function color(hex: string): Rgb {
  const c = parseHexColor(hex);
  if (c === null) {
    throw new Error(`invalid test colour ${hex}`);
  }
  return c;
}

/** A fake element style recording the custom properties. */
function fakeRoot(): ThemeTarget & { props: Map<string, string> } {
  const props = new Map<string, string>();
  return {
    props,
    style: {
      setProperty: (name: string, value: string | null) => {
        props.set(name, value ?? '');
      },
      removeProperty: (name: string) => {
        const old = props.get(name) ?? '';
        props.delete(name);
        return old;
      },
    },
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('textColorOn', () => {
  it('keeps white text when it reaches AA', () => {
    expect(textColorOn(color('#1D4ED8'))).toEqual({ r: 255, g: 255, b: 255 });
    expect(textColorOn(color('#767676'))).toEqual({ r: 255, g: 255, b: 255 });
  });

  it('switches to dark text on light colours', () => {
    expect(textColorOn(color('#FFD700'))).toBe(DARK_TEXT);
    expect(textColorOn(color('#FFFFFF'))).toBe(DARK_TEXT);
  });

  it('keeps white when dark text is no better', () => {
    // #777777: white 4.48:1, dark text 3.9:1.
    expect(textColorOn(color('#777777'))).toEqual({ r: 255, g: 255, b: 255 });
  });
});

describe('computeTenantTheme', () => {
  it('derives every property from a dark primary', () => {
    expect(computeTenantTheme({ primaryColor: '#1d4ed8', accentColor: '#0f766e' })).toEqual({
      '--tt-primary': '#1D4ED8',
      '--tt-on-primary': '#FFFFFF',
      '--tt-accent': '#0F766E',
      '--tt-link': '#1D4ED8',
      '--tt-focus': '#1D4ED8',
    });
  });

  it('keeps the default link and focus colours for a pale primary', () => {
    const theme = computeTenantTheme({ primaryColor: '#FFD700', accentColor: '#000000' });
    expect(theme['--tt-primary']).toBe('#FFD700');
    expect(theme['--tt-on-primary']).toBe('#111827');
    expect(theme['--tt-link']).toBeNull();
    expect(theme['--tt-focus']).toBeNull();
  });

  it('uses the primary for focus but not for links between 3:1 and 4.5:1', () => {
    // #888888 on white: about 3.54:1.
    const theme = computeTenantTheme({ primaryColor: '#888888', accentColor: '#000000' });
    expect(theme['--tt-link']).toBeNull();
    expect(theme['--tt-focus']).toBe('#888888');
  });

  it.each(['red', '#FFF', 'url(x)', '#123456;color:red', ''])('ignores the invalid colour %j', (bad) => {
    const theme = computeTenantTheme({ primaryColor: bad, accentColor: bad });
    for (const name of THEME_PROPERTIES) {
      expect(theme[name]).toBeNull();
    }
  });
});

describe('applyTenantTheme', () => {
  it('writes the theme through the CSSOM of the given root', () => {
    const root = fakeRoot();
    applyTenantTheme({ primaryColor: '#1d4ed8', accentColor: '#0f766e' }, root);
    expect(Object.fromEntries(root.props)).toEqual({
      '--tt-primary': '#1D4ED8',
      '--tt-on-primary': '#FFFFFF',
      '--tt-accent': '#0F766E',
      '--tt-link': '#1D4ED8',
      '--tt-focus': '#1D4ED8',
    });
  });

  it('removes properties that fall back to defaults', () => {
    const root = fakeRoot();
    applyTenantTheme({ primaryColor: '#1d4ed8', accentColor: '#0f766e' }, root);
    applyTenantTheme({ primaryColor: '#FFD700', accentColor: 'nope' }, root);
    expect(root.props.has('--tt-link')).toBe(false);
    expect(root.props.has('--tt-focus')).toBe(false);
    expect(root.props.has('--tt-accent')).toBe(false);
    expect(root.props.get('--tt-primary')).toBe('#FFD700');
  });

  it('defaults to document.documentElement', () => {
    const root = fakeRoot();
    vi.stubGlobal('document', { documentElement: root });
    applyTenantTheme({ primaryColor: '#000000', accentColor: '#000000' });
    expect(root.props.get('--tt-primary')).toBe('#000000');
    resetTenantTheme();
    expect(root.props.size).toBe(0);
  });

  it('resets an explicit root', () => {
    const root = fakeRoot();
    applyTenantTheme({ primaryColor: '#000000', accentColor: '#000000' }, root);
    resetTenantTheme(root);
    expect(root.props.size).toBe(0);
  });
});
