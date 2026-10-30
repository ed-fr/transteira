import { describe, expect, it } from 'vitest';
import {
  contrastFailures,
  contrastView,
  darkFallbacks,
  hasContrastFailure,
  isDarkPair,
} from './contrastView';

describe('contrastView', () => {
  it('computes the pairs live from the edited colours', () => {
    const rows = contrastView({ primaryColor: '#000000', accentColor: '#FFFFFF' });
    expect(rows).toEqual([
      { pair: 'primary-on-light', ratio: 21, level: 'AAA', source: 'live' },
      { pair: 'accent-on-light', ratio: 1, level: 'fail', source: 'live' },
      { pair: 'text-on-primary', ratio: 21, level: 'AAA', source: 'live' },
      { pair: 'primary-on-dark', ratio: 1.18, level: 'fail', source: 'live' },
      { pair: 'accent-on-dark', ratio: 17.73, level: 'AAA', source: 'live' },
    ]);
    expect(hasContrastFailure(rows)).toBe(true);
  });

  it('gives no live rows for invalid colours', () => {
    expect(contrastView({ primaryColor: 'red', accentColor: '#FFFFFF' }, null)).toEqual([]);
  });

  it('prefers the server results for the saved colours', () => {
    const saved = {
      primaryColor: '#000000',
      accentColor: '#ffffff',
      contrast: [
        { pair: 'accent-on-light', ratio: 1.01, level: 'fail' as const },
        { pair: 'primary-on-dark', ratio: 1.2, level: 'fail' as const },
        { pair: 'future-pair', ratio: 9, level: 'AAA' as const },
      ],
    };
    const rows = contrastView({ primaryColor: '#000000', accentColor: '#FFFFFF' }, saved);
    expect(rows).toEqual([
      { pair: 'primary-on-light', ratio: 21, level: 'AAA', source: 'live' },
      { pair: 'accent-on-light', ratio: 1.01, level: 'fail', source: 'server' },
      { pair: 'text-on-primary', ratio: 21, level: 'AAA', source: 'live' },
      { pair: 'primary-on-dark', ratio: 1.2, level: 'fail', source: 'server' },
      { pair: 'accent-on-dark', ratio: 17.73, level: 'AAA', source: 'live' },
      { pair: 'future-pair', ratio: 9, level: 'AAA', source: 'server' },
    ]);
  });

  it('ignores the server results once a colour is edited', () => {
    const saved = {
      primaryColor: '#000000',
      accentColor: '#000000',
      contrast: [{ pair: 'accent-on-light', ratio: 21, level: 'AAA' as const }],
    };
    const accent = contrastView({ primaryColor: '#000000', accentColor: '#FFFFFF' }, saved);
    expect(accent.every((r) => r.source === 'live')).toBe(true);
    const primary = contrastView({ primaryColor: '#111111', accentColor: '#000000' }, saved);
    expect(primary.every((r) => r.source === 'live')).toBe(true);
    // Black fails on the dark background only: no warning, a dark fallback.
    const black = contrastView({ primaryColor: '#000000', accentColor: '#000000' });
    expect(hasContrastFailure(black)).toBe(false);
    expect(darkFallbacks(black).map((r) => r.pair)).toEqual(['primary-on-dark', 'accent-on-dark']);
    expect(hasContrastFailure(contrastView({ primaryColor: 'nope', accentColor: '#000000' }))).toBe(false);
  });

  it('never warns for the dark pairs, which fall back to the default colours', () => {
    // #1D4ED8: AA on white and under white text, 2.65:1 on the dark background.
    const rows = contrastView({ primaryColor: '#1D4ED8', accentColor: '#FFFFFF' });
    expect(contrastFailures(rows).map((r) => r.pair)).toEqual(['accent-on-light']);
    expect(darkFallbacks(rows).map((r) => r.pair)).toEqual(['primary-on-dark']);
    const ok = contrastView({ primaryColor: '#1D4ED8', accentColor: '#0F766E' });
    expect(hasContrastFailure(ok)).toBe(false);
    expect(darkFallbacks(ok).map((r) => r.pair)).toEqual(['primary-on-dark', 'accent-on-dark']);
    expect(isDarkPair('accent-on-dark')).toBe(true);
    expect(isDarkPair('text-on-primary')).toBe(false);
  });
});
