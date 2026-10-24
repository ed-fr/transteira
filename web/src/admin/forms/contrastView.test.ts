import { describe, expect, it } from 'vitest';
import { contrastView, hasContrastFailure } from './contrastView';

describe('contrastView', () => {
  it('computes the pairs live from the edited colours', () => {
    const rows = contrastView({ primaryColor: '#000000', accentColor: '#FFFFFF' });
    expect(rows).toEqual([
      { pair: 'primary-on-light', ratio: 21, level: 'AAA', source: 'live' },
      { pair: 'accent-on-light', ratio: 1, level: 'fail', source: 'live' },
      { pair: 'text-on-primary', ratio: 21, level: 'AAA', source: 'live' },
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
      ],
    };
    const rows = contrastView({ primaryColor: '#000000', accentColor: '#FFFFFF' }, saved);
    expect(rows).toEqual([
      { pair: 'primary-on-light', ratio: 21, level: 'AAA', source: 'live' },
      { pair: 'accent-on-light', ratio: 1.01, level: 'fail', source: 'server' },
      { pair: 'text-on-primary', ratio: 21, level: 'AAA', source: 'live' },
      { pair: 'primary-on-dark', ratio: 1.2, level: 'fail', source: 'server' },
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
    expect(hasContrastFailure(contrastView({ primaryColor: '#000000', accentColor: '#000000' }))).toBe(false);
  });
});
