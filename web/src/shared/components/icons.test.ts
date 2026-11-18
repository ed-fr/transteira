import { describe, expect, it } from 'vitest';
import { ICONS, ICON_NAMES } from './icons';

describe('icon set', () => {
  it('holds the icons the public pages use', () => {
    for (const name of [
      'upload',
      'check',
      'x',
      'lock',
      'shield',
      'clock',
      'download',
      'copy',
      'moon',
      'sun',
      'help',
      'list',
      'send',
      'alert',
      'chevron',
    ]) {
      expect(ICON_NAMES).toContain(name);
    }
  });

  it('lists the names in alphabetical order', () => {
    expect([...ICON_NAMES]).toEqual(Object.keys(ICONS).sort());
  });

  it('draws every icon with plain path data in the 24 × 24 box', () => {
    for (const name of ICON_NAMES) {
      const paths = ICONS[name];
      expect(paths.length, name).toBeGreaterThan(0);
      for (const d of paths) {
        expect(d, name).toMatch(/^M[0-9MmLlHhVvCcSsQqTtAaZz .,-]+$/);
        for (const n of d.match(/-?\d*\.?\d+/g) ?? []) {
          expect(Math.abs(Number(n)), `${name}: ${d}`).toBeLessThanOrEqual(24);
        }
      }
    }
  });
});
