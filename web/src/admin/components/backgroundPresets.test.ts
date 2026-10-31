import { describe, expect, it } from 'vitest';
import {
  DEFAULT_PRESET,
  choiceChanged,
  normalizeChoice,
  presetLabel,
  presetToSend,
  previewUrl,
} from './backgroundPresets';

const ocean = { id: 'ocean', labels: { en: 'Ocean', fr: 'Océan' } };

describe('presetLabel', () => {
  it('uses the interface language, including from a regional tag', () => {
    expect(presetLabel(ocean, 'fr')).toBe('Océan');
    expect(presetLabel(ocean, 'FR-fr')).toBe('Océan');
  });
  it('falls back to English, then to the identifier', () => {
    expect(presetLabel(ocean, 'de')).toBe('Ocean');
    expect(presetLabel({ id: 'x', labels: {} }, 'fr')).toBe('x');
    expect(presetLabel({ id: 'x', labels: { en: '', fr: '' } }, 'fr')).toBe('x');
  });
});

describe('normalizeChoice', () => {
  it('maps absent values to the default preset', () => {
    expect(normalizeChoice(undefined)).toBe(DEFAULT_PRESET);
    expect(normalizeChoice(null)).toBe(DEFAULT_PRESET);
    expect(normalizeChoice('')).toBe(DEFAULT_PRESET);
    expect(normalizeChoice('ocean')).toBe('ocean');
  });
});

describe('choiceChanged / presetToSend', () => {
  it('compares with the normalized saved value', () => {
    expect(choiceChanged('default', undefined)).toBe(false);
    expect(choiceChanged('ocean', undefined)).toBe(true);
    expect(choiceChanged('ocean', 'ocean')).toBe(false);
  });
  it('sends null for the default preset', () => {
    expect(presetToSend('default')).toBeNull();
    expect(presetToSend('ocean')).toBe('ocean');
  });
});

describe('previewUrl', () => {
  it('encodes the identifier', () => {
    expect(previewUrl('ocean')).toBe('/api/v1/admin/background-presets/ocean');
    expect(previewUrl('a/b c')).toBe('/api/v1/admin/background-presets/a%2Fb%20c');
  });
});
