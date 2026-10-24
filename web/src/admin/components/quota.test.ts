import { describe, expect, it } from 'vitest';
import en from '../../locales/en/adminComponents.json';
import fr from '../../locales/fr/adminComponents.json';
import {
  QUOTA_WARNING_RATIO,
  quotaBadgeVariant,
  quotaLevel,
  quotaMeterAttributes,
  quotaRatio,
  quotaTexts,
  type QuotaLevel,
  type Translate,
} from './quota';

const fakeT: Translate = (key, params) => (params === undefined ? key : `${key} ${JSON.stringify(params)}`);

describe('quotaRatio', () => {
  it('divides used by quota without capping', () => {
    expect(quotaRatio(25, 100)).toBe(0.25);
    expect(quotaRatio(150, 100)).toBe(1.5);
    expect(quotaRatio(-1, 100)).toBe(0);
    expect(quotaRatio(Number.NaN, 100)).toBe(0);
  });

  it('handles a zero or invalid quota', () => {
    expect(quotaRatio(0, 0)).toBe(0);
    expect(quotaRatio(5, 0)).toBe(1);
    expect(quotaRatio(5, Number.NaN)).toBe(1);
  });
});

describe('quotaLevel', () => {
  it('warns from 80 % and is full from 100 %', () => {
    expect(QUOTA_WARNING_RATIO).toBe(0.8);
    expect(quotaLevel(0)).toBe('ok');
    expect(quotaLevel(0.79)).toBe('ok');
    expect(quotaLevel(0.8)).toBe('warning');
    expect(quotaLevel(0.99)).toBe('warning');
    expect(quotaLevel(1)).toBe('full');
    expect(quotaLevel(1.2)).toBe('full');
  });

  it('maps each level to a badge variant', () => {
    expect((['ok', 'warning', 'full'] as QuotaLevel[]).map(quotaBadgeVariant)).toEqual([
      'ok',
      'warning',
      'error',
    ]);
  });
});

describe('quotaMeterAttributes', () => {
  it('sets low at 80 % and high at the quota, optimum 0', () => {
    expect(quotaMeterAttributes(30, 100)).toEqual({
      min: 0,
      max: 100,
      value: 30,
      low: 80,
      high: 100,
      optimum: 0,
    });
  });

  it('clamps the value', () => {
    expect(quotaMeterAttributes(130, 100).value).toBe(100);
    expect(quotaMeterAttributes(-3, 100).value).toBe(0);
  });

  it('keeps a valid meter with a zero quota', () => {
    expect(quotaMeterAttributes(0, 0)).toEqual({ min: 0, max: 1, value: 0, low: 0.8, high: 1, optimum: 0 });
    expect(quotaMeterAttributes(5, 0).value).toBe(1);
  });
});

describe('quotaTexts', () => {
  const fmt = (n: number): string => `${n}B`;
  const pct = (r: number): string => `${Math.round(r * 100)}%`;

  it('writes the usage and the level', () => {
    expect(quotaTexts(85, 100, fmt, pct, fakeT)).toEqual({
      usage: 'adminComponents.quota.usage {"used":"85B","quota":"100B","percent":"85%"}',
      level: 'adminComponents.quota.level.warning',
    });
  });

  it('states when no quota is set', () => {
    expect(quotaTexts(-1, 0, fmt, pct, fakeT)).toEqual({
      usage: 'adminComponents.quota.noQuota {"used":"0B"}',
      level: 'adminComponents.quota.level.ok',
    });
    expect(quotaTexts(5, 0, fmt, pct, fakeT).level).toBe('adminComponents.quota.level.full');
  });

  it('has every message in every language', () => {
    for (const bundle of [en, fr]) {
      expect(bundle.quota.usage).toContain('{percent}');
      expect(bundle.quota.noQuota).toContain('{used}');
      for (const level of ['ok', 'warning', 'full'] as const) {
        expect(bundle.quota.level[level]).toBeTruthy();
      }
    }
  });
});
