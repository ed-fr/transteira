import { describe, expect, it } from 'vitest';
import {
  defaultLevel,
  effectiveDeleteAfterFirst,
  effectiveExpiryDays,
  invalidFields,
  keepExpiry,
  keepMaxDownloads,
  levelByKey,
  mapRecipientDomainErrors,
  effectiveRecipientVerification,
  mapRuleErrors,
  selectableLevels,
  maxDownloadsCap,
  parseMaxDownloads,
  validatePolicy,
} from './form';

const rules = {
  requireRecipientVerification: false,
  requirePassword: true,
  allowedExpiryDays: [1, 7] as (1 | 7 | 30)[],
  internalRecipientsOnly: false,
  forceDeleteAfterFirstDownload: true,
  maxDownloads: 3,
};
const levels = [
  { key: 'a', label: 'A', isDefault: false, rules },
  { key: 'b', label: 'B', isDefault: true, rules },
];

describe('confidentiality helpers', () => {
  it('finds and defaults levels', () => {
    expect(defaultLevel(levels)?.key).toBe('b');
    expect(defaultLevel([{ key: 'a', label: 'A', isDefault: false, rules }])?.key).toBe('a');
    expect(defaultLevel([])).toBeUndefined();
    expect(levelByKey(levels, 'a')?.key).toBe('a');
    expect(levelByKey(levels, 'zz')).toBeUndefined();
    expect(levelByKey(levels, undefined)).toBeUndefined();
  });

  it('restricts durations and keeps a valid selection', () => {
    expect(effectiveExpiryDays([1, 7, 30], rules)).toEqual([1, 7]);
    expect(effectiveExpiryDays([1, 7, 30], undefined)).toEqual([1, 7, 30]);
    expect(keepExpiry(7, [1, 7])).toBe(7);
    expect(keepExpiry(30, [1, 7])).toBe(7);
    expect(keepExpiry(undefined, [1])).toBe(1);
  });

  it('reads and caps the download limit', () => {
    expect(maxDownloadsCap(undefined)).toBe(1000);
    expect(maxDownloadsCap(rules)).toBe(3);
    expect(parseMaxDownloads('')).toEqual({ ok: true, value: undefined });
    // bind:value on a number input yields a number, or null when empty.
    expect(parseMaxDownloads(3)).toEqual({ ok: true, value: 3 });
    expect(parseMaxDownloads(null)).toEqual({ ok: true, value: undefined });
    expect(keepMaxDownloads(5, rules)).toBe('3');
    expect(keepMaxDownloads(null, rules)).toBe('');
    expect(parseMaxDownloads(' 5 ')).toEqual({ ok: true, value: 5 });
    expect(parseMaxDownloads('0')).toEqual({ ok: false, code: 'too-small' });
    expect(parseMaxDownloads('1.5')).toEqual({ ok: false, code: 'invalid' });
    expect(parseMaxDownloads('1001')).toEqual({ ok: false, code: 'too-large' });
    expect(parseMaxDownloads('4', 3)).toEqual({ ok: false, code: 'max-exceeded' });
    expect(keepMaxDownloads('9', rules)).toBe('3');
    expect(keepMaxDownloads('2', rules)).toBe('2');
    expect(keepMaxDownloads('abc', rules)).toBe('abc');
    expect(keepMaxDownloads('9', undefined)).toBe('9');
  });

  it('forces the deletion option', () => {
    expect(effectiveDeleteAfterFirst(false, rules)).toBe(true);
    expect(effectiveDeleteAfterFirst(false, undefined)).toBe(false);
    expect(effectiveDeleteAfterFirst(true, undefined)).toBe(true);
  });

  it('validates the password and the download limit', () => {
    expect(validatePolicy('', '', rules, true)).toEqual({
      password: { key: 'deposit.form.password.requiredByLevel' },
    });
    expect(validatePolicy('x', '9', rules, true)['maxDownloads']).toEqual({
      key: 'deposit.form.maxDownloads.exceeded',
      params: { max: 3 },
    });
    expect(validatePolicy('x', 'abc', undefined, true)['maxDownloads']?.key).toBe(
      'deposit.form.maxDownloads.invalid',
    );
    expect(validatePolicy('x', 'abc', undefined, false)).toEqual({});
  });

  it('maps rule and recipient domain errors', () => {
    expect(
      mapRuleErrors([
        { field: '/expiryDays', code: 'not-allowed' },
        { field: '/expiryDays', code: 'required' },
        { field: '/recipients/1', code: 'internal-only' },
        { field: '/maxDownloads', code: 'max-exceeded' },
        { field: '/other', code: 'weird' },
      ]),
    ).toEqual({
      expiryDays: { key: 'deposit.form.rules.not-allowed' },
      'recipients.1': { key: 'deposit.form.rules.internal-only' },
      maxDownloads: { key: 'deposit.form.rules.max-exceeded' },
      other: { key: 'fieldErrors.invalid' },
    });
    expect(mapRuleErrors(undefined)).toEqual({});
    expect(mapRecipientDomainErrors([{ field: '/recipients/2', code: 'x' }])).toEqual({
      'recipients.2': { key: 'deposit.form.recipients.domainRefused' },
    });
    expect(invalidFields({ maxDownloads: { key: 'k' } })).toEqual(['maxDownloads']);
  });
});

describe('effectiveRecipientVerification', () => {
  it('needs the feature, then follows the choice or the level', () => {
    const required = { ...rules, requireRecipientVerification: true };
    expect(effectiveRecipientVerification(true, undefined, false)).toBe(false);
    expect(effectiveRecipientVerification(false, required, false)).toBe(false);
    expect(effectiveRecipientVerification(false, undefined, true)).toBe(false);
    expect(effectiveRecipientVerification(true, rules, true)).toBe(true);
    expect(effectiveRecipientVerification(false, required, true)).toBe(true);
  });

  it('maps the required rule error of the option to its own message', () => {
    expect(mapRuleErrors([{ field: '/recipientVerification', code: 'required' }])).toEqual({
      recipientVerification: { key: 'deposit.form.recipientVerification.requiredByLevel' },
    });
  });
});

describe('selectableLevels', () => {
  const mk = (key: string, isDefault: boolean, r: Partial<typeof rules>) => ({
    key,
    label: key,
    isDefault,
    rules: { ...rules, ...r },
  });
  const all = [
    mk('open', false, { allowedExpiryDays: [1, 7, 30] }),
    mk('verified', true, { requireRecipientVerification: true, allowedExpiryDays: [1, 7, 30] }),
    mk('long', false, { allowedExpiryDays: [30] }),
  ];

  it('hides levels requiring recipient verification while unavailable', () => {
    expect(selectableLevels(all, [1, 7, 30], false).map((l) => l.key)).toEqual(['open', 'long']);
    expect(selectableLevels(all, [1, 7, 30], true).map((l) => l.key)).toEqual(['open', 'verified', 'long']);
  });

  it('hides levels without any offered duration', () => {
    expect(selectableLevels(all, [1, 7], true).map((l) => l.key)).toEqual(['open', 'verified']);
  });

  it('falls back to the first visible level when the default is hidden', () => {
    expect(defaultLevel(selectableLevels(all, [1, 7, 30], false))?.key).toBe('open');
  });

  it('returns nothing when no level is usable', () => {
    expect(selectableLevels(all.slice(1, 2), [1, 7, 30], false)).toEqual([]);
    expect(selectableLevels(all.slice(2), [1], true)).toEqual([]);
  });
});
