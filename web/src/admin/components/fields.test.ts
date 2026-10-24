import { describe, expect, it } from 'vitest';
import en from '../../locales/en/adminComponents.json';
import fr from '../../locales/fr/adminComponents.json';
import { MAX_TRANSFER_BYTES } from '../forms/bytes';
import {
  byteErrorKey,
  byteFieldValue,
  confirmTextMatches,
  effectiveSecretMode,
  formatLineNumbers,
  passwordConfirmError,
  replaceLine,
  statusIcon,
  statusKey,
  validateByteField,
  type ByteFieldError,
  type StatusVariant,
} from './fields';

describe('confirmTextMatches', () => {
  it('accepts anything when no text is required', () => {
    expect(confirmTextMatches('', undefined)).toBe(true);
    expect(confirmTextMatches('x', '')).toBe(true);
  });

  it('requires the exact text, surrounding spaces aside', () => {
    expect(confirmTextMatches('Entity A', 'Entity A')).toBe(true);
    expect(confirmTextMatches('  Entity A ', 'Entity A')).toBe(true);
    expect(confirmTextMatches('entity a', 'Entity A')).toBe(false);
    expect(confirmTextMatches('Entity  A', 'Entity A')).toBe(false);
    expect(confirmTextMatches('', 'Entity A')).toBe(false);
  });
});

describe('passwordConfirmError', () => {
  it('reports a mismatch only once the confirmation is typed', () => {
    expect(passwordConfirmError('secret', '')).toBeUndefined();
    expect(passwordConfirmError('secret', 'secret')).toBeUndefined();
    expect(passwordConfirmError('secret', 'secre')).toBe('mismatch');
  });
});

describe('effectiveSecretMode', () => {
  it('keeps the chosen mode when a secret is stored', () => {
    expect(effectiveSecretMode(true, 'remove', 'x')).toBe('remove');
    expect(effectiveSecretMode(true, 'keep', '')).toBe('keep');
    expect(effectiveSecretMode(true, 'replace', '')).toBe('replace');
  });

  it('follows the value without a stored secret', () => {
    expect(effectiveSecretMode(false, 'remove', '')).toBe('keep');
    expect(effectiveSecretMode(false, 'keep', 'new')).toBe('replace');
  });
});

describe('validateByteField', () => {
  it('accepts an empty optional field and refuses an empty required one', () => {
    expect(validateByteField('  ', 'GiB', undefined, false)).toEqual({ bytes: null, error: undefined });
    expect(validateByteField('', 'GiB', undefined, true)).toEqual({ bytes: null, error: 'required' });
  });

  it('converts a valid amount', () => {
    expect(validateByteField('1,5', 'GiB', MAX_TRANSFER_BYTES, true)).toEqual({
      bytes: 1.5 * 2 ** 30,
      error: undefined,
    });
  });

  it('reports parse errors and the ceiling', () => {
    expect(validateByteField('abc', 'MiB', undefined, false).error).toBe('invalid');
    expect(validateByteField('0', 'MiB', undefined, false).error).toBe('not-positive');
    expect(validateByteField('21', 'GiB', MAX_TRANSFER_BYTES, false)).toEqual({
      bytes: null,
      error: 'too-large',
    });
  });
});

describe('byteFieldValue', () => {
  it('gives an empty amount for no size', () => {
    expect(byteFieldValue(null)).toEqual({ amount: '', unit: 'GiB' });
    expect(byteFieldValue(undefined, 'MiB')).toEqual({ amount: '', unit: 'MiB' });
    expect(byteFieldValue(0)).toEqual({ amount: '', unit: 'GiB' });
  });

  it('splits a stored size', () => {
    expect(byteFieldValue(20 * 2 ** 30)).toEqual({ amount: '20', unit: 'GiB' });
  });
});

describe('byteErrorKey', () => {
  it('maps every error to an existing message in every language', () => {
    const all: ByteFieldError[] = ['required', 'invalid', 'not-positive', 'too-large'];
    expect(all.map(byteErrorKey)).toEqual(['required', 'invalid', 'notPositive', 'tooLarge']);
    for (const bundle of [en, fr]) {
      for (const e of all) {
        expect(bundle.byteSize.errors[byteErrorKey(e)]).toBeTruthy();
      }
    }
  });
});

describe('status badge', () => {
  const variants: StatusVariant[] = ['ok', 'warning', 'missing', 'error', 'AA', 'AAA', 'fail', 'info'];

  it('gives each variant an icon', () => {
    expect(variants.map(statusIcon)).toEqual([
      'check',
      'alert',
      'cross',
      'cross',
      'check',
      'check',
      'cross',
      'info',
    ]);
  });

  it('has a default text for each variant in every language', () => {
    for (const bundle of [en, fr]) {
      for (const v of variants) {
        expect((bundle.status as Record<string, string>)[statusKey(v)]).toBeTruthy();
      }
    }
  });
});

describe('replaceLine', () => {
  it('replaces one line and normalises line breaks', () => {
    expect(replaceLine('a\r\nb\nc', 2, 'B')).toBe('a\nB\nc');
  });

  it('leaves the text unchanged for an out of range line', () => {
    expect(replaceLine('a\nb', 0, 'x')).toBe('a\nb');
    expect(replaceLine('a\nb', 3, 'x')).toBe('a\nb');
    expect(replaceLine('a\nb', 1.5, 'x')).toBe('a\nb');
  });
});

describe('formatLineNumbers', () => {
  it('joins line numbers', () => {
    expect(formatLineNumbers([3, 5, 8])).toBe('3, 5, 8');
  });
});
