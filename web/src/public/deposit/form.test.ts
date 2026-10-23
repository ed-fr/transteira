import { describe, expect, it } from 'vitest';
import {
  addFiles,
  defaultExpiry,
  fieldOf,
  fileIssues,
  fileNameError,
  invalidFields,
  isEmail,
  mapServerErrors,
  parseRecipients,
  recipientIssues,
  validateForm,
  type FormValues,
} from './form';

describe('parseRecipients', () => {
  it('splits on commas, semicolons and line breaks, trims and drops empty entries', () => {
    expect(parseRecipients(' a@example.com, b@example.com;\nc@example.com\r\n\n , ')).toEqual([
      'a@example.com',
      'b@example.com',
      'c@example.com',
    ]);
  });

  it('keeps the address of "Name <address>" entries', () => {
    expect(parseRecipients('Carol <carol@example.net>, <dave@example.net>')).toEqual([
      'carol@example.net',
      'dave@example.net',
    ]);
    expect(parseRecipients('Nobody <>')).toEqual([]);
  });

  it('removes duplicates case-insensitively, keeping the first spelling', () => {
    expect(parseRecipients('Alice@Example.com\nalice@example.com, bob@example.com')).toEqual([
      'Alice@Example.com',
      'bob@example.com',
    ]);
  });

  it('returns an empty list for an empty field', () => {
    expect(parseRecipients('')).toEqual([]);
  });
});

describe('isEmail', () => {
  it('accepts plain addresses and rejects obvious mistakes', () => {
    expect(isEmail('alice@entity-a.example.com')).toBe(true);
    expect(isEmail('alice')).toBe(false);
    expect(isEmail('alice@example')).toBe(false);
    expect(isEmail('a b@example.com')).toBe(false);
    expect(isEmail('a@b@example.com')).toBe(false);
    expect(isEmail(`${'a'.repeat(250)}@example.com`)).toBe(false);
  });
});

describe('fileNameError', () => {
  it('checks length, control and bidirectional characters', () => {
    expect(fileNameError('report.pdf')).toBeUndefined();
    expect(fileNameError('')).toBe('required');
    expect(fileNameError('a'.repeat(255))).toBeUndefined();
    expect(fileNameError('a'.repeat(256))).toBe('too-long');
    // 255 characters outside the BMP are 510 UTF-16 code units: still accepted.
    expect(fileNameError('\u{1F600}'.repeat(255))).toBeUndefined();
    expect(fileNameError('bad\nname')).toBe('invalid-file-name');
    expect(fileNameError('bad\u007fname')).toBe('invalid-file-name');
    expect(fileNameError('invoice\u202Efdp.exe')).toBe('invalid-file-name');
    expect(fileNameError('x\u2066y')).toBe('invalid-file-name');
  });
});

describe('addFiles', () => {
  it('skips files already selected', () => {
    const a = { name: 'a', size: 1, lastModified: 1 };
    const b = { name: 'b', size: 2, lastModified: 1 };
    const a2 = { name: 'a', size: 1, lastModified: 2 };
    expect(addFiles([a], [{ ...a }, b, a2])).toEqual([a, b, a2]);
  });
});

describe('validateForm', () => {
  const limits = { maxTransferBytes: 100, expiryDays: [1, 7, 30] };
  const base: FormValues<{ name: string; size: number }> = {
    recipientsText: 'carol@example.net',
    message: '',
    expiryDays: 7,
    password: '',
    deleteAfterFirstDownload: false,
    files: [{ name: 'a.txt', size: 10 }],
  };

  it('accepts a valid form', () => {
    expect(validateForm(base, limits, true)).toEqual({});
  });

  it('requires recipients for internal depositors only', () => {
    const values = { ...base, recipientsText: ' ' };
    expect(validateForm(values, limits, true)).toEqual({ recipients: { key: 'fieldErrors.required' } });
    expect(validateForm(values, limits, false)).toEqual({});
  });

  it('flags each invalid address by its index and too many recipients', () => {
    const errors = validateForm({ ...base, recipientsText: 'ok@example.net, nope, also@bad' }, limits, true);
    expect(errors).toEqual({
      'recipients.1': { key: 'fieldErrors.invalid-email' },
      'recipients.2': { key: 'fieldErrors.invalid-email' },
    });
    const many = Array.from({ length: 101 }, (_v, i) => `r${i}@example.net`).join(',');
    expect(validateForm({ ...base, recipientsText: many }, limits, true)['recipients']).toEqual({
      key: 'deposit.form.recipients.tooMany',
      params: { max: 100 },
    });
  });

  it('checks message, expiry and password lengths', () => {
    const errors = validateForm(
      { ...base, message: 'x'.repeat(5001), expiryDays: 3, password: 'p'.repeat(1025) },
      limits,
      true,
    );
    expect(errors).toEqual({
      message: { key: 'fieldErrors.too-long' },
      expiryDays: { key: 'fieldErrors.required' },
      password: { key: 'fieldErrors.too-long' },
    });
    expect(validateForm({ ...base, expiryDays: undefined }, limits, true)['expiryDays']).toBeDefined();
  });

  it('checks the files: none, too many, too large, names', () => {
    expect(validateForm({ ...base, files: [] }, limits, true)['files']).toEqual({
      key: 'deposit.form.files.none',
    });
    const many = Array.from({ length: 1001 }, () => ({ name: 'f', size: 0 }));
    expect(validateForm({ ...base, files: many }, limits, true)['files']).toEqual({
      key: 'deposit.form.files.tooMany',
      params: { max: 1000 },
    });
    const big = [
      { name: 'a', size: 60 },
      { name: 'b', size: 41 },
    ];
    expect(validateForm({ ...base, files: big }, limits, true)['files']).toEqual({
      key: 'deposit.form.files.tooLarge',
    });
    const named = [
      { name: 'ok', size: 1 },
      { name: 'bad\u0001', size: 1 },
    ];
    expect(validateForm({ ...base, files: named }, limits, true)).toEqual({
      'files.1.name': { key: 'fieldErrors.invalid-file-name' },
    });
  });
});

describe('mapServerErrors', () => {
  it('normalises JSON pointers, keeps the first error and falls back to invalid', () => {
    const has = (key: string) => key !== 'fieldErrors.strange';
    expect(
      mapServerErrors(
        [
          { field: '/recipients/1', code: 'invalid-email' },
          { field: '/recipients/1', code: 'duplicate' },
          { field: '/files/0/name', code: 'invalid-file-name' },
          { field: '/message', code: 'strange' },
        ],
        has,
      ),
    ).toEqual({
      'recipients.1': { key: 'fieldErrors.invalid-email' },
      'files.0.name': { key: 'fieldErrors.invalid-file-name' },
      message: { key: 'fieldErrors.invalid' },
    });
    expect(mapServerErrors(undefined, has)).toEqual({});
  });
});

describe('error helpers', () => {
  const errors = {
    recipients: { key: 'r' },
    'recipients.1': { key: 'r1' },
    'files.0.name': { key: 'f0' },
    'files.2': { key: 'f2' },
    other: { key: 'o' },
  };

  it('lists recipient issues with their address', () => {
    expect(recipientIssues(errors, ['a@x.example', 'b@x.example'])).toEqual([
      { address: 'b@x.example', message: { key: 'r1' } },
    ]);
  });

  it('lists file issues by index', () => {
    expect([...fileIssues(errors, 3)]).toEqual([
      [0, { key: 'f0' }],
      [2, { key: 'f2' }],
    ]);
  });

  it('gives the invalid fields in form order', () => {
    expect(fieldOf('files.0.name')).toBe('files');
    expect(fieldOf('other')).toBeUndefined();
    expect(invalidFields({ ...errors, password: { key: 'p' } })).toEqual(['recipients', 'password', 'files']);
  });

  it('picks the default expiry', () => {
    expect(defaultExpiry([1, 7, 30])).toBe(7);
    expect(defaultExpiry([1, 30])).toBe(1);
    expect(defaultExpiry([])).toBeUndefined();
  });
});
