import { describe, expect, it } from 'vitest';
import {
  addFiles,
  defaultExpiry,
  fieldOf,
  fileIssues,
  fileNameError,
  hasSecurityError,
  invalidFields,
  isEmail,
  isSecurityField,
  levelDownloadsCap,
  mapServerErrors,
  parseRecipients,
  recipientIssueMap,
  SECURITY_FIELDS,
  validateForm,
  validatePolicy,
  type FormValues,
  type LevelRules,
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

  it('maps recipient issues by index', () => {
    expect([...recipientIssueMap(errors, 2)]).toEqual([[1, { key: 'r1' }]]);
    expect(recipientIssueMap(errors, 1).size).toBe(0);
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

describe('security options', () => {
  const rules: LevelRules = {
    requireRecipientVerification: false,
    requirePassword: false,
    allowedExpiryDays: [1, 7, 30],
    internalRecipientsOnly: false,
    forceDeleteAfterFirstDownload: false,
    maxDownloads: null,
  };

  it('tells the fields of the block', () => {
    expect(SECURITY_FIELDS).toEqual(['password', 'maxDownloads', 'recipientVerification', 'endToEnd']);
    expect(isSecurityField('password')).toBe(true);
    expect(isSecurityField('endToEnd')).toBe(true);
    expect(isSecurityField('recipients')).toBe(false);
    expect(hasSecurityError({ 'files.0.name': { key: 'f' } })).toBe(false);
    expect(hasSecurityError({ maxDownloads: { key: 'm' }, message: { key: 'x' } })).toBe(true);
    expect(hasSecurityError({})).toBe(false);
  });

  it('gives the cap of the level only when it sets one', () => {
    expect(levelDownloadsCap(undefined)).toBeUndefined();
    expect(levelDownloadsCap(rules)).toBeUndefined();
    expect(levelDownloadsCap({ ...rules, maxDownloads: 3 })).toBe(3);
    expect(levelDownloadsCap({ ...rules, maxDownloads: 5000 })).toBe(1000);
  });

  it('refuses a switch turned on with its field left empty', () => {
    expect(validatePolicy('', '', rules, true, { passwordOn: true, maxDownloadsOn: true })).toEqual({
      password: { key: 'deposit.form.password.empty' },
      maxDownloads: { key: 'deposit.form.maxDownloads.empty' },
    });
    // Without the switches (or with values), nothing changes.
    expect(validatePolicy('', '', rules, true)).toEqual({});
    expect(validatePolicy('', '', rules, true, {})).toEqual({});
    expect(validatePolicy('pw', '2', rules, true, { passwordOn: true, maxDownloadsOn: true })).toEqual({});
    // The option is not offered: no download error.
    expect(validatePolicy('pw', '', rules, false, { maxDownloadsOn: true })).toEqual({});
  });

  it('keeps the level errors first and accepts an empty field under a cap', () => {
    const level = { ...rules, requirePassword: true, maxDownloads: 3 };
    expect(validatePolicy('', '', level, true, { passwordOn: true, maxDownloadsOn: true })).toEqual({
      password: { key: 'deposit.form.password.requiredByLevel' },
    });
    expect(validatePolicy('pw', 'x', rules, true, { maxDownloadsOn: true })['maxDownloads']?.key).toBe(
      'deposit.form.maxDownloads.invalid',
    );
  });
});
