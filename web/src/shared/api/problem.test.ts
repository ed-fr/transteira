import { describe, expect, it } from 'vitest';
import { ApiProblem, NetworkError, type Problem } from './client';
import {
  describeError,
  fieldErrors,
  fieldMessage,
  normalizeField,
  problemMessage,
  type Translator,
} from './problem';

const messages: Record<string, string> = {
  'errors.not-found': 'Not found',
  'errors.network': 'Offline',
  'errors.unknown': 'Unknown error',
  'errors.validation-failed': 'Invalid fields',
  'fieldErrors.invalid': 'Invalid value',
  'fieldErrors.invalid-email': 'Invalid email',
  'fieldErrors.required': 'Required',
};

const tr: Translator = {
  t: (key) => messages[key] ?? key,
  has: (key) => Object.hasOwn(messages, key),
};

function problem(status: number, body: Partial<Problem>): ApiProblem {
  return new ApiProblem(status, { type: 'about:blank', title: 'T', status, ...body } as Problem);
}

describe('normalizeField', () => {
  it.each([
    ['/email', 'email'],
    ['/recipients/2', 'recipients.2'],
    ['/message/fr', 'message.fr'],
    ['/files/0/name', 'files.0.name'],
    ['/a~1b/c~0d', 'a/b.c~d'],
    ['recipients[2]', 'recipients.2'],
    ['files[0].name', 'files.0.name'],
    ['limit', 'limit'],
    ['/', ''],
    ['', ''],
  ])('%s → %s', (input, expected) => {
    expect(normalizeField(input)).toBe(expected);
  });
});

describe('field messages', () => {
  it('translates known codes and falls back to fieldErrors.invalid', () => {
    expect(fieldMessage(tr, 'required')).toBe('Required');
    expect(fieldMessage(tr, 'brand-new-code')).toBe('Invalid value');
  });

  it('maps validation errors to normalised fields, first error wins, allowed kept', () => {
    const fields = fieldErrors(tr, [
      { field: '/recipients/1', code: 'invalid-email' },
      { field: '/recipients/1', code: 'duplicate' },
      { field: '/expiryDays', code: 'not-allowed', allowed: [1, 7, 30] },
      { field: 'email', code: 'required' },
    ]);
    expect(fields).toEqual({
      'recipients.1': { code: 'invalid-email', message: 'Invalid email' },
      expiryDays: { code: 'not-allowed', message: 'Invalid value', allowed: [1, 7, 30] },
      email: { code: 'required', message: 'Required' },
    });
    expect(fieldErrors(tr, undefined)).toEqual({});
  });
});

describe('problemMessage', () => {
  it('translates known codes', () => {
    expect(problemMessage(tr, problem(404, { code: 'not-found', detail: 'server text' }))).toBe('Not found');
  });

  it('falls back to the server detail, then the title, for codes without translation', () => {
    expect(problemMessage(tr, problem(409, { code: 'state-conflict', detail: 'Localised detail' }))).toBe(
      'Localised detail',
    );
    expect(problemMessage(tr, problem(409, { code: 'state-conflict', title: 'Conflict' }))).toBe('Conflict');
  });

  it('uses errors.unknown when nothing else is available', () => {
    expect(problemMessage(tr, new ApiProblem(502, undefined))).toBe('Unknown error');
    expect(problemMessage(tr, problem(500, { code: 'state-conflict', title: '' }))).toBe('Unknown error');
    expect(problemMessage(tr, new Error('boom'))).toBe('Unknown error');
    expect(problemMessage(tr, 'string')).toBe('Unknown error');
  });

  it('maps network errors', () => {
    expect(problemMessage(tr, new NetworkError(new TypeError('x')))).toBe('Offline');
  });
});

describe('describeError', () => {
  it('collects everything a form needs', () => {
    const view = describeError(
      tr,
      problem(400, {
        code: 'validation-failed',
        errors: [{ field: '/email', code: 'invalid-email' }],
        attemptsRemaining: 1,
        retryAfterSeconds: 30,
        maxTransferBytes: 100,
        files: ['a.exe'],
      }),
    );
    expect(view).toEqual({
      code: 'validation-failed',
      status: 400,
      message: 'Invalid fields',
      fields: { email: { code: 'invalid-email', message: 'Invalid email' } },
      attemptsRemaining: 1,
      retryAfterSeconds: 30,
      maxTransferBytes: 100,
      files: ['a.exe'],
    });
  });

  it('describes network errors', () => {
    const view = describeError(tr, new NetworkError(null));
    expect(view.code).toBeUndefined();
    expect(view.status).toBeUndefined();
    expect(view.message).toBe('Offline');
    expect(view.fields).toEqual({});
  });
});
