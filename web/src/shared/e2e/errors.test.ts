import { expect, it } from 'vitest';
import { E2EError, GO_ERROR_NAMES, isE2EError } from './errors';

it('carries a stable code and a detail', () => {
  const plain = new E2EError('auth');
  expect(plain.message).toBe('tte2: auth');
  expect(plain.name).toBe('E2EError');
  const detailed = new E2EError('truncated', 'chunk 2');
  expect(detailed.message).toBe('tte2: truncated: chunk 2');
  expect(detailed.code).toBe('truncated');
  expect(GO_ERROR_NAMES[detailed.code]).toBe('ErrTruncated');
});

it('recognises E2E errors', () => {
  const err = new E2EError('format');
  expect(isE2EError(err)).toBe(true);
  expect(isE2EError(err, 'format')).toBe(true);
  expect(isE2EError(err, 'auth')).toBe(false);
  expect(isE2EError(new Error('x'))).toBe(false);
});
