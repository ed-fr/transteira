import { describe, expect, it } from 'vitest';
import { filterErrors, filterIssueMessage, formatWait } from './common';
import type { FilterIssue } from './filters';

const t = (key: string, params?: Record<string, string | number>): string =>
  params === undefined ? key : `${key} ${JSON.stringify(params)}`;

describe('formatWait', () => {
  it('formats waits in seconds then minutes, rounded up', () => {
    expect(formatWait(1, t)).toBe('opsTransfers.wait.seconds {"count":1}');
    expect(formatWait(0, t)).toBe('opsTransfers.wait.seconds {"count":1}');
    expect(formatWait(59, t)).toBe('opsTransfers.wait.seconds {"count":59}');
    expect(formatWait(59.2, t)).toBe('opsTransfers.wait.minutes {"count":1}');
    expect(formatWait(60, t)).toBe('opsTransfers.wait.minutes {"count":1}');
    expect(formatWait(3599, t)).toBe('opsTransfers.wait.minutes {"count":60}');
  });
});

describe('filterIssueMessage', () => {
  it('translates every issue code', () => {
    expect(filterIssueMessage('invalid-email', t)).toBe('fieldErrors.invalid-email');
    expect(filterIssueMessage('invalid-format', t)).toBe('fieldErrors.invalid-format');
    expect(filterIssueMessage('too-long', t)).toBe('fieldErrors.too-long');
    expect(filterIssueMessage('range', t)).toBe('fieldErrors.invalid');
    expect(filterIssueMessage('range', t, 'reversed')).toBe('reversed');
  });
});

describe('filterErrors', () => {
  const message = (issue: FilterIssue): string => `${issue.field}:${issue.code}`;
  const fieldOf = (issue: FilterIssue): string => (issue.field === 'a' ? 'aInput' : issue.field);

  it('is undefined without issues', () => {
    expect(filterErrors([], message, fieldOf)).toBeUndefined();
  });

  it('keeps the first message of each field and the first invalid field', () => {
    const issues: FilterIssue[] = [
      { field: 'a', code: 'too-long' },
      { field: 'b', code: 'invalid-format' },
      { field: 'a', code: 'range' },
    ];
    expect(filterErrors(issues, message, fieldOf)).toEqual({
      errors: { aInput: 'a:too-long', b: 'b:invalid-format' },
      first: 'aInput',
    });
  });
});
