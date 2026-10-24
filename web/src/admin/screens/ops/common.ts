// Helpers shared by the tenant operation screens: the wait before a new attempt (rate limits,
// conflicts with an upload in progress) and the messages of the filter form issues (transfers,
// audit log).
import type { FilterIssue, FilterIssueCode, FilterSpec } from './filters';
import type { Translate } from '../../../shared/i18n/messages';

/** Translation function (the t of the i18n module). */
export type { Translate };

/** "30 seconds" or "2 minutes" (at least 1 second, minutes rounded up from 60 seconds). */
export function formatWait(seconds: number, t: Translate): string {
  const s = Math.max(1, Math.ceil(seconds));
  return s < 60
    ? t('opsTransfers.wait.seconds', { count: s })
    : t('opsTransfers.wait.minutes', { count: Math.ceil(s / 60) });
}

/**
 * Message of a filter form issue: the generic field error of its code. A "range" issue (an end
 * day before a start day) has no generic message: rangeMessage, else the generic "invalid".
 */
export function filterIssueMessage(code: FilterIssueCode, t: Translate, rangeMessage?: string): string {
  switch (code) {
    case 'invalid-email':
      return t('fieldErrors.invalid-email');
    case 'invalid-format':
      return t('fieldErrors.invalid-format');
    case 'too-long':
      return t('fieldErrors.too-long');
    case 'range':
      return rangeMessage ?? t('fieldErrors.invalid');
  }
}

/** Errors of a filter form: one message per form field and the first invalid field (to focus). */
export interface FilterErrors<F extends string> {
  errors: Partial<Record<F, string>>;
  first: F;
}

/**
 * Errors of a filter form from the issues of validateFilters: the message of the first issue of
 * each form field (fieldOf maps a filter to the form field showing it) and the field of the
 * first issue. Undefined when there is no issue.
 */
export function filterErrors<S extends FilterSpec, F extends string>(
  issues: readonly FilterIssue<S>[],
  message: (issue: FilterIssue<S>) => string,
  fieldOf: (issue: FilterIssue<S>) => F,
): FilterErrors<F> | undefined {
  const first = issues[0];
  if (first === undefined) {
    return undefined;
  }
  const errors: Partial<Record<F, string>> = {};
  for (const issue of issues) {
    errors[fieldOf(issue)] ??= message(issue);
  }
  return { errors, first: fieldOf(first) };
}
