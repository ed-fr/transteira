// Mapping of API errors to translated messages.
//
// - A Problem code maps to the key errors.<code> (src/locales/<lang>/errors.json); when the
//   bundle has no such key (a code added on the server later), the localised server detail is
//   shown, then errors.unknown.
// - validation-failed field errors map to a field → message record: the field (a JSON pointer
//   such as "/recipients/2", or "recipients[2]") is normalised to a dotted path
//   ("recipients.2"), and its code maps to fieldErrors.<code> (fallback fieldErrors.invalid).
// - A NetworkError maps to errors.network.
import { ApiProblem, NetworkError, type ProblemFieldError } from './client';

/** Translation function (t of the i18n module). */
export type Translate = (key: string, params?: Record<string, string | number>) => string;

/** Minimal translator view needed here: t() and a key existence check. */
export interface Translator {
  t: Translate;
  has(key: string): boolean;
}

/** One field error ready to display. */
export interface FieldMessage {
  /** Error code returned by the server (for example invalid-email). */
  code: string;
  /** Translated message. */
  message: string;
  /** Accepted values, when the server lists them. */
  allowed?: unknown[];
}

/**
 * Normalises a field reference to a dotted path: "/recipients/2" → "recipients.2",
 * "files[0].name" → "files.0.name", "/message/fr" → "message.fr". JSON pointer escapes
 * (~1, ~0) are decoded.
 */
export function normalizeField(field: string): string {
  const pointer = field.startsWith('/');
  const parts = pointer
    ? field
        .slice(1)
        .split('/')
        .map((p) => p.replace(/~1/g, '/').replace(/~0/g, '~'))
    : field.replace(/\[(\d+)\]/g, '.$1').split('.');
  return parts.filter((p) => p !== '').join('.');
}

/** Translated message of a field error code. */
export function fieldMessage(tr: Translator, code: string): string {
  const key = `fieldErrors.${code}`;
  return tr.t(tr.has(key) ? key : 'fieldErrors.invalid');
}

/**
 * Field errors of a validation-failed problem, keyed by normalised field path. When a field
 * has several errors, the first one is kept.
 */
export function fieldErrors(
  tr: Translator,
  errors: readonly ProblemFieldError[] | undefined,
): Record<string, FieldMessage> {
  const out: Record<string, FieldMessage> = {};
  for (const error of errors ?? []) {
    const field = normalizeField(error.field);
    if (Object.hasOwn(out, field)) {
      continue;
    }
    const entry: FieldMessage = { code: error.code, message: fieldMessage(tr, error.code) };
    if (error.allowed !== undefined) {
      entry.allowed = error.allowed;
    }
    out[field] = entry;
  }
  return out;
}

/** Translated message of any error thrown by the API client (or anything else). */
export function problemMessage(tr: Translator, err: unknown): string {
  if (err instanceof NetworkError) {
    return tr.t('errors.network');
  }
  if (err instanceof ApiProblem) {
    if (err.code !== undefined) {
      const key = `errors.${err.code}`;
      if (tr.has(key)) {
        return tr.t(key);
      }
    }
    const detail = err.problem?.detail ?? err.problem?.title;
    if (detail !== undefined && detail !== '') {
      return detail;
    }
  }
  return tr.t('errors.unknown');
}

/** Everything a form needs to display an API error. */
export interface ErrorView {
  /** Problem code, undefined for network or non-problem errors. */
  code: string | undefined;
  /** HTTP status, undefined for network errors. */
  status: number | undefined;
  /** General message. */
  message: string;
  /** Per-field messages (validation-failed). */
  fields: Record<string, FieldMessage>;
  /** Remaining attempts (wrong code or password). */
  attemptsRemaining: number | undefined;
  /** Seconds before a new attempt is possible. */
  retryAfterSeconds: number | undefined;
  /** Size limit of a transfer (transfer-too-large). */
  maxTransferBytes: number | undefined;
  /** Refused file names (blocked-file). */
  files: string[] | undefined;
}

/** Builds the display view of an error. */
export function describeError(tr: Translator, err: unknown): ErrorView {
  const problem = err instanceof ApiProblem ? err : undefined;
  return {
    code: problem?.code,
    status: problem?.status,
    message: problemMessage(tr, err),
    fields: fieldErrors(tr, problem?.errors),
    attemptsRemaining: problem?.attemptsRemaining,
    retryAfterSeconds: problem?.retryAfterSeconds,
    maxTransferBytes: problem?.maxTransferBytes,
    files: problem?.files,
  };
}
