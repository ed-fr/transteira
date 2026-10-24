// Logic of the admin field components (ConfirmDialog, PasswordField, SecretModeField,
// ByteSizeField, StatusBadge, LineListEditor), kept out of the components so that it is unit
// tested in Node.
import { parseByteSize, toFieldValue, type ByteSizeError, type ByteUnit } from '../forms/bytes';
import { splitLines } from '../forms/lines';
import type { PasswordMode } from '../forms/smtp';

// ---- ConfirmDialog -------------------------------------------------------------------------

/**
 * Reports whether the confirmation can be given: always when no text is required, otherwise
 * only when typed equals expected exactly (case and inner spaces included; surrounding spaces
 * of a paste are ignored).
 */
export function confirmTextMatches(typed: string, expected: string | undefined): boolean {
  return expected === undefined || expected === '' || typed.trim() === expected;
}

// ---- PasswordField -------------------------------------------------------------------------

/** Autocomplete values accepted by PasswordField. */
export type PasswordAutocomplete = 'current-password' | 'new-password' | 'off';

/**
 * Error of the confirmation field of a new password: mismatch once the confirmation is typed
 * and differs from the password, undefined otherwise.
 */
export function passwordConfirmError(password: string, confirmation: string): 'mismatch' | undefined {
  return confirmation !== '' && confirmation !== password ? 'mismatch' : undefined;
}

// ---- SecretModeField -----------------------------------------------------------------------

/**
 * Mode to send for a secret field: with a stored secret, the chosen mode; without one, replace
 * when a value is typed and keep (send nothing) otherwise.
 */
export function effectiveSecretMode(secretSet: boolean, mode: PasswordMode, value: string): PasswordMode {
  if (secretSet) {
    return mode;
  }
  return value === '' ? 'keep' : 'replace';
}

// ---- ByteSizeField -------------------------------------------------------------------------

/** Error of a size field: the parse errors of forms/bytes.ts, plus an empty required field. */
export type ByteFieldError = ByteSizeError | 'required';

/** Result of the validation of a size field: bytes is null when the field is empty or invalid. */
export interface ByteFieldState {
  bytes: number | null;
  error: ByteFieldError | undefined;
}

/** Validates the amount and unit of a size field against max (inclusive). */
export function validateByteField(
  amount: string,
  unit: ByteUnit,
  max: number | undefined,
  required: boolean,
): ByteFieldState {
  if (amount.trim() === '') {
    return { bytes: null, error: required ? 'required' : undefined };
  }
  const r = parseByteSize(amount, unit, max);
  return r.ok ? { bytes: r.bytes, error: undefined } : { bytes: null, error: r.error };
}

/** Field value (amount and unit) of a stored size; an empty amount for null. */
export function byteFieldValue(
  bytes: number | null | undefined,
  fallbackUnit: ByteUnit = 'GiB',
): {
  amount: string;
  unit: ByteUnit;
} {
  return bytes === null || bytes === undefined || bytes < 1
    ? { amount: '', unit: fallbackUnit }
    : toFieldValue(bytes);
}

/** Translation key suffix of a size field error (adminComponents.byteSize.errors.<key>). */
export function byteErrorKey(error: ByteFieldError): 'required' | 'invalid' | 'notPositive' | 'tooLarge' {
  switch (error) {
    case 'not-positive':
      return 'notPositive';
    case 'too-large':
      return 'tooLarge';
    default:
      return error;
  }
}

// ---- StatusBadge ---------------------------------------------------------------------------

/** Variants of StatusBadge. */
export type StatusVariant = 'ok' | 'warning' | 'missing' | 'error' | 'AA' | 'AAA' | 'fail' | 'info';

/** Kind of icon of each variant (a CSS class draws it; the text always says the status). */
export function statusIcon(variant: StatusVariant): 'check' | 'alert' | 'cross' | 'info' {
  switch (variant) {
    case 'ok':
    case 'AA':
    case 'AAA':
      return 'check';
    case 'warning':
      return 'alert';
    case 'missing':
    case 'error':
    case 'fail':
      return 'cross';
    default:
      return 'info';
  }
}

/** Translation key suffix of the default text of a variant (adminComponents.status.<key>). */
export function statusKey(variant: StatusVariant): string {
  return variant.toLowerCase();
}

// ---- LineListEditor ------------------------------------------------------------------------

/**
 * Replaces line (from 1) of text with value, keeping the other lines and the line breaks
 * (normalised to LF). Out of range lines leave text unchanged.
 */
export function replaceLine(text: string, line: number, value: string): string {
  const lines = splitLines(text);
  if (!Number.isInteger(line) || line < 1 || line > lines.length) {
    return text;
  }
  lines[line - 1] = value;
  return lines.join('\n');
}

/** Joins line numbers for display ("3, 5, 8"). */
export function formatLineNumbers(lines: readonly number[]): string {
  return lines.join(', ');
}
