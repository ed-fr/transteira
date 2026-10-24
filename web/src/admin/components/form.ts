// Logic of FormSection, kept out of the component so that it is unit tested in Node: outcome of
// a submission, error summary built from the API field errors, unsaved-changes guards.
import type { FieldMessage } from '../../shared/api/problem';

/** One entry of the error summary of a form: a link to the field in error. */
export interface SummaryError {
  /** Id of the element to focus (the input, textarea, select or first radio of the field). */
  id: string;
  /** Visible label of the field, repeated in the summary link. */
  label: string;
  /** Error message shown next to the field. */
  message: string;
}

/**
 * Result returned by the onsubmit of a FormSection:
 * - ok: the inline result announces message (default: "Changes saved.");
 * - not ok: message is shown as a general error, errors fill the error summary and the focus
 *   moves to the first field in error (or to the summary when there are no field errors).
 * Returning nothing counts as a success with the default message.
 */
export type SubmitOutcome =
  { ok: true; message?: string } | { ok: false; message?: string; errors?: readonly SummaryError[] };

/** A field of the form, as needed to map API field errors to the summary. */
export interface FieldRef {
  /** Id of the element to focus. */
  id: string;
  /** Visible label of the field. */
  label: string;
}

/** Outcome of a submission once normalised. */
export interface NormalizedOutcome {
  ok: boolean;
  /** Message to show; undefined means the default message of the component. */
  message: string | undefined;
  errors: SummaryError[];
}

/** Normalises the value returned by onsubmit (void counts as a success). */
export function normalizeOutcome(outcome: SubmitOutcome | void | undefined): NormalizedOutcome {
  if (outcome === undefined) {
    return { ok: true, message: undefined, errors: [] };
  }
  if (outcome.ok) {
    return { ok: true, message: outcome.message, errors: [] };
  }
  return { ok: false, message: outcome.message, errors: [...(outcome.errors ?? [])] };
}

/**
 * Builds the error summary from the field errors of a validation-failed problem
 * (describeError(...).fields), in the order of fields (the order of the form). A field path
 * matches a field ref of the same name, or the closest parent path ("internalCidrs.2" matches
 * "internalCidrs"); a field present several times is listed once. Errors on unknown fields
 * are returned in unmatched, for a general message.
 */
export function summaryFromFields(
  apiFields: Readonly<Record<string, FieldMessage>>,
  fields: Readonly<Record<string, FieldRef>>,
): { errors: SummaryError[]; unmatched: string[] } {
  const byField = new Map<string, string>();
  const unmatched: string[] = [];
  for (const [path, error] of Object.entries(apiFields)) {
    const name = matchField(path, fields);
    if (name === undefined) {
      unmatched.push(path);
    } else if (!byField.has(name)) {
      byField.set(name, error.message);
    }
  }
  const errors: SummaryError[] = [];
  for (const [name, ref] of Object.entries(fields)) {
    const message = byField.get(name);
    if (message !== undefined) {
      errors.push({ id: ref.id, label: ref.label, message });
    }
  }
  return { errors, unmatched };
}

function matchField(path: string, fields: Readonly<Record<string, FieldRef>>): string | undefined {
  const parts = path.split('.');
  for (let n = parts.length; n > 0; n--) {
    const candidate = parts.slice(0, n).join('.');
    if (Object.hasOwn(fields, candidate)) {
      return candidate;
    }
  }
  return undefined;
}

/** Returns the message of the summary entry whose element id is id, if any. */
export function errorFor(errors: readonly SummaryError[], id: string): string | undefined {
  return errors.find((e) => e.id === id)?.message;
}

/**
 * Returns a navigation guard (router.addGuard) that lets the navigation through when the form
 * is clean, and otherwise asks confirm(message).
 */
export function unsavedChangesGuard(
  isDirty: () => boolean,
  confirm: (message: string) => boolean,
  message: string,
): (path: string) => boolean {
  return () => !isDirty() || confirm(message);
}

/** The part of a BeforeUnloadEvent used by the unsaved-changes warning. */
export interface BeforeUnloadLike {
  preventDefault(): void;
  returnValue?: unknown;
}

/** Returns a beforeunload listener that asks the browser to warn while the form is dirty. */
export function beforeUnloadWarning(isDirty: () => boolean): (event: BeforeUnloadLike) => void {
  return (event) => {
    if (isDirty()) {
      event.preventDefault();
      // Older browsers need returnValue set to show the dialog.
      event.returnValue = '';
    }
  };
}

/** The part of document used to focus an element by id. */
export interface FocusDocument {
  getElementById(id: string): { focus(): void } | null;
}

/** Focuses the element of id; reports whether it was found. */
export function focusById(doc: FocusDocument, id: string): boolean {
  const el = doc.getElementById(id);
  if (el === null) {
    return false;
  }
  el.focus();
  return true;
}
