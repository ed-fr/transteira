// Logic of the blocklist of a tenant (CLAUDE.md section 15.2), kept out of the component so that
// it is unit tested in Node: labels of the entry kinds, client-side check of a value according to
// its kind (an email address, a domain, a SHA-256 digest), body of the creation, mapping of the
// API errors to the form fields (409 already-exists on the value) and list updates. The server
// trims, lowercases and validates the value again and remains authoritative.
import type { ErrorView } from '../../../shared/api/problem';
import type { components } from '../../../shared/api/schema';
import { isEmail } from '../../../shared/validation/email';
import {
  summaryFromFields,
  type FieldRef,
  type SubmitOutcome,
  type SummaryError,
} from '../../components/form';
import type { SelectOption } from '../../components/select';
import { parseDomain } from '../../forms/domain';
import { domainLineMessage } from '../tenants/network';
import { BLOCKLIST_KINDS, codePointLength, type BlocklistFilters, type BlocklistKind } from './filters';
import { removeItem, type PagedList } from './paging';
import type { Translate } from '../../../shared/i18n/messages';

/** Translation function (the t of the i18n module). */
export type { Translate };

export type { BlocklistKind };

/** A blocklist entry. */
export type BlocklistEntry = components['schemas']['BlocklistEntry'];
/** Body of createBlocklistEntry. */
export type BlocklistEntryCreate = components['schemas']['BlocklistEntryCreate'];

/** Maximum length of a value (BlocklistEntryCreate.value). */
export const VALUE_MAX_LENGTH = 320;
/** Maximum length of a comment (BlocklistEntryCreate.comment). */
export const COMMENT_MAX_LENGTH = 500;

const SHA256 = /^[0-9a-f]{64}$/i;

/** Message key of the label of each kind. */
const KIND_KEYS: Record<BlocklistKind, string> = {
  email: 'opsBlocklist.kind.email',
  domain: 'opsBlocklist.kind.domain',
  sha256: 'opsBlocklist.kind.sha256',
};

/** Message key of the hint of the value field for each kind. */
const HINT_KEYS: Record<BlocklistKind, string> = {
  email: 'opsBlocklist.form.valueHint.email',
  domain: 'opsBlocklist.form.valueHint.domain',
  sha256: 'opsBlocklist.form.valueHint.sha256',
};

function isKind(kind: string): kind is BlocklistKind {
  return (BLOCKLIST_KINDS as readonly string[]).includes(kind);
}

/** Label of a kind; a kind unknown to this version of the interface is shown as is. */
export function kindLabel(kind: string, t: Translate): string {
  return isKind(kind) ? t(KIND_KEYS[kind]) : kind;
}

/** Hint of the value field for a kind. */
export function valueHint(kind: BlocklistKind, t: Translate): string {
  return t(HINT_KEYS[kind]);
}

/** Options of the kind field of the form (each kind). */
export function kindOptions(t: Translate): SelectOption[] {
  return BLOCKLIST_KINDS.map((k) => ({ value: k, label: t(KIND_KEYS[k]) }));
}

/** Options of the kind filter: "All kinds" then each kind. */
export function kindFilterOptions(t: Translate): SelectOption[] {
  return [{ value: '', label: t('opsBlocklist.filters.allKinds') }, ...kindOptions(t)];
}

/** Result of the check of a value: the value to send, or the message of the error. */
export type ValueCheck =
  { ok: true; value: string } | { ok: false; key: string; params?: Record<string, string> };

/**
 * Checks a value according to its kind and returns the value to send:
 * - email: a bare address (isEmail), lowercased;
 * - domain: a domain name (parseDomain: lowercase, punycode; a trailing dot is refused with the
 *   name without it as suggestion);
 * - sha256: 64 hexadecimal characters, upper case accepted and lowercased.
 * An empty value is "required", a value over 320 characters "too long".
 */
export function checkValue(kind: BlocklistKind, raw: string): ValueCheck {
  const value = raw.trim();
  if (value === '') {
    return { ok: false, key: 'fieldErrors.required' };
  }
  if (codePointLength(value) > VALUE_MAX_LENGTH) {
    return { ok: false, key: 'fieldErrors.too-long' };
  }
  switch (kind) {
    case 'email':
      return isEmail(value)
        ? { ok: true, value: value.toLowerCase() }
        : { ok: false, key: 'fieldErrors.invalid-email' };
    case 'domain': {
      const parsed = parseDomain(value);
      if (parsed.ok) {
        return { ok: true, value: parsed.value };
      }
      const m = domainLineMessage({ line: 1, raw: value, ...parsed });
      return m.params === undefined
        ? { ok: false, key: m.key }
        : { ok: false, key: m.key, params: m.params as Record<string, string> };
    }
    case 'sha256':
      return SHA256.test(value)
        ? { ok: true, value: value.toLowerCase() }
        : { ok: false, key: 'opsBlocklist.errors.sha256' };
  }
}

/** Values of the add form. */
export interface BlocklistForm {
  kind: BlocklistKind;
  value: string;
  comment: string;
}

/** The fields of the add form, for the error summary. */
export interface BlocklistFields {
  kind: FieldRef;
  value: FieldRef;
  comment: FieldRef;
}

/** Empty add form (kind email). */
export function emptyForm(): BlocklistForm {
  return { kind: 'email', value: '', comment: '' };
}

/** Client-side validation of the add form: the value per kind and the comment length. */
export function validateEntry(form: BlocklistForm, fields: BlocklistFields, t: Translate): SummaryError[] {
  const out: SummaryError[] = [];
  const value = checkValue(form.kind, form.value);
  if (!value.ok) {
    out.push({ id: fields.value.id, label: fields.value.label, message: t(value.key, value.params) });
  }
  if (codePointLength(form.comment.trim()) > COMMENT_MAX_LENGTH) {
    out.push({ id: fields.comment.id, label: fields.comment.label, message: t('fieldErrors.too-long') });
  }
  return out;
}

/** Body of the creation (the comment omitted when blank); undefined when the value is invalid. */
export function entryBody(form: BlocklistForm): BlocklistEntryCreate | undefined {
  const value = checkValue(form.kind, form.value);
  if (!value.ok) {
    return undefined;
  }
  const comment = form.comment.trim();
  return comment === ''
    ? { kind: form.kind, value: value.value }
    : { kind: form.kind, value: value.value, comment };
}

/**
 * Outcome of a failed creation: 409 already-exists is reported on the value field, field errors
 * of a validation-failed problem on their fields; any other error (or a field error on an
 * unknown field) as a general message.
 */
export function createErrorOutcome(view: ErrorView, fields: BlocklistFields, t: Translate): SubmitOutcome {
  if (view.code === 'already-exists' || view.status === 409) {
    return {
      ok: false,
      errors: [
        { id: fields.value.id, label: fields.value.label, message: t('opsBlocklist.errors.alreadyExists') },
      ],
    };
  }
  const mapped = summaryFromFields(view.fields, { ...fields });
  if (mapped.errors.length === 0 || mapped.unmatched.length > 0) {
    return { ok: false, errors: mapped.errors, message: view.message };
  }
  return { ok: false, errors: mapped.errors };
}

/**
 * List after a creation: the entry (as normalised by the server) comes first, unless the list is
 * filtered on another kind.
 */
export function prependEntry(
  state: PagedList<BlocklistEntry>,
  entry: BlocklistEntry,
  filters: BlocklistFilters,
): PagedList<BlocklistEntry> {
  if (filters.kind !== undefined && filters.kind !== entry.kind) {
    return state;
  }
  return { ...state, items: [entry, ...state.items.filter((r) => r.id !== entry.id)] };
}

/** List after a deletion (also after a 404: the entry is already gone). */
export function afterDelete(state: PagedList<BlocklistEntry>, id: string): PagedList<BlocklistEntry> {
  return removeItem(state, id);
}

/** Result text of the filter bar: number of entries loaded, "or more" when a page remains. */
export function loadedText(count: number, hasMore: boolean, t: Translate): string {
  return t(hasMore ? 'opsBlocklist.loadedMore' : 'opsBlocklist.loaded', { count });
}
