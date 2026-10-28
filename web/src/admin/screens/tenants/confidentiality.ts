// Logic of the tenant confidentiality levels screen (CLAUDE.md section 8.3, version 1.1), kept
// out of the component so that it is unit tested in Node: editable drafts of the levels,
// client-side validation mirroring api/openapi.yaml (ConfidentialityLevelList), list operations,
// the request body, dirty state and the mapping of server field errors to the drafts.
import type { FieldMessage } from '../../../shared/api/problem';
import { languageValues, type components } from '../../../shared/api/schema';
import type { FieldRef, SummaryError } from '../../components/form';

/** A confidentiality level as stored by the API. */
export type ConfidentialityLevel = components['schemas']['ConfidentialityLevel'];

/** Languages of the labels and descriptions (every supported language is required). */
export const LEVEL_LANGUAGES: readonly string[] = languageValues;
/** Durations a level may allow, in days. */
export const EXPIRY_CHOICES = [1, 7, 30] as const;
/** Minimum number of levels. */
export const MIN_LEVELS = 1;
/** Maximum number of levels. */
export const MAX_LEVELS = 10;
/** Maximum length of a label, in characters. */
export const LABEL_MAX_LENGTH = 50;
/** Maximum length of a description, in characters. */
export const DESCRIPTION_MAX_LENGTH = 500;
/** Maximum value of the download cap. */
export const MAX_DOWNLOADS_CAP = 1000;
/** Format of a level key (ConfidentialityLevelKey). */
export const KEY_PATTERN = /^[a-z][a-z0-9_-]{0,31}$/;

/** Translation function (t of the i18n module). */
export type Translate = (key: string, params?: Record<string, string | number>) => string;

/** Editable copy of a level; uid identifies it across reorders (never sent). */
export interface LevelDraft {
  uid: number;
  key: string;
  labels: Record<string, string>;
  descriptions: Record<string, string>;
  isDefault: boolean;
  allowedExpiryDays: number[];
  requirePassword: boolean;
  requireRecipientVerification: boolean;
  internalRecipientsOnly: boolean;
  forceDeleteAfterFirstDownload: boolean;
  /** Cap of the number of downloads as typed; empty for none. */
  maxDownloadsText: string;
}

/** A field of a level that can carry an error. */
export type LevelField = 'key' | 'days' | 'maxDownloads' | `label.${string}` | `description.${string}`;

function blankTexts(): Record<string, string> {
  return Object.fromEntries(LEVEL_LANGUAGES.map((lang) => [lang, '']));
}

/** Draft of a level read from the API. */
export function toDraft(level: ConfidentialityLevel, uid: number): LevelDraft {
  const labels = blankTexts();
  const descriptions = blankTexts();
  for (const lang of LEVEL_LANGUAGES) {
    labels[lang] = level.labels[lang] ?? '';
    descriptions[lang] = level.descriptions?.[lang] ?? '';
  }
  return {
    uid,
    key: level.key,
    labels,
    descriptions,
    isDefault: level.isDefault,
    allowedExpiryDays: [...level.rules.allowedExpiryDays],
    requirePassword: level.rules.requirePassword,
    requireRecipientVerification: level.rules.requireRecipientVerification,
    internalRecipientsOnly: level.rules.internalRecipientsOnly,
    forceDeleteAfterFirstDownload: level.rules.forceDeleteAfterFirstDownload,
    maxDownloadsText: level.rules.maxDownloads === null ? '' : String(level.rules.maxDownloads),
  };
}

/** A blank level for the "add" button: all durations, no constraint. */
export function newDraft(uid: number, isDefault: boolean): LevelDraft {
  return {
    uid,
    key: '',
    labels: blankTexts(),
    descriptions: blankTexts(),
    isDefault,
    allowedExpiryDays: [...EXPIRY_CHOICES],
    requirePassword: false,
    requireRecipientVerification: false,
    internalRecipientsOnly: false,
    forceDeleteAfterFirstDownload: false,
    maxDownloadsText: '',
  };
}

/** Parsed cap: a number, null for none, undefined when the text is not valid. */
export function parseCap(text: string | number | null | undefined): number | null | undefined {
  // A number input bound with bind:value yields a number (or null when empty).
  const trimmed = String(text ?? '').trim();
  if (trimmed === '') {
    return null;
  }
  if (!/^\d+$/.test(trimmed)) {
    return undefined;
  }
  const n = Number(trimmed);
  return n >= 1 && n <= MAX_DOWNLOADS_CAP ? n : undefined;
}

/** Level to send for a draft (trimmed texts, empty descriptions omitted, ordered durations). */
export function fromDraft(draft: LevelDraft): ConfidentialityLevel {
  const labels: Record<string, string> = {};
  const descriptions: Record<string, string> = {};
  for (const lang of LEVEL_LANGUAGES) {
    labels[lang] = (draft.labels[lang] ?? '').trim();
    const description = (draft.descriptions[lang] ?? '').trim();
    if (description !== '') {
      descriptions[lang] = description;
    }
  }
  const level: ConfidentialityLevel = {
    key: draft.key.trim(),
    labels,
    isDefault: draft.isDefault,
    rules: {
      requireRecipientVerification: draft.requireRecipientVerification,
      requirePassword: draft.requirePassword,
      allowedExpiryDays: EXPIRY_CHOICES.filter((d) => draft.allowedExpiryDays.includes(d)),
      internalRecipientsOnly: draft.internalRecipientsOnly,
      forceDeleteAfterFirstDownload: draft.forceDeleteAfterFirstDownload,
      maxDownloads: parseCap(draft.maxDownloadsText) ?? null,
    },
  };
  if (Object.keys(descriptions).length > 0) {
    level.descriptions = descriptions;
  }
  return level;
}

/** Body of the PUT. */
export function levelsBody(drafts: readonly LevelDraft[]): components['schemas']['ConfidentialityLevelList'] {
  return { items: drafts.map(fromDraft) };
}

/** Reports whether the drafts differ from the saved levels. */
export function levelsChanged(
  saved: readonly ConfidentialityLevel[],
  drafts: readonly LevelDraft[],
): boolean {
  const normalize = (levels: readonly ConfidentialityLevel[]): string =>
    JSON.stringify(levels.map((l) => fromDraft(toDraft(l, 0))));
  return normalize(saved) !== normalize(levelsBody(drafts).items);
}

// ---- List operations -----------------------------------------------------------------------

/** Moves a level by delta places (-1 up, +1 down); out-of-range moves return the list as is. */
export function moveLevel(drafts: readonly LevelDraft[], index: number, delta: number): LevelDraft[] {
  const target = index + delta;
  if (index < 0 || index >= drafts.length || target < 0 || target >= drafts.length) {
    return [...drafts];
  }
  const out = [...drafts];
  const [moved] = out.splice(index, 1);
  out.splice(target, 0, moved as LevelDraft);
  return out;
}

/** Makes one level the default (and the others not). */
export function setDefault(drafts: readonly LevelDraft[], index: number): LevelDraft[] {
  return drafts.map((d, i) => ({ ...d, isDefault: i === index }));
}

/** Removes a level; when it was the default, the first remaining one becomes the default. */
export function removeLevel(drafts: readonly LevelDraft[], index: number): LevelDraft[] {
  const out = drafts.filter((_d, i) => i !== index);
  if (out.length > 0 && !out.some((d) => d.isDefault)) {
    out[0] = { ...(out[0] as LevelDraft), isDefault: true };
  }
  return out;
}

/** Adds a blank level at the end (the default one when the list is empty). */
export function addLevel(drafts: readonly LevelDraft[], uid: number): LevelDraft[] {
  if (drafts.length >= MAX_LEVELS) {
    return [...drafts];
  }
  return [...drafts, newDraft(uid, drafts.length === 0)];
}

// ---- Validation ----------------------------------------------------------------------------

/** Reference of a field of the form (id to focus, label for the summary). */
export type FieldRefOf = (index: number, field: LevelField | 'list') => FieldRef;

const ERR = 'adminTenants.confidentiality.errors';

function keyError(key: string, others: readonly string[]): string | undefined {
  const trimmed = key.trim();
  if (trimmed === '') {
    return `${ERR}.keyRequired`;
  }
  if (!KEY_PATTERN.test(trimmed)) {
    return `${ERR}.keyFormat`;
  }
  return others.includes(trimmed) ? `${ERR}.keyDuplicate` : undefined;
}

/**
 * Client-side validation, mirroring the spec: 1 to 10 levels, exactly one default, unique keys of
 * the form [a-z][a-z0-9_-]{0,31}, a label of 1 to 50 characters in each language, descriptions
 * of at most 500 characters, at least one duration, a cap between 1 and 1000 or empty.
 */
export function validateLevels(drafts: readonly LevelDraft[], ref: FieldRefOf, t: Translate): SummaryError[] {
  const out: SummaryError[] = [];
  const push = (
    index: number,
    field: LevelField | 'list',
    key: string,
    params?: Record<string, string | number>,
  ): void => {
    const r = ref(index, field);
    out.push({ id: r.id, label: r.label, message: t(key, params) });
  };
  if (drafts.length < MIN_LEVELS) {
    push(0, 'list', `${ERR}.noLevel`);
    return out;
  }
  if (drafts.length > MAX_LEVELS) {
    push(0, 'list', `${ERR}.tooMany`, { max: MAX_LEVELS });
  }
  if (drafts.filter((d) => d.isDefault).length !== 1) {
    push(0, 'list', `${ERR}.defaultCount`);
  }
  drafts.forEach((draft, index) => {
    const others = drafts.filter((_d, i) => i !== index).map((d) => d.key.trim());
    const kerr = keyError(draft.key, others);
    if (kerr !== undefined) {
      push(index, 'key', kerr);
    }
    for (const lang of LEVEL_LANGUAGES) {
      const label = (draft.labels[lang] ?? '').trim();
      if (label === '') {
        push(index, `label.${lang}`, `${ERR}.labelRequired`);
      } else if ([...label].length > LABEL_MAX_LENGTH) {
        push(index, `label.${lang}`, `${ERR}.labelTooLong`, { max: LABEL_MAX_LENGTH });
      }
      if ([...(draft.descriptions[lang] ?? '').trim()].length > DESCRIPTION_MAX_LENGTH) {
        push(index, `description.${lang}`, `${ERR}.descriptionTooLong`, { max: DESCRIPTION_MAX_LENGTH });
      }
    }
    if (draft.allowedExpiryDays.length === 0) {
      push(index, 'days', `${ERR}.daysRequired`);
    }
    if (parseCap(draft.maxDownloadsText) === undefined) {
      push(index, 'maxDownloads', `${ERR}.capInvalid`, { max: MAX_DOWNLOADS_CAP });
    }
  });
  return out;
}

// ---- Server errors -------------------------------------------------------------------------

/** Field of a level a normalised server field path ("items.2.rules.maxDownloads") designates. */
export function parseServerPath(path: string): { index: number; field: LevelField } | 'list' | undefined {
  const parts = path.split('.');
  if (parts[0] !== 'items') {
    return undefined;
  }
  if (parts.length === 1) {
    return 'list';
  }
  const index = Number(parts[1]);
  if (!Number.isInteger(index) || index < 0) {
    return undefined;
  }
  const rest = parts.slice(2).join('.');
  if (rest === 'key') {
    return { index, field: 'key' };
  }
  if (rest === 'rules.allowedExpiryDays' || rest.startsWith('rules.allowedExpiryDays.')) {
    return { index, field: 'days' };
  }
  if (rest === 'rules.maxDownloads') {
    return { index, field: 'maxDownloads' };
  }
  const lang = /^(labels|descriptions)\.(.+)$/.exec(rest);
  if (lang !== null && LEVEL_LANGUAGES.includes(lang[2] as string)) {
    return { index, field: lang[1] === 'labels' ? `label.${lang[2]}` : `description.${lang[2]}` };
  }
  return undefined;
}

/**
 * Maps the field errors of a validation-failed answer (normalised paths) to the error summary;
 * paths that match no field of a level, and list-level errors, are returned in unmatched.
 */
export function serverLevelErrors(
  apiFields: Readonly<Record<string, FieldMessage>>,
  drafts: readonly LevelDraft[],
  ref: FieldRefOf,
): { errors: SummaryError[]; unmatched: string[] } {
  const errors: SummaryError[] = [];
  const unmatched: string[] = [];
  const seen = new Set<string>();
  for (const [path, error] of Object.entries(apiFields)) {
    const parsed = parseServerPath(path);
    if (parsed === undefined || parsed === 'list' || parsed.index >= drafts.length) {
      unmatched.push(path);
      continue;
    }
    const r = ref(parsed.index, parsed.field);
    if (!seen.has(r.id)) {
      seen.add(r.id);
      errors.push({ id: r.id, label: r.label, message: error.message });
    }
  }
  return { errors, unmatched };
}
