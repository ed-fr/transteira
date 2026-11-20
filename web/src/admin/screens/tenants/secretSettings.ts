// Logic of the one-time secrets settings screen (version 2.1, CLAUDE.md section 22.1), kept out
// of the component so that it is unit tested in Node: the editable draft, client-side validation
// mirroring SecretSettings (api/openapi.yaml), the PUT body (it replaces every setting) and the
// dirty state. Since 2.3 also the express limits: their highest value for the signed-in admin
// (the delegated admin only lowers them, threat model T-418) and the refusal of a raise; the
// express members are only sent when the admin changed them, so that a stale form never writes
// back what the super admin changed meanwhile.
import type { ErrorView } from '../../../shared/api/problem';
import type { components } from '../../../shared/api/schema';
import type { FieldRef, SummaryError } from '../../components/form';
import type { Translate } from './network';

/** Settings of the secrets module of a tenant. */
export type SecretSettings = components['schemas']['SecretSettings'];
/** Duration code of a secret. */
export type SecretDuration = components['schemas']['SecretDuration'];

/** Catalogue of the durations a tenant may offer, shortest first. */
export const SECRET_DURATIONS: readonly SecretDuration[] = ['1h', '12h', '1d', '3d', '7d', '30d'];
/** One mebibyte, in bytes. */
export const MIB = 2 ** 20;
/** Smallest allowed value of the file size, in MiB. */
export const MIN_FILE_MIB = 1;
/** Largest allowed value of the file size, in MiB. */
export const MAX_FILE_MIB = 25;

/** Bounds and defaults of the express secret limits (SecretSettings, since 2.3). */
export const EXPRESS_LIMITS = {
  perHourPerIp: { min: 1, max: 1000, def: 10 },
  perHourPerToken: { min: 1, max: 10000, def: 100 },
  maxPending: { min: 1, max: 100000, def: 1000 },
} as const;

/** Bounds and default of one express limit. */
export interface ExpressLimitBounds {
  readonly min: number;
  readonly max: number;
  readonly def: number;
}

/** Highest value of each express limit the signed-in admin may save. */
export interface ExpressCeilings {
  perHourPerIp: number;
  perHourPerToken: number;
  maxPending: number;
}

function ceilingOf(bounds: ExpressLimitBounds, stored: number | undefined, superAdmin: boolean): number {
  if (superAdmin) {
    return bounds.max;
  }
  // A missing (or zero) stored value is read as the default, like the server.
  const current = stored === undefined || stored < bounds.min ? bounds.def : stored;
  return Math.min(bounds.max, Math.max(bounds.def, current));
}

/**
 * Highest value of each express limit the signed-in admin may save (updateSecretSettings, since
 * 2.3): its bound for the super admin; for any other admin the greater of its default and its
 * stored value. A delegated admin thus lowers a limit, sets it back to its default or sends back
 * unchanged a value the super admin raised, but never raises it (403 forbidden): the express
 * ciphertexts fill the database shared by every tenant (threat model T-418).
 */
export function expressCeilings(stored: SecretSettings | undefined, superAdmin: boolean): ExpressCeilings {
  return {
    perHourPerIp: ceilingOf(EXPRESS_LIMITS.perHourPerIp, stored?.expressPerHourPerIp, superAdmin),
    perHourPerToken: ceilingOf(EXPRESS_LIMITS.perHourPerToken, stored?.expressPerHourPerToken, superAdmin),
    maxPending: ceilingOf(EXPRESS_LIMITS.maxPending, stored?.expressMaxPending, superAdmin),
  };
}

/** Ceilings of the super admin: the bounds of the specification. */
export const EXPRESS_BOUNDS: ExpressCeilings = expressCeilings(undefined, true);

/** Parameters of the hint of an express limit field: its bounds, as high as the admin may go. */
export function expressHintParams(
  bounds: ExpressLimitBounds,
  ceiling: number,
): { min: number; max: number; def: number } {
  return { min: bounds.min, max: ceiling, def: bounds.def };
}

/**
 * Reports whether a refused replacement is the refusal of a raised express limit (403
 * forbidden): the stored limits changed since the screen was loaded (for example lowered by the
 * super admin), so the ceilings are stale.
 */
export function isRaiseRefused(view: Pick<ErrorView, 'status' | 'code'>): boolean {
  return view.status === 403 && view.code === 'forbidden';
}

/** Editable copy of the settings (the file size is typed in MiB, the express limits as text). */
export interface SecretSettingsDraft {
  enabled: boolean;
  durations: SecretDuration[];
  defaultDuration: SecretDuration | '';
  fileAllowed: boolean;
  fileMibText: string;
  emailAllowed: boolean;
  emailRequiresPassphrase: boolean;
  expressEnabled: boolean;
  expressPerHourPerIpText: string;
  expressPerHourPerTokenText: string;
  expressMaxPendingText: string;
}

/** The fields of the form, for the error summary. */
export interface SecretFields {
  durations: FieldRef;
  defaultDuration: FieldRef;
  fileMaxBytes: FieldRef;
  expressPerHourPerIp: FieldRef;
  expressPerHourPerToken: FieldRef;
  expressMaxPending: FieldRef;
}

// Digits with at most three decimals, with a dot or a comma (French input).
const MIB_AMOUNT = /^[0-9]{1,3}([.,][0-9]{1,3})?$/;

/** Parses a whole number typed as digits within [min, max]; undefined when invalid or out of range. */
export function parseBoundedInt(text: string, min: number, max: number): number | undefined {
  const s = text.trim();
  if (!/^[0-9]{1,9}$/.test(s)) {
    return undefined;
  }
  const n = Number(s);
  return n >= min && n <= max ? n : undefined;
}

/** Orders a duration selection like the catalogue, without duplicate or unknown value. */
export function sortDurations(values: readonly string[]): SecretDuration[] {
  return SECRET_DURATIONS.filter((d) => values.includes(d));
}

/** File size in MiB as typed text (up to three decimals, no trailing zero). */
export function bytesToMibText(bytes: number): string {
  return String(Number((bytes / MIB).toFixed(3)));
}

/** Parses the file size typed in MiB into bytes; undefined when invalid or out of 1 to 25 MiB. */
export function parseFileMib(text: string): number | undefined {
  const s = text.trim();
  if (!MIB_AMOUNT.test(s)) {
    return undefined;
  }
  const mib = Number(s.replace(',', '.'));
  if (mib < MIN_FILE_MIB || mib > MAX_FILE_MIB) {
    return undefined;
  }
  return Math.round(mib * MIB);
}

/** Draft of saved settings; a missing default duration becomes the first offered one. */
export function toDraft(settings: SecretSettings): SecretSettingsDraft {
  const durations = sortDurations(settings.durations);
  return {
    enabled: settings.enabled,
    durations,
    defaultDuration: settings.defaultDuration ?? durations[0] ?? '',
    fileAllowed: settings.fileAllowed,
    fileMibText: bytesToMibText(settings.fileMaxBytes),
    emailAllowed: settings.emailAllowed,
    emailRequiresPassphrase: settings.emailRequiresPassphrase === true,
    expressEnabled: settings.expressEnabled === true,
    expressPerHourPerIpText: String(settings.expressPerHourPerIp ?? EXPRESS_LIMITS.perHourPerIp.def),
    expressPerHourPerTokenText: String(settings.expressPerHourPerToken ?? EXPRESS_LIMITS.perHourPerToken.def),
    expressMaxPendingText: String(settings.expressMaxPending ?? EXPRESS_LIMITS.maxPending.def),
  };
}

/**
 * Selection after checking or unchecking a duration. The default duration follows: when it is no
 * longer offered it becomes the first offered one (empty when none).
 */
export function toggleDuration(
  draft: Pick<SecretSettingsDraft, 'durations' | 'defaultDuration'>,
  duration: SecretDuration,
  on: boolean,
): Pick<SecretSettingsDraft, 'durations' | 'defaultDuration'> {
  const rest = draft.durations.filter((d) => d !== duration);
  const durations = sortDurations(on ? [...rest, duration] : rest);
  const keep = draft.defaultDuration !== '' && durations.includes(draft.defaultDuration);
  return { durations, defaultDuration: keep ? draft.defaultDuration : (durations[0] ?? '') };
}

/**
 * Client-side validation: at least one duration, a valid file size, and each express limit a
 * whole number within its bounds and at most its ceiling for the signed-in admin (the bounds by
 * default, as for the super admin; see expressCeilings).
 */
export function validateSecretSettings(
  draft: SecretSettingsDraft,
  fields: SecretFields,
  t: Translate,
  ceilings: ExpressCeilings = EXPRESS_BOUNDS,
): SummaryError[] {
  const out: SummaryError[] = [];
  if (draft.durations.length === 0) {
    out.push({
      id: fields.durations.id,
      label: fields.durations.label,
      message: t('adminSecrets.settings.errors.durationsRequired'),
    });
  } else if (draft.defaultDuration === '' || !draft.durations.includes(draft.defaultDuration)) {
    out.push({
      id: fields.defaultDuration.id,
      label: fields.defaultDuration.label,
      message: t('adminSecrets.settings.errors.defaultNotOffered'),
    });
  }
  if (parseFileMib(draft.fileMibText) === undefined) {
    out.push({
      id: fields.fileMaxBytes.id,
      label: fields.fileMaxBytes.label,
      message: t('adminSecrets.settings.errors.fileSize', { min: MIN_FILE_MIB, max: MAX_FILE_MIB }),
    });
  }
  const express = [
    [
      'expressPerHourPerIp',
      draft.expressPerHourPerIpText,
      EXPRESS_LIMITS.perHourPerIp,
      ceilings.perHourPerIp,
    ],
    [
      'expressPerHourPerToken',
      draft.expressPerHourPerTokenText,
      EXPRESS_LIMITS.perHourPerToken,
      ceilings.perHourPerToken,
    ],
    ['expressMaxPending', draft.expressMaxPendingText, EXPRESS_LIMITS.maxPending, ceilings.maxPending],
  ] as const;
  for (const [key, text, bounds, ceiling] of express) {
    const value = parseBoundedInt(text, bounds.min, bounds.max);
    if (value === undefined) {
      out.push({
        id: fields[key].id,
        label: fields[key].label,
        message: t('adminSecrets.settings.errors.expressLimit', { min: bounds.min, max: ceiling }),
      });
    } else if (value > ceiling) {
      out.push({
        id: fields[key].id,
        label: fields[key].label,
        message: t('adminSecrets.settings.errors.expressLimitRaise', { max: ceiling }),
      });
    }
  }
  return out;
}

/**
 * Body of the PUT. It replaces every setting of the 2.1 module; the file size of an invalid draft
 * falls back to the 10 MiB default (validate first). The passphrase rule only applies with e-mail
 * delivery, so it is sent false when e-mail is not allowed. The express members (since 2.3) are
 * only sent when they differ from stored, the settings of the last answer of the server: an
 * absent express member keeps the value stored at the time of the write (updateSecretSettings),
 * so a stale form never writes back the anonymous mode or a limit that the admin did not change,
 * for example closed or lowered by the super admin since the screen was loaded. Without stored,
 * every express member is sent, an invalid limit as its default (validate first).
 */
export function secretSettingsBody(draft: SecretSettingsDraft, stored?: SecretSettings): SecretSettings {
  const body: SecretSettings = {
    enabled: draft.enabled,
    durations: [...draft.durations],
    fileAllowed: draft.fileAllowed,
    fileMaxBytes: parseFileMib(draft.fileMibText) ?? 10 * MIB,
    emailAllowed: draft.emailAllowed,
    emailRequiresPassphrase: draft.emailAllowed && draft.emailRequiresPassphrase,
  };
  if (draft.defaultDuration !== '') {
    body.defaultDuration = draft.defaultDuration;
  }
  if (stored === undefined || draft.expressEnabled !== (stored.expressEnabled === true)) {
    body.expressEnabled = draft.expressEnabled;
  }
  const limits = [
    ['expressPerHourPerIp', draft.expressPerHourPerIpText, EXPRESS_LIMITS.perHourPerIp],
    ['expressPerHourPerToken', draft.expressPerHourPerTokenText, EXPRESS_LIMITS.perHourPerToken],
    ['expressMaxPending', draft.expressMaxPendingText, EXPRESS_LIMITS.maxPending],
  ] as const;
  for (const [key, text, bounds] of limits) {
    const value = parseBoundedInt(text, bounds.min, bounds.max) ?? bounds.def;
    if (stored === undefined || value !== (stored[key] ?? bounds.def)) {
      body[key] = value;
    }
  }
  return body;
}

/** Express limits of the draft, as typed text. */
const EXPRESS_TEXT_KEYS = [
  'expressPerHourPerIpText',
  'expressPerHourPerTokenText',
  'expressMaxPendingText',
] as const;

/**
 * Draft and baseline (the draft of the last stored settings, for the dirty state) once the
 * stored settings were read again, after a refused raise: each express member the admin left as
 * it was in the baseline takes its stored value, each one the admin changed is kept; the baseline
 * takes the stored values. The 2.1 members are left as they are. The screen then shows what is
 * stored (for example a limit the super admin lowered meanwhile) and secretSettingsBody, compared
 * with fresh, only sends what the admin changed.
 */
export function rebaseExpress(
  draft: SecretSettingsDraft,
  saved: SecretSettingsDraft,
  fresh: SecretSettings,
): { draft: SecretSettingsDraft; saved: SecretSettingsDraft } {
  const stored = toDraft(fresh);
  const nextDraft: SecretSettingsDraft = { ...draft, durations: [...draft.durations] };
  const nextSaved: SecretSettingsDraft = { ...saved, durations: [...saved.durations] };
  if (draft.expressEnabled === saved.expressEnabled) {
    nextDraft.expressEnabled = stored.expressEnabled;
  }
  nextSaved.expressEnabled = stored.expressEnabled;
  for (const key of EXPRESS_TEXT_KEYS) {
    if (draft[key].trim() === saved[key].trim()) {
      nextDraft[key] = stored[key];
    }
    nextSaved[key] = stored[key];
  }
  return { draft: nextDraft, saved: nextSaved };
}

/** Reports whether two drafts differ. */
export function secretDraftChanged(a: SecretSettingsDraft, b: SecretSettingsDraft): boolean {
  return (
    a.enabled !== b.enabled ||
    a.durations.join() !== b.durations.join() ||
    a.defaultDuration !== b.defaultDuration ||
    a.fileAllowed !== b.fileAllowed ||
    a.fileMibText.trim() !== b.fileMibText.trim() ||
    a.emailAllowed !== b.emailAllowed ||
    a.emailRequiresPassphrase !== b.emailRequiresPassphrase ||
    a.expressEnabled !== b.expressEnabled ||
    a.expressPerHourPerIpText.trim() !== b.expressPerHourPerIpText.trim() ||
    a.expressPerHourPerTokenText.trim() !== b.expressPerHourPerTokenText.trim() ||
    a.expressMaxPendingText.trim() !== b.expressMaxPendingText.trim()
  );
}

/** Result text of the purge of the live anonymous express secrets. */
export function purgeResultText(deleted: number, t: Translate): string {
  return t('adminSecrets.express.purge.done', { count: deleted });
}
