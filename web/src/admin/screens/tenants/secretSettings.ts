// Logic of the one-time secrets settings screen (version 2.1, CLAUDE.md section 22.1), kept out
// of the component so that it is unit tested in Node: the editable draft, client-side validation
// mirroring SecretSettings (api/openapi.yaml), the PUT body (it replaces every setting) and the
// dirty state.
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

/** Editable copy of the settings (the file size is typed in MiB). */
export interface SecretSettingsDraft {
  enabled: boolean;
  durations: SecretDuration[];
  defaultDuration: SecretDuration | '';
  fileAllowed: boolean;
  fileMibText: string;
  emailAllowed: boolean;
  emailRequiresPassphrase: boolean;
}

/** The fields of the form, for the error summary. */
export interface SecretFields {
  durations: FieldRef;
  defaultDuration: FieldRef;
  fileMaxBytes: FieldRef;
}

// Digits with at most three decimals, with a dot or a comma (French input).
const MIB_AMOUNT = /^[0-9]{1,3}([.,][0-9]{1,3})?$/;

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

/** Client-side validation: at least one duration, a valid file size (when files are allowed). */
export function validateSecretSettings(
  draft: SecretSettingsDraft,
  fields: SecretFields,
  t: Translate,
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
  return out;
}

/**
 * Body of the PUT (it replaces every setting). The file size of an invalid draft falls back to
 * the 10 MiB default: validate first. The passphrase rule only applies with e-mail delivery, so
 * it is sent false when e-mail is not allowed.
 */
export function secretSettingsBody(draft: SecretSettingsDraft): SecretSettings {
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
  return body;
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
    a.emailRequiresPassphrase !== b.emailRequiresPassphrase
  );
}
