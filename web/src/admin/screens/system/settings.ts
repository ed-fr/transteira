// Logic of the system settings screen (SystemSettings.svelte), kept out of the component so
// that it is unit tested in Node: the disk alert threshold edited as a percentage, the alert
// address with its confirmation, the merge patch of the changed fields and the mapping of the
// API errors to fields.
//
// The server stores the threshold in basis points (rounded to the nearest one), from 0.50 to
// 0.99. The screen edits a percentage from 50 to 99 with at most two decimals (one basis point),
// so that a stored value such as 0.855 is shown exactly (85.5) and saved unchanged. The address
// is not verified by the server: the screen asks to type it twice when it changes.
import type { ErrorView } from '../../../shared/api/problem';
import type { components } from '../../../shared/api/schema';
import type { Translate } from '../../../shared/i18n/messages';
import { EMAIL_MAX_LENGTH, isEmail } from '../../../shared/validation/email';
import {
  summaryFromFields,
  type FieldRef,
  type SubmitOutcome,
  type SummaryError,
} from '../../components/form';
import { buildPatch } from '../../forms/patch';

/** Instance settings (GET /admin/system/settings). */
export type SystemSettings = components['schemas']['SystemSettings'];
/** Merge patch of the instance settings. */
export type SystemSettingsUpdate = components['schemas']['SystemSettingsUpdate'];

/** Lowest threshold, in percent. */
export const MIN_THRESHOLD_PERCENT = 50;
/** Highest threshold, in percent. */
export const MAX_THRESHOLD_PERCENT = 99;
/** Points below the threshold at which the alert clears. */
export const ALERT_HYSTERESIS_POINTS = 5;

// ---- Threshold -------------------------------------------------------------------------------

/** Threshold ratio rounded to the basis point, as the server stores it. */
export function roundRatio(ratio: number): number {
  return Math.round(ratio * 10_000) / 10_000;
}

/** Percentage of a ratio, rounded to the basis point (0.855 → 85.5). */
export function percentFromRatio(ratio: number): number {
  return Math.round(ratio * 10_000) / 100;
}

/** Ratio of a percentage, rounded to the basis point (85.5 → 0.855). */
export function ratioFromPercent(percent: number): number {
  return Math.round(percent * 100) / 10_000;
}

/** Text of the threshold field for a ratio, with the decimal separator of the locale. */
export function formatPercentInput(ratio: number, decimalSeparator: string): string {
  return String(percentFromRatio(ratio)).replace('.', decimalSeparator);
}

/** Decimal separator of a locale ("," in French, "." in English). */
export function decimalSeparator(locale: string): string {
  try {
    const part = new Intl.NumberFormat(locale || 'en').formatToParts(1.5).find((p) => p.type === 'decimal');
    return part?.value ?? '.';
  } catch {
    return '.';
  }
}

/** Problem of the threshold field. */
export type ThresholdIssue = 'required' | 'invalid' | 'range';

/** Parses the threshold field: digits with at most two decimals ("." or ","), else undefined. */
export function parsePercent(raw: string): number | undefined {
  const text = raw.trim().replace(',', '.');
  if (!/^\d{1,3}(\.\d{1,2})?$/.test(text)) {
    return undefined;
  }
  return Number(text);
}

/** Problem of the threshold field, undefined when it holds a percentage from 50 to 99. */
export function thresholdIssue(raw: string): ThresholdIssue | undefined {
  if (raw.trim() === '') {
    return 'required';
  }
  const percent = parsePercent(raw);
  if (percent === undefined) {
    return 'invalid';
  }
  return percent < MIN_THRESHOLD_PERCENT || percent > MAX_THRESHOLD_PERCENT ? 'range' : undefined;
}

// ---- Form model ------------------------------------------------------------------------------

/** Values of the form. */
export interface SettingsForm {
  /** Threshold in percent, as typed. */
  threshold: string;
  /** Alert address, as typed; empty: no address. */
  email: string;
  /** Address typed again, required when the address changes. */
  emailConfirm: string;
}

/** Form filled with the saved settings. */
export function formFromSettings(settings: SystemSettings, separator: string): SettingsForm {
  return {
    threshold: formatPercentInput(settings.diskAlertThreshold, separator),
    email: settings.alertEmail ?? '',
    emailConfirm: '',
  };
}

/** Reports whether the form sets a new, non-empty address (the confirmation is then required). */
export function emailChanged(settings: SystemSettings, form: SettingsForm): boolean {
  const email = form.email.trim();
  return email !== '' && email !== (settings.alertEmail ?? '');
}

/** Reports whether the form removes the saved address. */
export function emailRemoved(settings: SystemSettings, form: SettingsForm): boolean {
  return settings.alertEmail !== null && form.email.trim() === '';
}

/**
 * Merge patch of the changed fields: the threshold (as a ratio rounded to the basis point)
 * when it differs from the saved one, the new address, or null to remove it. An unchanged or
 * unparseable field is left out, so an empty object means that there is nothing to save.
 */
export function settingsPatch(settings: SystemSettings, form: SettingsForm): SystemSettingsUpdate {
  const percent = parsePercent(form.threshold);
  const email = form.email.trim();
  const patch: SystemSettingsUpdate = buildPatch<SystemSettingsUpdate, 'diskAlertThreshold' | 'alertEmail'>(
    { diskAlertThreshold: roundRatio(settings.diskAlertThreshold), alertEmail: settings.alertEmail },
    {
      diskAlertThreshold: percent === undefined ? undefined : ratioFromPercent(percent),
      alertEmail: email === '' ? null : email,
    },
    ['diskAlertThreshold', 'alertEmail'],
  );
  if (emailRemoved(settings, form)) {
    patch.alertEmail = null;
  }
  return patch;
}

/**
 * Reports whether the form was edited: a threshold whose value differs from the saved one
 * (compared parsed, so "85", "85.0" and "85,0" are the same value and a change of the interface
 * language, which changes the decimal separator, never makes the form dirty), a threshold that
 * cannot be parsed, or another address.
 */
export function isSettingsDirty(settings: SystemSettings, form: SettingsForm): boolean {
  const percent = parsePercent(form.threshold);
  return (
    percent === undefined ||
    ratioFromPercent(percent) !== roundRatio(settings.diskAlertThreshold) ||
    form.email.trim() !== (settings.alertEmail ?? '')
  );
}

// ---- Validation and errors -------------------------------------------------------------------

/** Fields of the form, for the error summary. */
export interface SettingsFieldRefs {
  diskAlertThreshold: FieldRef;
  alertEmail: FieldRef;
  emailConfirm: FieldRef;
}

/** Message of a threshold issue. */
export function thresholdIssueText(issue: ThresholdIssue, t: Translate): string {
  switch (issue) {
    case 'required':
      return t('sysSettings.threshold.required');
    case 'invalid':
      return t('sysSettings.threshold.invalid');
    default:
      return t('sysSettings.threshold.range', { min: MIN_THRESHOLD_PERCENT, max: MAX_THRESHOLD_PERCENT });
  }
}

/** Client check of the form: threshold, address and its confirmation when it changes. */
export function validateSettingsForm(
  settings: SystemSettings,
  form: SettingsForm,
  refs: SettingsFieldRefs,
  t: Translate,
): SummaryError[] {
  const errors: SummaryError[] = [];
  const add = (ref: FieldRef, message: string): void => {
    errors.push({ id: ref.id, label: ref.label, message });
  };
  const issue = thresholdIssue(form.threshold);
  if (issue !== undefined) {
    add(refs.diskAlertThreshold, thresholdIssueText(issue, t));
  }
  const email = form.email.trim();
  if (email !== '' && (email.length > EMAIL_MAX_LENGTH || !isEmail(email))) {
    add(refs.alertEmail, t('sysSettings.email.invalid'));
  } else if (emailChanged(settings, form)) {
    const confirm = form.emailConfirm.trim();
    if (confirm === '') {
      add(refs.emailConfirm, t('sysSettings.email.confirmRequired'));
    } else if (confirm.toLowerCase() !== email.toLowerCase()) {
      add(refs.emailConfirm, t('sysSettings.email.confirmMismatch'));
    }
  }
  return errors;
}

/**
 * Outcome of a failed PATCH: the field errors of a validation failure on their fields (range
 * for the threshold, invalid-email for the address), anything else as a general message.
 */
export function settingsFailure(view: ErrorView, refs: SettingsFieldRefs, t: Translate): SubmitOutcome {
  if (view.code !== 'validation-failed') {
    return { ok: false, message: view.message };
  }
  const fields = { ...view.fields };
  const threshold = fields['diskAlertThreshold'];
  if (threshold !== undefined) {
    fields['diskAlertThreshold'] = { ...threshold, message: thresholdIssueText('range', t) };
  }
  const email = fields['alertEmail'];
  if (email !== undefined) {
    fields['alertEmail'] = { ...email, message: t('sysSettings.email.invalid') };
  }
  const { errors, unmatched } = summaryFromFields(fields, {
    diskAlertThreshold: refs.diskAlertThreshold,
    alertEmail: refs.alertEmail,
  });
  if (errors.length > 0 && unmatched.length === 0) {
    return { ok: false, errors };
  }
  return { ok: false, message: view.message, errors };
}

// ---- Antivirus engine (since 1.1) ------------------------------------------------------------

/** Antivirus engine of the instance (read only, TT_ANTIVIRUS_ENGINE). */
export type AntivirusEngine = components['schemas']['AntivirusEngine'];

/** Translation key of the label of an engine; an unknown engine is shown as its raw value. */
export function engineLabelKey(engine: string): string | undefined {
  switch (engine) {
    case 'clamd':
    case 'icap':
    case 'http':
    case 'none':
      return `sysSettings.antivirus.engine.${engine}`;
    default:
      return undefined;
  }
}

/** Label of an engine, or its raw value when this version does not know it. */
export function engineLabel(engine: string, t: Translate): string {
  const key = engineLabelKey(engine);
  return key === undefined ? engine : t(key);
}

/** Reports whether the engine means that no file of the instance is analysed. */
export function engineDisabled(engine: string | undefined): boolean {
  return engine === 'none';
}
