// Logic of the maintenance screen (Maintenance.svelte), kept out of the component so that it is
// unit tested in Node: view model of the state, form model, client check of the messages, body
// of the PUT, confirmation needed before saving and mapping of the API errors to fields.
//
// The messages are plain text shown on the public pages of every tenant (threat T-170): the
// client check mirrors the server rules of internal/maintenance (1 to 500 code points, no
// control character other than line feed, no U+2028 or U+2029, no bidirectional control). It
// is indicative only: the server decides.
//
// Server behaviour to keep in mind: a PUT replaces every stored message (an absent message
// clears them), and while TT_MAINTENANCE=true forces the mode, a PUT with enabled false answers
// 409 state-conflict. Every PUT in that case therefore sends enabled true, which also records
// the stored choice as "on".
import type { ErrorView } from '../../../shared/api/problem';
import type { components } from '../../../shared/api/schema';
import type { Translate } from '../../../shared/i18n/messages';
import {
  summaryFromFields,
  type FieldRef,
  type SubmitOutcome,
  type SummaryError,
} from '../../components/form';
import type { StatusVariant } from '../../components/fields';
import { codePointLength } from '../ops/filters';

/** Maintenance state (GET /admin/system/maintenance). */
export type Maintenance = components['schemas']['Maintenance'];
/** Body of PUT /admin/system/maintenance. */
export type MaintenanceUpdate = components['schemas']['MaintenanceUpdate'];

/**
 * Languages of the maintenance messages edited on the screen: the languages of the interface
 * (fr, en). The API accepts others, but a PUT replaces every stored message, so a message
 * stored in another language (for example by a script) is removed by a save from this screen.
 */
export const MESSAGE_LANGUAGES = ['fr', 'en'] as const;
/** A language of the maintenance messages. */
export type MessageLanguage = (typeof MESSAGE_LANGUAGES)[number];

/** Maximum length of a message, in Unicode code points (server: MaxMessageRunes). */
export const MAX_MESSAGE_LENGTH = 500;

// ---- Message check ---------------------------------------------------------------------------

/**
 * Reports whether the code point cp is refused in a message: a control character (category
 * Cc: U+0000 to U+001F, U+007F to U+009F) other than line feed, the line or paragraph
 * separator (U+2028, U+2029) or a bidirectional control (U+061C, U+200E, U+200F, U+202A to
 * U+202E, U+2066 to U+2069).
 */
export function isForbiddenCodePoint(cp: number): boolean {
  if (cp === 0x0a) {
    return false;
  }
  return (
    cp <= 0x1f ||
    (cp >= 0x7f && cp <= 0x9f) ||
    cp === 0x2028 ||
    cp === 0x2029 ||
    cp === 0x061c ||
    cp === 0x200e ||
    cp === 0x200f ||
    (cp >= 0x202a && cp <= 0x202e) ||
    (cp >= 0x2066 && cp <= 0x2069)
  );
}

/** Problem found in a message by the client check. */
export type MessageIssue = 'too-long' | 'forbidden-character';

/**
 * Message as sent to the API: the text without leading and trailing white space; an empty
 * result means "no message in this language".
 */
export function normalizeMessage(raw: string): string {
  return raw.trim();
}

/** Length of a message once normalised, in Unicode code points (the unit of the server rule). */
export function messageLength(raw: string): number {
  return codePointLength(normalizeMessage(raw));
}

/** Problem of a message once normalised, undefined when valid or empty (an empty one is omitted). */
export function messageIssue(raw: string): MessageIssue | undefined {
  const msg = normalizeMessage(raw);
  for (const ch of msg) {
    if (isForbiddenCodePoint(ch.codePointAt(0) as number)) {
      return 'forbidden-character';
    }
  }
  return codePointLength(msg) > MAX_MESSAGE_LENGTH ? 'too-long' : undefined;
}

// ---- View model ------------------------------------------------------------------------------

/** What the state section shows. */
export interface MaintenanceView {
  /** The maintenance mode is in effect. */
  enabled: boolean;
  /** Badge of the state. */
  variant: StatusVariant;
  /** Translation key of the state label. */
  stateKey: string;
  /** Translation key of the source label. */
  sourceKey: string;
  /** Start of the maintenance (valid date-time), when on. */
  since: string | undefined;
  /** TT_MAINTENANCE=true forces the mode: disabling is not possible here. */
  forced: boolean;
  /** Translation key of the stored choice of the super admin, shown only while forced. */
  storedKey: string | undefined;
}

/** View of the state section for a maintenance state. */
export function maintenanceView(state: Maintenance): MaintenanceView {
  const forced = state.source === 'environment';
  const since =
    state.enabled && state.since !== undefined && !Number.isNaN(Date.parse(state.since))
      ? state.since
      : undefined;
  return {
    enabled: state.enabled,
    variant: state.enabled ? 'warning' : 'ok',
    stateKey: state.enabled ? 'sysMaintenance.state.on' : 'sysMaintenance.state.off',
    sourceKey: `sysMaintenance.source.${state.source}`,
    since,
    forced,
    storedKey: forced
      ? state.adminEnabled
        ? 'sysMaintenance.stored.on'
        : 'sysMaintenance.stored.off'
      : undefined,
  };
}

// ---- Form model ------------------------------------------------------------------------------

/** Values of the form. */
export interface MaintenanceForm {
  /** Maintenance mode requested (always true while the environment forces it). */
  enabled: boolean;
  /** Message per language, as typed. */
  messages: Record<MessageLanguage, string>;
}

/** Form filled with a maintenance state: the stored choice (on while forced) and the messages. */
export function formFromMaintenance(state: Maintenance): MaintenanceForm {
  return {
    enabled: state.source === 'environment' ? true : state.adminEnabled,
    messages: {
      fr: state.message?.['fr'] ?? '',
      en: state.message?.['en'] ?? '',
    },
  };
}

/** Reports whether the form differs from the saved state (messages compared once normalised). */
export function isMaintenanceDirty(state: Maintenance, form: MaintenanceForm): boolean {
  const saved = formFromMaintenance(state);
  return (
    saved.enabled !== form.enabled ||
    MESSAGE_LANGUAGES.some(
      (lang) => normalizeMessage(saved.messages[lang]) !== normalizeMessage(form.messages[lang]),
    )
  );
}

/**
 * Body of the PUT: enabled (forced to true while the environment forces the mode) and the
 * non-empty messages; message is omitted when every field is empty, which clears the stored
 * messages.
 */
export function buildMaintenanceUpdate(form: MaintenanceForm, forced: boolean): MaintenanceUpdate {
  const message: Record<string, string> = {};
  for (const lang of MESSAGE_LANGUAGES) {
    const msg = normalizeMessage(form.messages[lang]);
    if (msg !== '') {
      message[lang] = msg;
    }
  }
  const body: MaintenanceUpdate = { enabled: forced || form.enabled };
  if (Object.keys(message).length > 0) {
    body.message = message;
  }
  return body;
}

/** Confirmation asked before saving. */
export type MaintenanceConfirmation = 'enable' | 'disable' | 'keepAfterEnvironment';

/**
 * Confirmation to ask before saving form, if any:
 * - enable / disable: the mode changes (new deposits blocked or reopened on every tenant);
 * - keepAfterEnvironment: the environment forces the mode and the stored choice is off; saving
 *   records it as on, so the mode stays on once TT_MAINTENANCE is removed.
 */
export function confirmationFor(
  state: Maintenance,
  form: MaintenanceForm,
): MaintenanceConfirmation | undefined {
  if (state.source === 'environment') {
    return state.adminEnabled ? undefined : 'keepAfterEnvironment';
  }
  if (form.enabled === state.adminEnabled) {
    return undefined;
  }
  return form.enabled ? 'enable' : 'disable';
}

/** Translation keys of a confirmation dialog. */
export interface ConfirmationKeys {
  title: string;
  text: string;
  action: string;
}

/** Translation keys of the dialog of a confirmation. */
export function confirmationKeys(kind: MaintenanceConfirmation): ConfirmationKeys {
  return {
    title: `sysMaintenance.confirm.${kind}.title`,
    text: `sysMaintenance.confirm.${kind}.text`,
    action: `sysMaintenance.confirm.${kind}.action`,
  };
}

/** Message announced after a successful save. */
export function savedKey(before: Maintenance, after: Maintenance): string {
  if (before.enabled !== after.enabled) {
    return after.enabled ? 'sysMaintenance.saved.enabled' : 'sysMaintenance.saved.disabled';
  }
  return 'sysMaintenance.saved.updated';
}

// ---- Validation and errors -------------------------------------------------------------------

/** Fields of the form, for the error summary. */
export interface MaintenanceFieldRefs {
  enabled: FieldRef;
  fr: FieldRef;
  en: FieldRef;
}

/** Message of a message issue. */
export function messageIssueText(issue: MessageIssue, t: Translate): string {
  return issue === 'too-long'
    ? t('sysMaintenance.errors.tooLong', { max: MAX_MESSAGE_LENGTH })
    : t('sysMaintenance.errors.forbiddenCharacter');
}

/** Client check of the form: the messages (an empty message is valid, it is omitted). */
export function validateMaintenanceForm(
  form: MaintenanceForm,
  refs: MaintenanceFieldRefs,
  t: Translate,
): SummaryError[] {
  const errors: SummaryError[] = [];
  for (const lang of MESSAGE_LANGUAGES) {
    const issue = messageIssue(form.messages[lang]);
    if (issue !== undefined) {
      errors.push({ id: refs[lang].id, label: refs[lang].label, message: messageIssueText(issue, t) });
    }
  }
  return errors;
}

/**
 * Outcome of a failed PUT: 409 state-conflict (the environment forces the mode) as a general
 * message, a validation failure on /message/<lang> on that message field (with the rules of
 * the messages), anything else as a general message.
 */
export function maintenanceFailure(view: ErrorView, refs: MaintenanceFieldRefs, t: Translate): SubmitOutcome {
  if (view.status === 409 && view.code === 'state-conflict') {
    return { ok: false, message: t('sysMaintenance.errors.forced') };
  }
  if (view.code === 'validation-failed') {
    const rules = t('sysMaintenance.errors.invalidMessage', { max: MAX_MESSAGE_LENGTH });
    const fields = Object.fromEntries(
      Object.entries(view.fields).map(([path, error]) => [
        path,
        path.startsWith('message.') ? { ...error, message: rules } : error,
      ]),
    );
    const { errors, unmatched } = summaryFromFields(fields, {
      enabled: refs.enabled,
      'message.fr': refs.fr,
      'message.en': refs.en,
    });
    if (errors.length > 0 && unmatched.length === 0) {
      return { ok: false, errors };
    }
    return { ok: false, message: view.message, errors };
  }
  return { ok: false, message: view.message };
}
