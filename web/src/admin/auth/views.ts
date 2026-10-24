// View models of the admin authentication screens (pure, no DOM): which step a screen shows for
// the current authentication state, client-side checks of the credential forms, mapping of the
// API errors of each flow to messages and fields, countdown arithmetic and the recovery codes
// text file. The screens (screens/auth/*.svelte, screens/Account.svelte) only render these.
//
// Secrets (passwords, TOTP secret, recovery codes) are never stored here: the functions take
// them as arguments and return derived values for the component that holds them in memory.
import type { ErrorView } from '../../shared/api/problem';
import type { AuthOrigin, AuthState, TotpEnrollment } from './machine';

/** Minimum length of an admin password (AdminPassword.minLength). */
export const MIN_PASSWORD_LENGTH = 12;

/** Pattern of a username (Username schema). */
export const USERNAME = /^[a-z0-9][a-z0-9._-]{2,63}$/;

/** Pattern of a TOTP code once spaces are removed. */
export const TOTP_CODE = /^[0-9]{6}$/;

/** Maximum length of a recovery code (TotpCode.recoveryCode.maxLength). */
export const MAX_RECOVERY_CODE_LENGTH = 32;

// ---- Steps ---------------------------------------------------------------------------------

/** Step shown by an authentication screen. */
export type FlowView =
  /** The screen's own form (password, setup, activation). */
  | { kind: 'form' }
  /** Waiting for the profile or the bootstrap. */
  | { kind: 'loading' }
  /** Second factor: TOTP code or recovery code. */
  | { kind: 'totp' }
  /** Mandatory enrollment whose secret must still be requested. */
  | { kind: 'enrollStart' }
  /** Mandatory enrollment with its secret. */
  | { kind: 'enroll'; enrollment: TotpEnrollment }
  /** Step this interface does not handle (password_change_required, V2 SSO...). */
  | { kind: 'unsupported' }
  /** Recovery codes shown once. */
  | { kind: 'recovery'; codes: string[]; username: string | undefined }
  /** Fully authenticated: the screen navigates away. */
  | { kind: 'done' };

/**
 * Step to show on the screen of the flow origin. Intermediate steps opened by another flow are
 * ignored (the screen shows its own form).
 */
export function flowView(state: AuthState, origin: AuthOrigin): FlowView {
  switch (state.kind) {
    case 'authenticated':
      return { kind: 'done' };
    case 'loading':
      return state.origin === undefined || state.origin === origin ? { kind: 'loading' } : { kind: 'form' };
    case 'preauth':
      if (state.origin !== origin) {
        return { kind: 'form' };
      }
      switch (state.step) {
        case 'totp':
          return { kind: 'totp' };
        case 'enroll':
          return state.enrollment === undefined
            ? { kind: 'enrollStart' }
            : { kind: 'enroll', enrollment: state.enrollment };
        default:
          return { kind: 'unsupported' };
      }
    case 'recovery':
      return state.origin === origin
        ? { kind: 'recovery', codes: state.codes, username: state.me?.username }
        : { kind: 'form' };
    default:
      return { kind: 'form' };
  }
}

/** Reports whether two views are the same step (a change of step moves the focus). */
export function sameStep(a: FlowView, b: FlowView): boolean {
  return a.kind === b.kind;
}

// ---- Client-side checks --------------------------------------------------------------------

/** A message: a translation key with optional parameters, or text already translated. */
export type Message = { key: string; params?: Record<string, string | number> } | { text: string };

/** Error of a field. */
export type FieldError = Message;

/** Renders a message with the translation function. */
export function renderMessage(
  message: Message | undefined,
  t: (key: string, params?: Record<string, string | number>) => string,
): string | undefined {
  if (message === undefined) {
    return undefined;
  }
  return 'text' in message ? message.text : t(message.key, message.params);
}

/** Errors of a form keyed by field name; absent fields are valid. */
export type FormErrors = Partial<Record<string, FieldError>>;

const REQUIRED: FieldError = { key: 'fieldErrors.required' };

/** Error of a new password: required, then at least MIN_PASSWORD_LENGTH characters. */
export function newPasswordError(password: string): FieldError | undefined {
  if (password === '') {
    return REQUIRED;
  }
  return [...password].length < MIN_PASSWORD_LENGTH ? { key: 'adminAuth.password.tooShort' } : undefined;
}

/** Error of the confirmation of a new password: required, then equal to the password. */
export function confirmPasswordError(password: string, confirmation: string): FieldError | undefined {
  if (confirmation === '') {
    return REQUIRED;
  }
  return confirmation === password ? undefined : { key: 'adminAuth.password.mismatch' };
}

/** Values of the setup form. */
export interface SetupValues {
  username: string;
  email: string;
  password: string;
  confirm: string;
  setupToken: string;
}

/** Client-side checks of the setup form (the server checks again). */
export function validateSetup(v: SetupValues): FormErrors {
  const errors: FormErrors = {};
  const username = v.username.trim();
  if (username === '') {
    errors['username'] = REQUIRED;
  } else if (!USERNAME.test(username)) {
    errors['username'] = { key: 'fieldErrors.invalid-username' };
  }
  const email = v.email.trim();
  if (email === '') {
    errors['email'] = REQUIRED;
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    errors['email'] = { key: 'fieldErrors.invalid-email' };
  }
  setIf(errors, 'password', newPasswordError(v.password));
  setIf(errors, 'confirm', confirmPasswordError(v.password, v.confirm));
  if (v.setupToken.trim() === '') {
    errors['setupToken'] = REQUIRED;
  }
  return errors;
}

/** Client-side checks of the login form: both fields required. */
export function validateLogin(username: string, password: string): FormErrors {
  const errors: FormErrors = {};
  if (username.trim() === '') {
    errors['username'] = REQUIRED;
  }
  if (password === '') {
    errors['password'] = REQUIRED;
  }
  return errors;
}

/** Client-side checks of a new password with its confirmation (activation). */
export function validateNewPassword(password: string, confirm: string): FormErrors {
  const errors: FormErrors = {};
  setIf(errors, 'password', newPasswordError(password));
  setIf(errors, 'confirm', confirmPasswordError(password, confirm));
  return errors;
}

/** Client-side checks of the password change form. */
export function validatePasswordChange(current: string, password: string, confirm: string): FormErrors {
  const errors: FormErrors = {};
  if (current === '') {
    errors['current'] = REQUIRED;
  }
  return { ...errors, ...validateNewPassword(password, confirm) };
}

/** Error of a "current password" confirmation field. */
export function currentPasswordError(current: string): FieldError | undefined {
  return current === '' ? REQUIRED : undefined;
}

function setIf(errors: FormErrors, field: string, error: FieldError | undefined): void {
  if (error !== undefined) {
    errors[field] = error;
  }
}

/** Reports whether a form has no error. */
export function isValid(errors: FormErrors): boolean {
  return Object.values(errors).every((e) => e === undefined);
}

/** Removes the spaces of a typed or pasted TOTP code ("123 456" → "123456"). */
export function normalizeTotpCode(raw: string): string {
  return raw.replace(/\s+/g, '');
}

/** Error of a typed TOTP code: required, then 6 digits. */
export function totpCodeError(raw: string): FieldError | undefined {
  const code = normalizeTotpCode(raw);
  if (code === '') {
    return REQUIRED;
  }
  return TOTP_CODE.test(code) ? undefined : { key: 'adminAuth.totp.format' };
}

/** Recovery code as sent: surrounding spaces removed. */
export function normalizeRecoveryCode(raw: string): string {
  return raw.trim();
}

/** Error of a typed recovery code: required, then at most MAX_RECOVERY_CODE_LENGTH characters. */
export function recoveryCodeError(raw: string): FieldError | undefined {
  const code = normalizeRecoveryCode(raw);
  if (code === '') {
    return REQUIRED;
  }
  return code.length > MAX_RECOVERY_CODE_LENGTH ? { key: 'fieldErrors.too-long' } : undefined;
}

// ---- API errors ----------------------------------------------------------------------------

/** Display of an API error by a form. */
export interface FormFailure {
  /** General message (a translation key with parameters), or the localised server message. */
  general?: Message;
  /** Field errors. */
  fields: FormErrors;
  /** Seconds before a new attempt (rate limited), when known. */
  retryAfterSeconds?: number;
  /** Attempts left after a wrong code. */
  attemptsRemaining?: number;
  /** The flow cannot go on from this screen. */
  redirect?: 'login';
  /** The activation link is invalid, used or expired. */
  invalidLink?: boolean;
  /** The pending TOTP enrollment expired: restart it. */
  enrollmentExpired?: boolean;
}

function rateLimited(view: ErrorView, key: string): FormFailure {
  return view.retryAfterSeconds === undefined || view.retryAfterSeconds <= 0
    ? { general: { key: 'adminAuth.login.lockedNoDelay' }, fields: {} }
    : {
        general: { key, params: { count: view.retryAfterSeconds } },
        fields: {},
        retryAfterSeconds: view.retryAfterSeconds,
      };
}

function generic(view: ErrorView): FormFailure {
  return { general: { text: view.message }, fields: {} };
}

/**
 * Maps the field errors of a validation-failed problem to the form fields: names maps an API
 * field path to a form field and to the message key shown there (otherwise the translated
 * field message of describeError).
 */
function mapFields(view: ErrorView, names: Record<string, { field: string; key?: string }>): FormErrors {
  const out: FormErrors = {};
  for (const [path, error] of Object.entries(view.fields)) {
    const target = names[path];
    if (target !== undefined && out[target.field] === undefined) {
      out[target.field] = target.key === undefined ? { text: error.message } : { key: target.key };
    }
  }
  return out;
}

function validation(view: ErrorView, names: Record<string, { field: string; key?: string }>): FormFailure {
  const fields = mapFields(view, names);
  return isValid(fields) ? generic(view) : { fields };
}

/** Error of the first-run setup. */
export function setupFailure(view: ErrorView): FormFailure {
  switch (view.code) {
    case 'setup-token-invalid':
      return { fields: { setupToken: { key: 'adminAuth.setup.tokenInvalid' } } };
    case 'setup-already-done':
      return { general: { key: 'adminAuth.setup.alreadyDone' }, fields: {}, redirect: 'login' };
    case 'rate-limited':
      return rateLimited(view, 'adminAuth.login.locked');
    case 'validation-failed':
      return validation(view, {
        username: { field: 'username' },
        email: { field: 'email' },
        password: { field: 'password', key: 'adminAuth.password.rejected' },
        setupToken: { field: 'setupToken' },
      });
    default:
      return generic(view);
  }
}

/**
 * Error of the first factor. Wrong credentials and malformed input both give the same generic
 * message, which never tells whether the account exists.
 */
export function loginFailure(view: ErrorView): FormFailure {
  switch (view.code) {
    case 'invalid-credentials':
    case 'validation-failed':
      return { general: { key: 'adminAuth.login.invalid' }, fields: {} };
    case 'rate-limited':
      return rateLimited(view, 'adminAuth.login.locked');
    default:
      return generic(view);
  }
}

/** Error of the account activation. */
export function activationFailure(view: ErrorView): FormFailure {
  if (view.code === 'not-found' || (view.code === 'validation-failed' && 'activationToken' in view.fields)) {
    return { fields: {}, invalidLink: true };
  }
  switch (view.code) {
    case 'rate-limited':
      return rateLimited(view, 'adminAuth.login.locked');
    case 'validation-failed':
      return validation(view, { password: { field: 'password', key: 'adminAuth.password.rejected' } });
    default:
      return generic(view);
  }
}

/** Error of a second factor (login) or of a TOTP confirmation (enrollment). */
export function totpFailure(view: ErrorView, mode: 'login' | 'enroll'): FormFailure {
  switch (view.code) {
    case 'invalid-credentials': {
      const failure: FormFailure = {
        fields: { code: { key: mode === 'login' ? 'adminAuth.totp.invalid' : 'adminAuth.enroll.invalid' } },
      };
      if (view.attemptsRemaining !== undefined) {
        failure.attemptsRemaining = view.attemptsRemaining;
      }
      return failure;
    }
    case 'validation-failed':
      return { fields: { code: { key: 'adminAuth.totp.format' } } };
    case 'state-conflict':
      return mode === 'enroll'
        ? { general: { key: 'adminAuth.enroll.expired' }, fields: {}, enrollmentExpired: true }
        : generic(view);
    case 'rate-limited':
      return rateLimited(view, 'adminAuth.totp.locked');
    default:
      return generic(view);
  }
}

/** Action confirmed by the current password, which names its password field. */
export type CurrentPasswordContext = 'password' | 'reenroll' | 'disable';

/** Name of the current password field of each form of the account page. */
const CURRENT_PASSWORD_FIELD: Record<CurrentPasswordContext, string> = {
  password: 'current',
  reenroll: 'reenroll',
  disable: 'disable',
};

/**
 * Error of an action confirmed by the current password: password change, TOTP re-enrollment or
 * disabling. A 403 forbidden only means "two-factor authentication is required" when disabling
 * it; for the other actions it is shown as the server's own message.
 */
export function currentPasswordFailure(view: ErrorView, context: CurrentPasswordContext): FormFailure {
  const field = CURRENT_PASSWORD_FIELD[context];
  switch (view.code) {
    case 'invalid-credentials':
      return { fields: { [field]: { key: 'adminAuth.account.password.currentInvalid' } } };
    case 'forbidden':
      return context === 'disable'
        ? { general: { key: 'adminAuth.account.totp.disable.forbidden' }, fields: {} }
        : generic(view);
    case 'rate-limited':
      return rateLimited(view, 'adminAuth.login.locked');
    case 'validation-failed':
      return validation(view, {
        currentPassword: { field },
        newPassword: { field: 'password', key: 'adminAuth.password.rejected' },
      });
    default:
      return generic(view);
  }
}

// ---- Countdown -----------------------------------------------------------------------------

/** Clock time (epoch milliseconds) of the next allowed attempt. */
export function retryAt(retryAfterSeconds: number | undefined, now: number): number | undefined {
  return retryAfterSeconds === undefined || retryAfterSeconds <= 0
    ? undefined
    : now + retryAfterSeconds * 1000;
}

/** Whole seconds left before until (rounded up, never negative; 0 when until is undefined). */
export function secondsLeft(until: number | undefined, now: number): number {
  return until === undefined ? 0 : Math.max(0, Math.ceil((until - now) / 1000));
}

// ---- Recovery codes file -------------------------------------------------------------------

/** Text file of the recovery codes: a header line, a blank line, one code per line (LF). */
export function recoveryCodesText(codes: readonly string[], header: string): string {
  return `${header}\n\n${codes.join('\n')}\n`;
}

/** Message of the leave confirmation while the codes are not acknowledged (never the codes). */
export function recoveryLeaveMessage(t: (key: string) => string): string {
  return `${t('adminAuth.recovery.leaveConfirm.title')}\n\n${t('adminAuth.recovery.leaveConfirm.text')}`;
}

/** Text copied by "copy all": one code per line. */
export function recoveryCodesClipboard(codes: readonly string[]): string {
  return codes.join('\n');
}

/** Browser objects used to download a text file (injectable for tests). */
export interface DownloadEnvironment {
  createObjectURL(blob: Blob): string;
  revokeObjectURL(url: string): void;
  /** Clicks a temporary <a download> link to url. */
  clickLink(url: string, fileName: string): void;
  /** Runs fn later (the object URL is revoked once the download started). */
  defer(fn: () => void): void;
}

/**
 * Downloads text as a UTF-8 file: a Blob object URL, clicked through an <a download> link, then
 * revoked. The content never goes to the server, storage or the URL bar.
 */
export function downloadText(fileName: string, text: string, env: DownloadEnvironment): void {
  const url = env.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }));
  try {
    env.clickLink(url, fileName);
  } finally {
    env.defer(() => env.revokeObjectURL(url));
  }
}

/** Default download environment: URL, document and setTimeout of the browser. */
export function browserDownloadEnvironment(): DownloadEnvironment {
  return {
    createObjectURL: (blob) => URL.createObjectURL(blob),
    revokeObjectURL: (url) => URL.revokeObjectURL(url),
    clickLink(url, fileName) {
      const a = document.createElement('a');
      a.href = url;
      a.download = fileName;
      a.className = 'tt-hidden';
      document.body.appendChild(a);
      try {
        a.click();
      } finally {
        a.remove();
      }
    },
    defer: (fn) => {
      setTimeout(fn, 0);
    },
  };
}

// ---- Form display --------------------------------------------------------------------------

/**
 * General message to show: during a rate limit lock (lockRemaining defined), the lock message
 * with the live count of seconds, or of minutes (rounded up, key suffixed with "Minutes") from
 * one minute on, hidden once the lock is over; otherwise general unchanged.
 */
export function generalMessage(
  general: Message | undefined,
  lockRemaining: number | undefined,
): Message | undefined {
  if (lockRemaining === undefined || general === undefined) {
    return general;
  }
  if (lockRemaining <= 0) {
    return undefined;
  }
  if (!('key' in general)) {
    return general;
  }
  return lockRemaining >= 60
    ? { key: `${general.key}Minutes`, params: { ...general.params, count: Math.ceil(lockRemaining / 60) } }
    : { key: general.key, params: { ...general.params, count: lockRemaining } };
}

/** A field of a form, for the error summary. */
export interface SummaryField {
  /** Name of the field in FormErrors. */
  name: string;
  /** Id of the input to focus. */
  id: string;
  /** Visible label of the field. */
  label: string;
}

/** One entry of an error summary. */
export interface SummaryEntry {
  id: string;
  label: string;
  message: string;
}

/** Entries of the error summary of a form, in the order of its fields. */
export function summaryEntries(
  errors: FormErrors,
  fields: readonly SummaryField[],
  t: (key: string, params?: Record<string, string | number>) => string,
): SummaryEntry[] {
  const out: SummaryEntry[] = [];
  for (const field of fields) {
    const message = renderMessage(errors[field.name], t);
    if (message !== undefined) {
      out.push({ id: field.id, label: field.label, message });
    }
  }
  return out;
}
