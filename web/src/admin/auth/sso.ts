// Single sign-on (OpenID Connect) on the login page, pure logic: closed list of the error codes
// the callback puts in the query string, the https check on the provider URL and the mapping of
// the start errors. The query value is untrusted (anyone can craft a link to the login page):
// it only selects a translation from a closed list, it is never displayed itself.
import type { ErrorView } from '../../shared/api/problem';
import { isEmail } from '../../shared/validation/email';
import { type FieldError, type FormFailure } from './views';

/** Codes of `?error=` sent by the callback (completeAdminOidcLogin), the closed list. */
export const SSO_LOGIN_ERRORS = [
  'sso-mfa-required',
  'sso-not-available',
  'rate-limited',
  'invalid-credentials',
] as const;

/** An error code of the callback. */
export type SsoLoginError = (typeof SSO_LOGIN_ERRORS)[number];

/** Reports whether a value is one of the codes of the closed list. */
export function isSsoLoginError(value: string): value is SsoLoginError {
  return (SSO_LOGIN_ERRORS as readonly string[]).includes(value);
}

/**
 * Translation key of the message for the `error` parameter of a query string: undefined when
 * there is none, the message of the code when it is in the closed list, otherwise the generic
 * message (an unknown value is never echoed).
 */
export function ssoLoginErrorKey(search: string): string | undefined {
  const value = new URLSearchParams(search).get('error');
  if (value === null || value === '') {
    return undefined;
  }
  return isSsoLoginError(value) ? `adminAuth.sso.errors.${value}` : 'adminAuth.sso.errors.generic';
}

/**
 * Reports whether the provider URL may be navigated to: an absolute https URL without embedded
 * credentials. Anything else (javascript:, http:, relative, malformed) is refused.
 */
export function isSafeRedirectUrl(value: string): boolean {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  return url.protocol === 'https:' && url.username === '' && url.password === '' && url.hostname !== '';
}

/** Error of the e-mail address of the single sign-on form: required, then a plausible address. */
export function ssoEmailError(email: string): FieldError | undefined {
  const value = email.trim();
  if (value === '') {
    return { key: 'fieldErrors.required' };
  }
  return isEmail(value) ? undefined : { key: 'fieldErrors.invalid-email' };
}

/**
 * Error of POST /admin/auth/oidc/start. The unavailable answer is the same for an unknown
 * domain and a disabled configuration, and the message does not tell which.
 */
export function ssoStartFailure(view: ErrorView): FormFailure {
  switch (view.code) {
    case 'sso-not-available':
      return { general: { key: 'adminAuth.sso.errors.sso-not-available' }, fields: {} };
    case 'validation-failed':
      return { fields: { email: { key: 'fieldErrors.invalid-email' } } };
    case 'rate-limited':
      return view.retryAfterSeconds === undefined || view.retryAfterSeconds <= 0
        ? { general: { key: 'adminAuth.login.lockedNoDelay' }, fields: {} }
        : {
            general: { key: 'adminAuth.login.locked', params: { count: view.retryAfterSeconds } },
            fields: {},
            retryAfterSeconds: view.retryAfterSeconds,
          };
    default:
      return { general: { text: view.message }, fields: {} };
  }
}
