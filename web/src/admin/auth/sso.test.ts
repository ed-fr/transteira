import { describe, expect, it } from 'vitest';
import type { ErrorView } from '../../shared/api/problem';
import {
  SSO_LOGIN_ERRORS,
  isSafeRedirectUrl,
  isSsoLoginError,
  ssoEmailError,
  ssoLoginErrorKey,
  ssoStartFailure,
} from './sso';
import { loginFailure } from './views';

function view(partial: Partial<ErrorView>): ErrorView {
  return {
    code: undefined,
    status: undefined,
    message: 'server message',
    fields: {},
    attemptsRemaining: undefined,
    retryAfterSeconds: undefined,
    maxTransferBytes: undefined,
    files: undefined,
    ...partial,
  };
}

describe('ssoLoginErrorKey', () => {
  it('maps every code of the closed list to its own message', () => {
    for (const code of SSO_LOGIN_ERRORS) {
      expect(ssoLoginErrorKey(`?error=${code}`)).toBe(`adminAuth.sso.errors.${code}`);
    }
  });

  it('gives the generic message to an unknown value and never echoes it', () => {
    for (const raw of ['<script>alert(1)</script>', 'access_denied', '__proto__', 'SSO-MFA-REQUIRED']) {
      const key = ssoLoginErrorKey(`?error=${encodeURIComponent(raw)}`);
      expect(key).toBe('adminAuth.sso.errors.generic');
      expect(key).not.toContain(raw);
    }
  });

  it('shows nothing without an error parameter', () => {
    expect(ssoLoginErrorKey('')).toBeUndefined();
    expect(ssoLoginErrorKey('?next=%2Ftenants')).toBeUndefined();
    expect(ssoLoginErrorKey('?error=')).toBeUndefined();
  });

  it('recognises the codes of the list only', () => {
    expect(isSsoLoginError('rate-limited')).toBe(true);
    expect(isSsoLoginError('constructor')).toBe(false);
  });
});

describe('isSafeRedirectUrl', () => {
  it('accepts an https address of the provider', () => {
    expect(isSafeRedirectUrl('https://login.example.com/tenant/oauth2/v2.0/authorize?client_id=a')).toBe(
      true,
    );
  });

  it('refuses everything else', () => {
    for (const url of [
      'http://login.example.com/authorize',
      'javascript:alert(1)',
      'data:text/html,x',
      '//login.example.com/authorize',
      '/admin/login',
      'https://user:pass@login.example.com/',
      'https://',
      '',
      'not a url',
    ]) {
      expect(isSafeRedirectUrl(url), url).toBe(false);
    }
  });
});

describe('ssoEmailError', () => {
  it('requires a plausible address', () => {
    expect(ssoEmailError('  ')).toEqual({ key: 'fieldErrors.required' });
    expect(ssoEmailError('nobody')).toEqual({ key: 'fieldErrors.invalid-email' });
    expect(ssoEmailError(' admin@entity-a.example.com ')).toBeUndefined();
  });
});

describe('ssoStartFailure', () => {
  it('words the unavailable answer without telling why', () => {
    expect(ssoStartFailure(view({ code: 'sso-not-available' })).general).toEqual({
      key: 'adminAuth.sso.errors.sso-not-available',
    });
  });

  it('points a validation error at the e-mail field', () => {
    expect(ssoStartFailure(view({ code: 'validation-failed' })).fields).toEqual({
      email: { key: 'fieldErrors.invalid-email' },
    });
  });

  it('counts down a rate limit and falls back to the server message otherwise', () => {
    expect(ssoStartFailure(view({ code: 'rate-limited', retryAfterSeconds: 30 }))).toMatchObject({
      general: { key: 'adminAuth.login.locked', params: { count: 30 } },
      retryAfterSeconds: 30,
    });
    expect(ssoStartFailure(view({ code: 'rate-limited' })).general).toEqual({
      key: 'adminAuth.login.lockedNoDelay',
    });
    expect(ssoStartFailure(view({ code: 'internal-error' })).general).toEqual({ text: 'server message' });
  });
});

describe('password login refused by single sign-on', () => {
  it('steers the 403 sso-required answer to the single sign-on form', () => {
    expect(loginFailure(view({ code: 'sso-required', status: 403 })).general).toEqual({
      key: 'adminAuth.sso.passwordRefused',
    });
  });
});
