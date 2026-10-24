import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ErrorView } from '../../shared/api/problem';
import type { AdminMe, AuthState, TotpEnrollment } from './machine';
import {
  activationFailure,
  browserDownloadEnvironment,
  confirmPasswordError,
  currentPasswordError,
  currentPasswordFailure,
  downloadText,
  flowView,
  isValid,
  loginFailure,
  newPasswordError,
  normalizeRecoveryCode,
  normalizeTotpCode,
  recoveryCodeError,
  recoveryCodesClipboard,
  recoveryLeaveMessage,
  recoveryCodesText,
  renderMessage,
  retryAt,
  sameStep,
  secondsLeft,
  setupFailure,
  totpCodeError,
  totpFailure,
  validateLogin,
  validateNewPassword,
  validatePasswordChange,
  validateSetup,
  type DownloadEnvironment,
} from './views';

const enrollment: TotpEnrollment = {
  secret: 'JBSWY3DPEHPK3PXP',
  otpauthUri: 'otpauth://totp/x',
  qrCodePng: 'iVBO',
};
const me: AdminMe = {
  id: 'adm_1',
  username: 'superadmin',
  email: 'it-admin@example.com',
  role: 'super_admin',
  totpEnabled: true,
  tenants: [],
  csrfToken: 'c',
};

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

describe('flowView', () => {
  it('maps every state of the own flow', () => {
    expect(flowView({ kind: 'authenticated', me }, 'login')).toEqual({ kind: 'done' });
    expect(flowView({ kind: 'loading' }, 'login')).toEqual({ kind: 'loading' });
    expect(flowView({ kind: 'loading', origin: 'login' }, 'login')).toEqual({ kind: 'loading' });
    expect(flowView({ kind: 'anonymous' }, 'login')).toEqual({ kind: 'form' });
    expect(flowView({ kind: 'setup' }, 'setup')).toEqual({ kind: 'form' });
    expect(flowView({ kind: 'preauth', step: 'totp', origin: 'login' }, 'login')).toEqual({ kind: 'totp' });
    expect(flowView({ kind: 'preauth', step: 'enroll', origin: 'login' }, 'login')).toEqual({
      kind: 'enrollStart',
    });
    expect(flowView({ kind: 'preauth', step: 'enroll', origin: 'setup', enrollment }, 'setup')).toEqual({
      kind: 'enroll',
      enrollment,
    });
    expect(flowView({ kind: 'preauth', step: 'unsupported', origin: 'activation' }, 'activation')).toEqual({
      kind: 'unsupported',
    });
    expect(flowView({ kind: 'recovery', codes: ['a'], origin: 'setup' }, 'setup')).toEqual({
      kind: 'recovery',
      codes: ['a'],
      username: undefined,
    });
    expect(flowView({ kind: 'recovery', codes: ['a'], origin: 'setup', me }, 'setup')).toEqual({
      kind: 'recovery',
      codes: ['a'],
      username: 'superadmin',
    });
  });

  it('ignores the steps of another flow', () => {
    const states: AuthState[] = [
      { kind: 'loading', origin: 'setup' },
      { kind: 'preauth', step: 'totp', origin: 'setup' },
      { kind: 'recovery', codes: [], origin: 'activation' },
    ];
    for (const state of states) {
      expect(flowView(state, 'login')).toEqual({ kind: 'form' });
    }
  });

  it('compares steps by kind', () => {
    expect(sameStep({ kind: 'form' }, { kind: 'form' })).toBe(true);
    expect(sameStep({ kind: 'form' }, { kind: 'totp' })).toBe(false);
  });
});

describe('client-side checks', () => {
  it('checks a new password and its confirmation', () => {
    expect(newPasswordError('')).toEqual({ key: 'fieldErrors.required' });
    expect(newPasswordError('short')).toEqual({ key: 'adminAuth.password.tooShort' });
    expect(newPasswordError('a-long-passphrase')).toBeUndefined();
    // Counted in characters, not UTF-16 units.
    expect(newPasswordError('😀'.repeat(11))).toEqual({ key: 'adminAuth.password.tooShort' });
    expect(confirmPasswordError('abc', '')).toEqual({ key: 'fieldErrors.required' });
    expect(confirmPasswordError('abc', 'abd')).toEqual({ key: 'adminAuth.password.mismatch' });
    expect(confirmPasswordError('abc', 'abc')).toBeUndefined();
  });

  it('checks the setup form', () => {
    const ok = {
      username: 'superadmin',
      email: 'it-admin@example.com',
      password: 'a-long-passphrase',
      confirm: 'a-long-passphrase',
      setupToken: 'stp_x',
    };
    expect(isValid(validateSetup(ok))).toBe(true);
    expect(validateSetup({ username: '', email: '', password: '', confirm: '', setupToken: ' ' })).toEqual({
      username: { key: 'fieldErrors.required' },
      email: { key: 'fieldErrors.required' },
      password: { key: 'fieldErrors.required' },
      confirm: { key: 'fieldErrors.required' },
      setupToken: { key: 'fieldErrors.required' },
    });
    expect(validateSetup({ ...ok, username: 'Admin', email: 'nope', confirm: 'other-passphrase' })).toEqual({
      username: { key: 'fieldErrors.invalid-username' },
      email: { key: 'fieldErrors.invalid-email' },
      confirm: { key: 'adminAuth.password.mismatch' },
    });
  });

  it('checks the login, activation and password change forms', () => {
    expect(validateLogin(' ', '')).toEqual({
      username: { key: 'fieldErrors.required' },
      password: { key: 'fieldErrors.required' },
    });
    expect(isValid(validateLogin('admin', 'x'))).toBe(true);
    expect(validateNewPassword('a-long-passphrase', 'x')).toEqual({
      confirm: { key: 'adminAuth.password.mismatch' },
    });
    expect(validatePasswordChange('', 'a-long-passphrase', 'a-long-passphrase')).toEqual({
      current: { key: 'fieldErrors.required' },
    });
    expect(isValid(validatePasswordChange('old', 'a-long-passphrase', 'a-long-passphrase'))).toBe(true);
    expect(currentPasswordError('')).toEqual({ key: 'fieldErrors.required' });
    expect(currentPasswordError('x')).toBeUndefined();
    expect(isValid({ a: undefined })).toBe(true);
  });

  it('normalises and checks codes', () => {
    expect(normalizeTotpCode(' 123 456 ')).toBe('123456');
    expect(totpCodeError('')).toEqual({ key: 'fieldErrors.required' });
    expect(totpCodeError('12345')).toEqual({ key: 'adminAuth.totp.format' });
    expect(totpCodeError('123 456')).toBeUndefined();
    expect(normalizeRecoveryCode(' rc-1 ')).toBe('rc-1');
    expect(recoveryCodeError(' ')).toEqual({ key: 'fieldErrors.required' });
    expect(recoveryCodeError('x'.repeat(33))).toEqual({ key: 'fieldErrors.too-long' });
    expect(recoveryCodeError('rc-7KQ2-9XLM-4PZD')).toBeUndefined();
  });
});

describe('renderMessage', () => {
  it('translates keys and keeps texts', () => {
    const t = (key: string, params?: Record<string, string | number>) =>
      `${key}${JSON.stringify(params ?? {})}`;
    expect(renderMessage(undefined, t)).toBeUndefined();
    expect(renderMessage({ text: 'as is' }, t)).toBe('as is');
    expect(renderMessage({ key: 'k', params: { count: 2 } }, t)).toBe('k{"count":2}');
  });
});

describe('API errors', () => {
  it('maps the setup errors', () => {
    expect(setupFailure(view({ code: 'setup-token-invalid' }))).toEqual({
      fields: { setupToken: { key: 'adminAuth.setup.tokenInvalid' } },
    });
    expect(setupFailure(view({ code: 'setup-already-done' }))).toEqual({
      general: { key: 'adminAuth.setup.alreadyDone' },
      fields: {},
      redirect: 'login',
    });
    expect(setupFailure(view({ code: 'rate-limited', retryAfterSeconds: 30 }))).toEqual({
      general: { key: 'adminAuth.login.locked', params: { count: 30 } },
      fields: {},
      retryAfterSeconds: 30,
    });
    expect(setupFailure(view({ code: 'rate-limited' }))).toEqual({
      general: { key: 'adminAuth.login.lockedNoDelay' },
      fields: {},
    });
    expect(
      setupFailure(
        view({
          code: 'validation-failed',
          fields: {
            username: { code: 'invalid-username', message: 'bad username' },
            password: { code: 'invalid', message: 'bad' },
            other: { code: 'invalid', message: 'ignored' },
          },
        }),
      ),
    ).toEqual({
      fields: { username: { text: 'bad username' }, password: { key: 'adminAuth.password.rejected' } },
    });
    expect(
      setupFailure(view({ code: 'validation-failed', fields: { x: { code: 'invalid', message: 'm' } } })),
    ).toEqual({
      general: { text: 'server message' },
      fields: {},
    });
    expect(setupFailure(view({ code: 'internal-error' }))).toEqual({
      general: { text: 'server message' },
      fields: {},
    });
  });

  it('gives one generic login message whatever the credentials error', () => {
    const generic = { general: { key: 'adminAuth.login.invalid' }, fields: {} };
    expect(loginFailure(view({ code: 'invalid-credentials' }))).toEqual(generic);
    expect(loginFailure(view({ code: 'validation-failed' }))).toEqual(generic);
    expect(loginFailure(view({ code: 'rate-limited', retryAfterSeconds: 5 })).retryAfterSeconds).toBe(5);
    expect(loginFailure(view({}))).toEqual({ general: { text: 'server message' }, fields: {} });
  });

  it('maps the activation errors', () => {
    expect(activationFailure(view({ code: 'not-found' }))).toEqual({ fields: {}, invalidLink: true });
    expect(
      activationFailure(
        view({ code: 'validation-failed', fields: { activationToken: { code: 'invalid', message: 'm' } } }),
      ),
    ).toEqual({ fields: {}, invalidLink: true });
    expect(
      activationFailure(
        view({ code: 'validation-failed', fields: { password: { code: 'invalid', message: 'm' } } }),
      ),
    ).toEqual({ fields: { password: { key: 'adminAuth.password.rejected' } } });
    expect(activationFailure(view({ code: 'rate-limited', retryAfterSeconds: 2 })).retryAfterSeconds).toBe(2);
    expect(activationFailure(view({ code: 'csrf-invalid' }))).toEqual({
      general: { text: 'server message' },
      fields: {},
    });
  });

  it('maps the second factor and enrollment errors', () => {
    expect(totpFailure(view({ code: 'invalid-credentials', attemptsRemaining: 2 }), 'login')).toEqual({
      fields: { code: { key: 'adminAuth.totp.invalid' } },
      attemptsRemaining: 2,
    });
    expect(totpFailure(view({ code: 'invalid-credentials' }), 'enroll')).toEqual({
      fields: { code: { key: 'adminAuth.enroll.invalid' } },
    });
    expect(totpFailure(view({ code: 'validation-failed' }), 'login')).toEqual({
      fields: { code: { key: 'adminAuth.totp.format' } },
    });
    expect(totpFailure(view({ code: 'state-conflict' }), 'enroll')).toEqual({
      general: { key: 'adminAuth.enroll.expired' },
      fields: {},
      enrollmentExpired: true,
    });
    expect(totpFailure(view({ code: 'state-conflict' }), 'login')).toEqual({
      general: { text: 'server message' },
      fields: {},
    });
    expect(totpFailure(view({ code: 'rate-limited', retryAfterSeconds: 60 }), 'login')).toEqual({
      general: { key: 'adminAuth.totp.locked', params: { count: 60 } },
      fields: {},
      retryAfterSeconds: 60,
    });
    expect(totpFailure(view({ code: 'internal-error' }), 'enroll').general).toEqual({
      text: 'server message',
    });
  });

  it('maps the errors of actions confirmed by the current password', () => {
    expect(currentPasswordFailure(view({ code: 'invalid-credentials' }), 'password')).toEqual({
      fields: { current: { key: 'adminAuth.account.password.currentInvalid' } },
    });
    expect(currentPasswordFailure(view({ code: 'invalid-credentials' }), 'disable')).toEqual({
      fields: { disable: { key: 'adminAuth.account.password.currentInvalid' } },
    });
    expect(currentPasswordFailure(view({ code: 'invalid-credentials' }), 'reenroll')).toEqual({
      fields: { reenroll: { key: 'adminAuth.account.password.currentInvalid' } },
    });
    expect(currentPasswordFailure(view({ code: 'forbidden' }), 'disable')).toEqual({
      general: { key: 'adminAuth.account.totp.disable.forbidden' },
      fields: {},
    });
    // A 403 of another action is not "two-factor authentication is required".
    for (const context of ['password', 'reenroll'] as const) {
      expect(currentPasswordFailure(view({ code: 'forbidden' }), context).general).toEqual({
        text: 'server message',
      });
    }
    expect(
      currentPasswordFailure(view({ code: 'rate-limited', retryAfterSeconds: 9 }), 'password')
        .retryAfterSeconds,
    ).toBe(9);
    expect(
      currentPasswordFailure(
        view({
          code: 'validation-failed',
          fields: {
            currentPassword: { code: 'required', message: 'required' },
            newPassword: { code: 'invalid', message: 'm' },
          },
        }),
        'password',
      ),
    ).toEqual({
      fields: { current: { text: 'required' }, password: { key: 'adminAuth.password.rejected' } },
    });
    expect(currentPasswordFailure(view({ code: 'internal-error' }), 'password').general).toEqual({
      text: 'server message',
    });
  });
});

describe('countdown arithmetic', () => {
  it('computes the retry time and the seconds left', () => {
    expect(retryAt(undefined, 1000)).toBeUndefined();
    expect(retryAt(0, 1000)).toBeUndefined();
    expect(retryAt(3, 1000)).toBe(4000);
    expect(secondsLeft(undefined, 0)).toBe(0);
    expect(secondsLeft(4000, 1001)).toBe(3);
    expect(secondsLeft(4000, 5000)).toBe(0);
  });
});

describe('recovery codes file', () => {
  it('builds the text and the clipboard content', () => {
    expect(recoveryCodesText(['a', 'b'], 'Header')).toBe('Header\n\na\nb\n');
    expect(recoveryCodesClipboard(['a', 'b'])).toBe('a\nb');
  });

  it('builds the leave confirmation without any code', () => {
    expect(recoveryLeaveMessage((key) => `t:${key}`)).toBe(
      't:adminAuth.recovery.leaveConfirm.title\n\nt:adminAuth.recovery.leaveConfirm.text',
    );
  });

  it('downloads through an object URL revoked afterwards', async () => {
    const events: string[] = [];
    let deferred: (() => void) | undefined;
    let blob: Blob | undefined;
    const env: DownloadEnvironment = {
      createObjectURL: (b) => {
        blob = b;
        events.push('create');
        return 'blob:1';
      },
      revokeObjectURL: (url) => events.push(`revoke ${url}`),
      clickLink: (url, name) => events.push(`click ${url} ${name}`),
      defer: (fn) => {
        deferred = fn;
      },
    };
    downloadText('codes.txt', 'content', env);
    expect(events).toEqual(['create', 'click blob:1 codes.txt']);
    deferred?.();
    expect(events).toEqual(['create', 'click blob:1 codes.txt', 'revoke blob:1']);
    expect(blob?.type).toBe('text/plain;charset=utf-8');
    expect(await blob?.text()).toBe('content');
  });

  it('revokes the URL even when the click fails', () => {
    const revoked: string[] = [];
    const env: DownloadEnvironment = {
      createObjectURL: () => 'blob:2',
      revokeObjectURL: (url) => revoked.push(url),
      clickLink: () => {
        throw new Error('blocked');
      },
      defer: (fn) => fn(),
    };
    expect(() => downloadText('f.txt', 'x', env)).toThrow('blocked');
    expect(revoked).toEqual(['blob:2']);
  });
});

describe('browserDownloadEnvironment', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it('clicks a temporary download link and revokes later', () => {
    vi.useFakeTimers();
    const anchor = { href: '', download: '', className: '', click: vi.fn(), remove: vi.fn() };
    const appendChild = vi.fn();
    vi.stubGlobal('document', { createElement: vi.fn(() => anchor), body: { appendChild } });
    const createObjectURL = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:3');
    const revokeObjectURL = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
    downloadText('codes.txt', 'x', browserDownloadEnvironment());
    expect(createObjectURL).toHaveBeenCalledOnce();
    expect(appendChild).toHaveBeenCalledWith(anchor);
    expect(anchor).toMatchObject({ href: 'blob:3', download: 'codes.txt', className: 'tt-hidden' });
    expect(anchor.click).toHaveBeenCalledOnce();
    expect(anchor.remove).toHaveBeenCalledOnce();
    expect(revokeObjectURL).not.toHaveBeenCalled();
    vi.runAllTimers();
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:3');
    createObjectURL.mockRestore();
    revokeObjectURL.mockRestore();
  });
});
