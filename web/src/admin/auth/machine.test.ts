import { describe, expect, it } from 'vitest';
import {
  authReducer,
  initialAuthState,
  meOf,
  type AdminMe,
  type AuthState,
  type TotpEnrollment,
} from './machine';

const me: AdminMe = {
  id: 'adm_1',
  username: 'superadmin',
  email: 'it-admin@example.com',
  role: 'super_admin',
  totpEnabled: true,
  tenants: [],
  csrfToken: 'csrf',
};
const enrollment: TotpEnrollment = {
  secret: 'JBSWY3DPEHPK3PXP',
  otpauthUri: 'otpauth://totp/x',
  qrCodePng: 'iVBO',
};

const loading: AuthState = { kind: 'loading' };
const setup: AuthState = { kind: 'setup' };
const anonymous: AuthState = { kind: 'anonymous' };
const authenticated: AuthState = { kind: 'authenticated', me };
const preTotp: AuthState = { kind: 'preauth', step: 'totp', origin: 'login' };
const preEnroll: AuthState = { kind: 'preauth', step: 'enroll', origin: 'activation' };
const recovery: AuthState = { kind: 'recovery', codes: ['a'], origin: 'setup' };

describe('authReducer', () => {
  it('starts loading', () => {
    expect(initialAuthState).toEqual({ kind: 'loading' });
  });

  describe('SETUP_STATUS', () => {
    it('goes to setup when required, from any state', () => {
      for (const s of [loading, anonymous, authenticated]) {
        expect(authReducer(s, { type: 'SETUP_STATUS', setupRequired: true })).toEqual(setup);
      }
    });
    it('leaves setup for anonymous, otherwise keeps the state', () => {
      expect(authReducer(setup, { type: 'SETUP_STATUS', setupRequired: false })).toEqual(anonymous);
      expect(authReducer(loading, { type: 'SETUP_STATUS', setupRequired: false })).toBe(loading);
    });
  });

  describe('ME_OK / ME_401', () => {
    it('authenticates, or stores the profile during the recovery codes', () => {
      for (const s of [loading, anonymous, preTotp, authenticated]) {
        expect(authReducer(s, { type: 'ME_OK', me })).toEqual(authenticated);
      }
      expect(authReducer(recovery, { type: 'ME_OK', me })).toEqual({ ...recovery, me });
    });
    it('maps a 401 by state', () => {
      expect(authReducer(loading, { type: 'ME_401' })).toEqual(anonymous);
      expect(authReducer({ kind: 'loading', origin: 'login' }, { type: 'ME_401' })).toEqual(anonymous);
      expect(authReducer(authenticated, { type: 'ME_401' })).toEqual({
        kind: 'anonymous',
        flash: 'sessionExpired',
      });
      for (const s of [setup, anonymous, preTotp, recovery]) {
        expect(authReducer(s, { type: 'ME_401' })).toBe(s);
      }
    });
  });

  describe('LOGIN_STATE', () => {
    it.each([
      ['totp_required', { kind: 'preauth', step: 'totp', origin: 'login' }],
      ['totp_enrollment_required', { kind: 'preauth', step: 'enroll', origin: 'login' }],
      ['authenticated', { kind: 'loading', origin: 'login' }],
      ['password_change_required', { kind: 'preauth', step: 'unsupported', origin: 'login' }],
      ['sso_redirect', { kind: 'preauth', step: 'unsupported', origin: 'login' }],
      ['', { kind: 'preauth', step: 'unsupported', origin: 'login' }],
    ])('maps %s', (status, expected) => {
      expect(authReducer(anonymous, { type: 'LOGIN_STATE', status, origin: 'login' })).toEqual(expected);
    });
    it('keeps the origin of the flow when the event has none', () => {
      expect(authReducer(preEnroll, { type: 'LOGIN_STATE', status: 'authenticated' })).toEqual({
        kind: 'loading',
        origin: 'activation',
      });
      expect(
        authReducer({ kind: 'loading', origin: 'setup' }, { type: 'LOGIN_STATE', status: 'totp_required' }),
      ).toEqual({
        kind: 'preauth',
        step: 'totp',
        origin: 'setup',
      });
      expect(authReducer(anonymous, { type: 'LOGIN_STATE', status: 'totp_required' })).toEqual(preTotp);
      expect(authReducer(loading, { type: 'LOGIN_STATE', status: 'totp_required' })).toEqual(preTotp);
    });
  });

  describe('ENROLLMENT', () => {
    it('opens the enrollment step with the secret', () => {
      expect(authReducer(setup, { type: 'ENROLLMENT', enrollment })).toEqual({
        kind: 'preauth',
        step: 'enroll',
        origin: 'setup',
        enrollment,
      });
      expect(authReducer(preEnroll, { type: 'ENROLLMENT', enrollment })).toEqual({
        ...preEnroll,
        enrollment,
      });
      expect(authReducer(anonymous, { type: 'ENROLLMENT', enrollment })).toEqual({
        kind: 'preauth',
        step: 'enroll',
        origin: 'login',
        enrollment,
      });
      expect(authReducer(anonymous, { type: 'ENROLLMENT', enrollment, origin: 'setup' })).toMatchObject({
        origin: 'setup',
      });
    });
    it('is ignored once authenticated or during the recovery codes', () => {
      expect(authReducer(authenticated, { type: 'ENROLLMENT', enrollment })).toBe(authenticated);
      expect(authReducer(recovery, { type: 'ENROLLMENT', enrollment })).toBe(recovery);
    });
  });

  describe('TOTP_CONFIRMED / CODES_ACK', () => {
    it('shows the codes after a pre-auth confirmation only', () => {
      expect(
        authReducer({ ...preEnroll, enrollment }, { type: 'TOTP_CONFIRMED', codes: ['x', 'y'] }),
      ).toEqual({
        kind: 'recovery',
        codes: ['x', 'y'],
        origin: 'activation',
      });
      expect(authReducer(authenticated, { type: 'TOTP_CONFIRMED', codes: ['x'] })).toBe(authenticated);
    });
    it('goes on to the application once the codes are acknowledged', () => {
      expect(authReducer({ ...recovery, me }, { type: 'CODES_ACK' })).toEqual(authenticated);
      expect(authReducer(recovery, { type: 'CODES_ACK' })).toEqual({ kind: 'loading', origin: 'setup' });
      expect(authReducer(anonymous, { type: 'CODES_ACK' })).toBe(anonymous);
    });
  });

  describe('UNAUTHENTICATED / LOGOUT', () => {
    it('expires a full session with a return path', () => {
      expect(authReducer(authenticated, { type: 'UNAUTHENTICATED', path: '/tenants?x=1' })).toEqual({
        kind: 'anonymous',
        flash: 'sessionExpired',
        next: '/tenants?x=1',
      });
      expect(authReducer(recovery, { type: 'UNAUTHENTICATED' })).toEqual({
        kind: 'anonymous',
        flash: 'sessionExpired',
      });
    });
    it('expires an intermediate step', () => {
      expect(authReducer(preTotp, { type: 'UNAUTHENTICATED', path: '/login' })).toEqual({
        kind: 'anonymous',
        flash: 'stepExpired',
      });
    });
    it('ignores it otherwise', () => {
      for (const s of [loading, setup, anonymous]) {
        expect(authReducer(s, { type: 'UNAUTHENTICATED', path: '/' })).toBe(s);
      }
    });
    it('logs out from any state', () => {
      for (const s of [authenticated, preTotp, recovery, anonymous]) {
        expect(authReducer(s, { type: 'LOGOUT' })).toEqual({ kind: 'anonymous', flash: 'loggedOut' });
      }
    });
  });
});

describe('meOf', () => {
  it('returns the profile when the state has one', () => {
    expect(meOf(authenticated)).toBe(me);
    expect(meOf({ ...recovery, me })).toBe(me);
    expect(meOf(recovery)).toBeUndefined();
    expect(meOf(anonymous)).toBeUndefined();
  });
});
