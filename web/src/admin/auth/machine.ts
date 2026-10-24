// Authentication state machine of the admin application (pure reducer, no I/O).
//
// The server keeps the intermediate login steps (second factor, mandatory TOTP enrollment) in a
// pre-auth session for 5 minutes, and GET /admin/me answers 401 during them: these steps only
// live in memory, and a reload goes back to the login screen.
//
//   loading        bootstrap (GET /admin/setup, then GET /admin/me), or a full session whose
//                  profile is being fetched
//   setup          first-run setup required (no admin yet)
//   anonymous      no session; optional flash message and return path
//   preauth        intermediate step: totp (code or recovery code), enroll (mandatory TOTP
//                  enrollment), unsupported (password_change_required or a status unknown to
//                  this version, for example V2 SSO); origin tells which flow started it
//   recovery       recovery codes shown once after a TOTP confirmation; the session is already
//                  full server side, the profile may arrive meanwhile
//   authenticated  full session with the admin profile
import type { components } from '../../shared/api/schema';

/** Profile of the authenticated admin (GET /admin/me). */
export type AdminMe = components['schemas']['AdminMe'];

/** New TOTP secret to confirm (setup, POST /admin/me/totp). */
export type TotpEnrollment = components['schemas']['TotpEnrollment'];

/** Flash message shown on the login screen (key admin.flash.<flash>). */
export type AuthFlash = 'sessionExpired' | 'stepExpired' | 'loggedOut';

/** Intermediate step of a pre-auth session. */
export type PreauthStep = 'totp' | 'enroll' | 'unsupported';

/** Flow that opened a pre-auth session. */
export type AuthOrigin = 'login' | 'setup' | 'activation';

/** State of the admin authentication. */
export type AuthState =
  | { kind: 'loading'; origin?: AuthOrigin }
  | { kind: 'setup' }
  | { kind: 'anonymous'; flash?: AuthFlash; next?: string }
  | { kind: 'preauth'; step: PreauthStep; origin: AuthOrigin; enrollment?: TotpEnrollment }
  | { kind: 'recovery'; codes: string[]; origin: AuthOrigin; me?: AdminMe }
  | { kind: 'authenticated'; me: AdminMe };

/** Events of the machine. */
export type AuthEvent =
  /** Answer of GET /admin/setup. */
  | { type: 'SETUP_STATUS'; setupRequired: boolean }
  /** Answer of GET /admin/me. */
  | { type: 'ME_OK'; me: AdminMe }
  /** GET /admin/me answered 401. */
  | { type: 'ME_401' }
  /** Answer of login, second factor or activation (LoginState.status, extensible). */
  | { type: 'LOGIN_STATE'; status: string; origin?: AuthOrigin }
  /** A TOTP secret to confirm (answer of the setup or of POST /admin/me/totp). */
  | { type: 'ENROLLMENT'; enrollment: TotpEnrollment; origin?: AuthOrigin }
  /** POST /admin/me/totp/confirm succeeded from a pre-auth session. */
  | { type: 'TOTP_CONFIRMED'; codes: string[] }
  /** The admin confirmed having saved the recovery codes. */
  | { type: 'CODES_ACK' }
  /** An API call answered 401 unauthenticated; path is the application path shown then. */
  | { type: 'UNAUTHENTICATED'; path?: string }
  /** Logged out. */
  | { type: 'LOGOUT' };

/** Initial state. */
export const initialAuthState: AuthState = { kind: 'loading' };

function originOf(state: AuthState, fallback: AuthOrigin): AuthOrigin {
  if (state.kind === 'preauth' || state.kind === 'recovery') {
    return state.origin;
  }
  return state.kind === 'loading' && state.origin !== undefined ? state.origin : fallback;
}

function preauth(step: PreauthStep, origin: AuthOrigin, enrollment?: TotpEnrollment): AuthState {
  return enrollment === undefined
    ? { kind: 'preauth', step, origin }
    : { kind: 'preauth', step, origin, enrollment };
}

/** Next state of the machine (pure; returns the same object when nothing changes). */
export function authReducer(state: AuthState, event: AuthEvent): AuthState {
  switch (event.type) {
    case 'SETUP_STATUS':
      if (event.setupRequired) {
        return { kind: 'setup' };
      }
      return state.kind === 'setup' ? { kind: 'anonymous' } : state;

    case 'ME_OK':
      if (state.kind === 'recovery') {
        return { ...state, me: event.me };
      }
      return { kind: 'authenticated', me: event.me };

    case 'ME_401':
      if (state.kind === 'loading') {
        return { kind: 'anonymous' };
      }
      return state.kind === 'authenticated' ? { kind: 'anonymous', flash: 'sessionExpired' } : state;

    case 'LOGIN_STATE': {
      const origin = event.origin ?? originOf(state, 'login');
      switch (event.status) {
        case 'totp_required':
          return preauth('totp', origin);
        case 'totp_enrollment_required':
          return preauth('enroll', origin);
        case 'authenticated':
          return { kind: 'loading', origin };
        default:
          return preauth('unsupported', origin);
      }
    }

    case 'ENROLLMENT':
      if (state.kind === 'authenticated' || state.kind === 'recovery') {
        return state;
      }
      return preauth(
        'enroll',
        event.origin ?? originOf(state, state.kind === 'setup' ? 'setup' : 'login'),
        event.enrollment,
      );

    case 'TOTP_CONFIRMED':
      return state.kind === 'preauth'
        ? { kind: 'recovery', codes: event.codes, origin: state.origin }
        : state;

    case 'CODES_ACK':
      if (state.kind !== 'recovery') {
        return state;
      }
      return state.me === undefined
        ? { kind: 'loading', origin: state.origin }
        : { kind: 'authenticated', me: state.me };

    case 'UNAUTHENTICATED':
      if (state.kind === 'authenticated' || state.kind === 'recovery') {
        return event.path === undefined
          ? { kind: 'anonymous', flash: 'sessionExpired' }
          : { kind: 'anonymous', flash: 'sessionExpired', next: event.path };
      }
      return state.kind === 'preauth' ? { kind: 'anonymous', flash: 'stepExpired' } : state;

    case 'LOGOUT':
      return { kind: 'anonymous', flash: 'loggedOut' };
  }
}

/** Profile of the admin when the state carries one. */
export function meOf(state: AuthState): AdminMe | undefined {
  return state.kind === 'authenticated' ? state.me : state.kind === 'recovery' ? state.me : undefined;
}
