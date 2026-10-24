// Reactive admin session: wraps the pure state machine (machine.ts) with the API calls of the
// authentication flows. Reading `state` or `me` inside a component is reactive.
//
// - bootstrap: GET /admin/setup, then GET /admin/me (401 = anonymous).
// - setup, login, activate, verifyTotp, startEnrollment, confirmEnrollment: one API call each,
//   whose answer drives the machine; API errors are rethrown for the form to display.
//   A status "authenticated" fetches the profile. If that fetch fails (network, server), the
//   fresh session is kept: the state stays loading with `error` set, so that the application
//   shows its error page, whose retry() fetches the profile again (a 401 then goes back to
//   anonymous).
// - retry: after an error, fetches the profile again when a fresh session waits for it, or
//   runs the bootstrap again otherwise.
// - logout: POST /admin/auth/logout (a 401 means the session was already gone), then the CSRF
//   token and every in-memory store are cleared and the logout is announced. endLocally does
//   the same clearing without the server, when the logout call could not reach it.
// - Every end of a session (reset) starts a new epoch: a profile answer that arrives after the
//   session it was asked for has ended is ignored, so that it cannot bring back a closed session
//   or overwrite a newer one.
// - handleUnauthenticated (client hook): a full or pre-auth session expired; the machine goes
//   back to anonymous with a flash message, and the in-memory data is cleared (T-165).
// - recoverCsrf (client hook): reloads the profile, whose answer carries the current CSRF
//   token; only for a full session.
// Secrets of the flows (TOTP secret, recovery codes) only live in the state, in memory.
import { ApiProblem, type ApiClient } from '../../shared/api/client';
import type { CsrfStore } from '../../shared/api/csrf.svelte';
import type { components } from '../../shared/api/schema';
import {
  authReducer,
  initialAuthState,
  meOf,
  type AdminMe,
  type AuthEvent,
  type AuthOrigin,
  type AuthState,
} from './machine';

/** Body of the first-run setup. */
export type SetupRequest = components['schemas']['SetupRequest'];
/** Body of the first factor. */
export type LoginRequest = components['schemas']['LoginRequest'];
/** Body of an account activation. */
export type ActivationRequest = components['schemas']['ActivationRequest'];
/** Body of the second factor: a TOTP code or a recovery code. */
export type TotpCode = components['schemas']['TotpCode'];

/** Dependencies of a session. */
export interface AdminSessionDeps {
  /** The admin API client (its hooks call handleUnauthenticated and recoverCsrf). */
  api: ApiClient;
  /** In-memory CSRF store of the admin application. */
  csrf: CsrfStore;
  /** Current application path with its query string (return path after a session expiry). */
  currentPath: () => string;
  /** Polite announcement for screen readers. */
  announce?: (message: string) => void;
  /** Translation function. */
  t?: (key: string) => string;
}

/** The reactive admin session. */
export interface AdminSession {
  /** Current authentication state. */
  readonly state: AuthState;
  /** Profile of the admin, when known. */
  readonly me: AdminMe | undefined;
  /**
   * Error of the last bootstrap, or of the profile fetch that follows an authentication
   * (network, server); undefined otherwise. Only meaningful while the state is loading.
   */
  readonly error: unknown;
  /** Applies an event to the machine. */
  dispatch(event: AuthEvent): void;
  /** Bootstrap: setup status, then profile. Rejects (and sets error) on an unexpected error. */
  bootstrap(): Promise<void>;
  /**
   * Recovers from `error`: fetches the profile again when a fresh session waits for it (a 401
   * goes back to anonymous), runs the bootstrap again otherwise. Rejects (and sets error) on
   * an unexpected error.
   */
  retry(): Promise<void>;
  /** Reloads the profile (after a tenant change, for example). undefined on 401. */
  refreshMe(): Promise<AdminMe | undefined>;
  /** First-run setup: creates the super admin and opens the TOTP enrollment. */
  setup(body: SetupRequest): Promise<void>;
  /** First factor. */
  login(body: LoginRequest): Promise<void>;
  /** Account activation (password), then the step the server asks for. */
  activate(body: ActivationRequest): Promise<void>;
  /** Second factor (TOTP code or recovery code). */
  verifyTotp(body: TotpCode): Promise<void>;
  /** Starts the mandatory TOTP enrollment of a pre-auth session (no body). */
  startEnrollment(): Promise<void>;
  /** Confirms the pending TOTP secret; the recovery codes are then shown. */
  confirmEnrollment(code: string): Promise<void>;
  /** The admin saved the recovery codes: goes on to the authenticated application. */
  acknowledgeCodes(): Promise<void>;
  /** Logs out. Rejects (state unchanged) when the server could not be reached. */
  logout(): Promise<void>;
  /**
   * Ends the session locally only (after a failed logout): back to anonymous, CSRF token and
   * in-memory stores cleared. The server session expires on its own.
   */
  endLocally(): void;
  /** Registers a function called whenever the session ends; returns its removal. */
  onReset(listener: () => void): () => void;
  /** Client hook: an API call answered 401 unauthenticated. */
  handleUnauthenticated(): void;
  /** Client hook: refreshes the CSRF token after a 403 csrf-invalid. */
  recoverCsrf(): Promise<boolean>;
}

function isStatus(err: unknown, status: number): boolean {
  return err instanceof ApiProblem && err.status === status;
}

/** Creates an admin session. */
export function createAdminSession(deps: AdminSessionDeps): AdminSession {
  let state = $state.raw<AuthState>(initialAuthState);
  let error = $state.raw<unknown>(undefined);
  let resetListeners: (() => void)[] = [];
  let loggingOut = false;
  // Incremented by reset(): answers of an older epoch belong to a session that has ended.
  let epoch = 0;

  function dispatch(event: AuthEvent): void {
    state = authReducer(state, event);
  }

  function reset(): void {
    epoch += 1;
    deps.csrf.clear();
    for (const listener of resetListeners) {
      listener();
    }
  }

  /** Profile fetch; undefined on 401, or when the session ended while it was in flight. */
  async function refreshMe(): Promise<AdminMe | undefined> {
    const asked = epoch;
    try {
      const res = await deps.api.get('/admin/me');
      if (asked !== epoch) {
        return undefined;
      }
      dispatch({ type: 'ME_OK', me: res.data });
      return res.data;
    } catch (err) {
      if (asked !== epoch) {
        return undefined;
      }
      if (isStatus(err, 401)) {
        dispatch({ type: 'ME_401' });
        return undefined;
      }
      throw err;
    }
  }

  async function bootstrap(): Promise<void> {
    error = undefined;
    try {
      const setup = await deps.api.get('/admin/setup');
      dispatch({ type: 'SETUP_STATUS', setupRequired: setup.data.setupRequired });
      if (!setup.data.setupRequired) {
        await refreshMe();
      }
    } catch (err) {
      error = err;
      throw err;
    }
  }

  /** Profile of a fresh full session; a failure keeps the session and sets error. */
  async function profileAfterAuth(): Promise<void> {
    error = undefined;
    const asked = epoch;
    try {
      if ((await refreshMe()) === undefined && asked === epoch) {
        // The fresh session is already gone: nothing of it may stay in memory.
        reset();
      }
    } catch (err) {
      error = err;
      throw err;
    }
  }

  async function retry(): Promise<void> {
    // A loading state with an origin is a fresh session waiting for its profile.
    if (state.kind === 'loading' && state.origin !== undefined) {
      await profileAfterAuth();
      return;
    }
    await bootstrap();
  }

  async function loginState(status: string, origin?: AuthOrigin): Promise<void> {
    dispatch(
      origin === undefined ? { type: 'LOGIN_STATE', status } : { type: 'LOGIN_STATE', status, origin },
    );
    if (state.kind === 'loading') {
      await profileAfterAuth();
    }
  }

  function endLocally(): void {
    dispatch({ type: 'LOGOUT' });
    reset();
  }

  function handleUnauthenticated(): void {
    if (
      loggingOut ||
      (state.kind !== 'authenticated' && state.kind !== 'preauth' && state.kind !== 'recovery')
    ) {
      return;
    }
    dispatch({ type: 'UNAUTHENTICATED', path: deps.currentPath() });
    reset();
  }

  return {
    get state() {
      return state;
    },
    get me() {
      return meOf(state);
    },
    get error() {
      return error;
    },
    dispatch,
    bootstrap,
    retry,
    refreshMe,
    async setup(body) {
      const res = await deps.api.post('/admin/setup', { body });
      dispatch({ type: 'ENROLLMENT', enrollment: res.data, origin: 'setup' });
    },
    async login(body) {
      const res = await deps.api.post('/admin/auth/login', { body });
      await loginState(res.data.status, 'login');
    },
    async activate(body) {
      const res = await deps.api.post('/admin/activation', { body });
      await loginState(res.data.status, 'activation');
    },
    async verifyTotp(body) {
      const res = await deps.api.post('/admin/auth/totp', { body });
      await loginState(res.data.status);
    },
    async startEnrollment() {
      const res = await deps.api.post('/admin/me/totp');
      dispatch({ type: 'ENROLLMENT', enrollment: res.data });
    },
    async confirmEnrollment(code) {
      const res = await deps.api.post('/admin/me/totp/confirm', { body: { code } });
      dispatch({ type: 'TOTP_CONFIRMED', codes: res.data.recoveryCodes });
      // The profile arrives while the codes are shown; a failure is retried on acknowledgement.
      await refreshMe().catch(() => undefined);
    },
    async acknowledgeCodes() {
      if (state.kind !== 'recovery') {
        return;
      }
      dispatch({ type: 'CODES_ACK' });
      // Without the profile yet, the machine waits for it (TypeScript keeps the old narrowing).
      if ((state as AuthState).kind === 'loading') {
        await profileAfterAuth();
      }
    },
    async logout() {
      loggingOut = true;
      try {
        await deps.api.post('/admin/auth/logout');
      } catch (err) {
        if (!isStatus(err, 401)) {
          throw err;
        }
      } finally {
        loggingOut = false;
      }
      endLocally();
      if (deps.announce !== undefined && deps.t !== undefined) {
        deps.announce(deps.t('admin.flash.loggedOut'));
      }
    },
    endLocally,
    onReset(listener) {
      resetListeners = [...resetListeners, listener];
      return () => {
        resetListeners = resetListeners.filter((l) => l !== listener);
      };
    },
    handleUnauthenticated,
    async recoverCsrf() {
      if (state.kind !== 'authenticated') {
        return false;
      }
      try {
        await refreshMe();
      } catch {
        return false;
      }
      return state.kind === 'authenticated' && deps.csrf.current !== undefined;
    },
  };
}
