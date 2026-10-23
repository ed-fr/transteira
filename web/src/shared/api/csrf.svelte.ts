// In-memory CSRF token store (threat model T-160). The token is never written to storage:
// after a reload it is obtained again from GET /deposit-sessions/current (public app) or
// GET /admin/me (admin app), whose answers carry it.

/** CSRF token holder. Reading `current` inside a component is reactive. */
export interface CsrfStore {
  /** Current token, undefined when none is known. */
  readonly current: string | undefined;
  /** Replaces the token (undefined or empty clears it). */
  set(token: string | undefined): void;
  /** Forgets the token (session ended or expired). */
  clear(): void;
}

/** Creates an independent store (tests, or one per application). */
export function createCsrfStore(): CsrfStore {
  let token = $state<string | undefined>(undefined);
  return {
    get current() {
      return token;
    },
    set(value) {
      token = value === '' ? undefined : value;
    },
    clear() {
      token = undefined;
    },
  };
}

/** The shared store of the application. */
export const csrf: CsrfStore = createCsrfStore();
