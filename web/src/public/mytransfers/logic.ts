// Pure logic of the "My transfers" screen (CLAUDE.md section 8.7): access token fragment,
// durations offered for an extension, and classification of API errors. Unit tested.
import { ApiProblem } from '../../shared/api/client';
import type { components } from '../../shared/api/schema';

/** Transfer line of the list. */
export type MyTransfer = components['schemas']['MyTransfer'];

/** Transfer with its files and per-recipient tracking. */
export type MyTransferDetail = components['schemas']['MyTransferDetail'];

/** Downloads of one recipient. */
export type RecipientTracking = components['schemas']['RecipientTracking'];

/** Durations (days) a transfer can be extended to, ascending. */
export const EXTENSION_DAYS: readonly number[] = [1, 7, 30];

const DAY_MS = 24 * 60 * 60 * 1000;
const TOKEN_FRAGMENT = /^#?(mta_[A-Za-z0-9]{22,43})$/;

/** Extracts the access token from a location hash ("#mta_..."); undefined when there is none. */
export function parseAccessToken(hash: string): string | undefined {
  return TOKEN_FRAGMENT.exec(hash)?.[1];
}

/**
 * Tolerance on extendableTo: the server computes it from its own clock when it answers (now plus
 * the longest allowed duration), so the browser, rendering later and with its own clock, must
 * not drop that longest duration for a few seconds or minutes of difference. A duration beyond
 * the 90-day limit by less than this is refused by the server (extension-limit-reached).
 */
export const EXTENSION_TOLERANCE_MS = 60 * 60 * 1000;

/**
 * Durations offered to extend a transfer: those whose new expiry (now plus the duration) moves
 * the expiry forward and does not exceed extendableTo (within EXTENSION_TOLERANCE_MS). Empty
 * when the transfer cannot be extended (extendableTo absent) or when it is already as far as it
 * can go.
 */
export function extensionOptions(
  now: number,
  expiresAt: string | undefined,
  extendableTo: string | undefined,
  days: readonly number[] = EXTENSION_DAYS,
): number[] {
  if (extendableTo === undefined) {
    return [];
  }
  const limit = Date.parse(extendableTo);
  const current = expiresAt === undefined ? Number.NEGATIVE_INFINITY : Date.parse(expiresAt);
  if (Number.isNaN(limit)) {
    return [];
  }
  return days.filter((d) => {
    const target = now + d * DAY_MS;
    return target <= limit + EXTENSION_TOLERANCE_MS && (Number.isNaN(current) || target > current);
  });
}

/** Reports a 401 from the API: the session is over. */
export function isSessionExpired(err: unknown): boolean {
  return err instanceof ApiProblem && err.status === 401;
}

/** Outcome of a failed access link request. */
export type RequestFailure =
  | { kind: 'rate-limited'; retryAfterSeconds: number | undefined }
  | { kind: 'mail-unavailable' }
  | { kind: 'invalid-email' }
  | { kind: 'error' };

/** Classifies the error of POST /me/access-links. */
export function requestFailure(err: unknown): RequestFailure {
  if (err instanceof ApiProblem) {
    if (err.status === 429) {
      return { kind: 'rate-limited', retryAfterSeconds: err.retryAfterSeconds };
    }
    if (err.status === 503 && err.code === 'mail-unavailable') {
      return { kind: 'mail-unavailable' };
    }
    if (err.status === 400) {
      return { kind: 'invalid-email' };
    }
  }
  return { kind: 'error' };
}

/** Outcome of a failed POST /me/sessions. */
export type SessionStartFailure = 'invalid-link' | 'rate-limited' | 'error';

/** Classifies the error of POST /me/sessions (410 and 400: the link is not usable). */
export function sessionStartFailure(err: unknown): SessionStartFailure {
  if (err instanceof ApiProblem) {
    if (err.status === 410 || err.status === 400) {
      return 'invalid-link';
    }
    if (err.status === 429) {
      return 'rate-limited';
    }
  }
  return 'error';
}

/**
 * Keeps the access token read from the fragment until its exchange is settled, so that a retry
 * after a network error does not lose it (the fragment is removed from the address bar at once).
 * The token stays in memory only: it never goes back into the URL or into any storage.
 */
export class AccessTokenHolder {
  #token: string | undefined;

  /**
   * Returns the token of hash when there is one (it replaces the pending token), otherwise the
   * pending token, if any.
   */
  take(hash: string): string | undefined {
    const token = parseAccessToken(hash);
    if (token !== undefined) {
      this.#token = token;
    }
    return this.#token;
  }

  /** Forgets the pending token: its exchange succeeded, failed for good or was declined. */
  clear(): void {
    this.#token = undefined;
  }
}

/** Session of the API (MyTransfersSession), as far as the screen uses it. */
export interface SessionSummary {
  email: string;
  expiresAt: string;
}

/** API calls used to open an access link. */
export interface AccessLinkApi {
  /** GET /me/sessions/current: the active session; rejects without one. */
  current(): Promise<SessionSummary>;
  /** POST /me/sessions: exchanges the token for a session. */
  start(token: string): Promise<SessionSummary>;
}

/** Outcome of opening an access link. */
export type AccessLinkOutcome =
  | ({ kind: 'signed-in' } & SessionSummary)
  | ({ kind: 'confirm-switch' } & SessionSummary)
  | { kind: 'invalid-link' }
  | { kind: 'error' };

/**
 * Opens the access link token. When a session is already active and the switch is not confirmed
 * yet, it does not exchange the token but returns 'confirm-switch' with the active session: a
 * page opening /me#mta_... in the browser of a signed-in sender (login CSRF) must not replace
 * that session silently. Otherwise it exchanges the token: 'signed-in', 'invalid-link' (the link
 * is not usable: invalid, used, expired, or too many attempts) or 'error' (network or server
 * error: the exchange may be retried with the same token).
 */
export async function openAccessLink(
  api: AccessLinkApi,
  token: string,
  confirmed: boolean,
): Promise<AccessLinkOutcome> {
  if (!confirmed) {
    let active: SessionSummary | undefined;
    try {
      active = await api.current();
    } catch {
      // No session (or the check failed): nothing to replace, exchange the token.
    }
    if (active !== undefined) {
      return { kind: 'confirm-switch', email: active.email, expiresAt: active.expiresAt };
    }
  }
  try {
    const session = await api.start(token);
    return { kind: 'signed-in', email: session.email, expiresAt: session.expiresAt };
  } catch (err) {
    return sessionStartFailure(err) === 'error' ? { kind: 'error' } : { kind: 'invalid-link' };
  }
}

/** Outcome of a failed extension. */
export type ExtendFailure =
  | { kind: 'limit-reached' }
  | { kind: 'conflict' }
  | { kind: 'not-allowed'; allowed: number[] }
  | { kind: 'not-found' }
  | { kind: 'error' };

/** Classifies the error of POST /me/transfers/{id}/extension. */
export function extendFailure(err: unknown): ExtendFailure {
  if (!(err instanceof ApiProblem)) {
    return { kind: 'error' };
  }
  if (err.status === 409) {
    return err.code === 'extension-limit-reached' ? { kind: 'limit-reached' } : { kind: 'conflict' };
  }
  if (err.status === 400) {
    const field = err.errors?.find((e) => e.code === 'not-allowed');
    if (field !== undefined) {
      const allowed = (field.allowed ?? []).filter((v): v is number => typeof v === 'number');
      return { kind: 'not-allowed', allowed };
    }
  }
  if (err.status === 404) {
    return { kind: 'not-found' };
  }
  return { kind: 'error' };
}

/** Phase of the screen. */
export type Phase =
  | { kind: 'loading' }
  | { kind: 'request'; notice?: 'expired-session' | 'invalid-link' }
  | { kind: 'sent' }
  | { kind: 'confirm-switch'; email: string; expiresAt: string }
  | { kind: 'transfers'; email: string; expiresAt: string };

/** Phase to show after an API call failed: back to the form on 401, otherwise undefined. */
export function phaseAfterError(err: unknown): Phase | undefined {
  return isSessionExpired(err) ? { kind: 'request', notice: 'expired-session' } : undefined;
}

/** Translation key of the status of a transfer. */
export function statusKey(status: string): string {
  return status === 'scanning' ? 'myTransfers.status.scanning' : 'myTransfers.status.available';
}
