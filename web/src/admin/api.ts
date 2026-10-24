// API client and session of the admin application. The client hooks are wired to the session:
// a 401 unauthenticated ends the session in the interface (back to the login screen with a
// return path), and a 403 csrf-invalid on an unsafe request reloads GET /admin/me, whose answer
// carries the current CSRF token (onCsrfToken), then retries the request once (T-165). The
// public application keeps the shared client without hooks.
import { createApiClient, type ApiClient } from '../shared/api/client';
import { csrf as sharedCsrf, type CsrfStore } from '../shared/api/csrf.svelte';
import { announce as sharedAnnounce } from '../shared/components/announce.svelte';
import { i18n, t as translate } from '../shared/i18n/i18n.svelte';
import { stripBase } from '../shared/router/router.svelte';
import { createAdminSession, type AdminSession } from './auth/session.svelte';

/** Base path of the admin application (same value as ADMIN_BASE of routes.ts). */
const BASE = '/admin';

/** Dependencies of the admin client and session. */
export interface AdminApiDeps {
  fetch: typeof fetch;
  language: () => string;
  csrf: CsrfStore;
  currentPath: () => string;
  announce?: (message: string) => void;
  t?: (key: string) => string;
  baseUrl?: string;
}

/** Creates the admin API client and its session, wired together. */
export function createAdminApi(deps: AdminApiDeps): { api: ApiClient; session: AdminSession } {
  // The hooks only run on an API answer, once the session below exists.
  // eslint-disable-next-line prefer-const
  let session: AdminSession;
  const api = createApiClient({
    fetch: deps.fetch,
    language: deps.language,
    csrfToken: () => deps.csrf.current,
    onCsrfToken: (token) => deps.csrf.set(token),
    onUnauthenticated: () => session.handleUnauthenticated(),
    recoverCsrf: () => session.recoverCsrf(),
    ...(deps.baseUrl === undefined ? {} : { baseUrl: deps.baseUrl }),
  });
  session = createAdminSession({
    api,
    csrf: deps.csrf,
    currentPath: deps.currentPath,
    ...(deps.announce === undefined ? {} : { announce: deps.announce }),
    ...(deps.t === undefined ? {} : { t: deps.t }),
  });
  return { api, session };
}

/** Application path and query string of the current page (window.location). */
export function locationPath(location: { pathname: string; search: string } | undefined): string {
  if (location === undefined) {
    return '/';
  }
  return (stripBase(BASE, location.pathname) ?? '/') + location.search;
}

const admin = createAdminApi({
  fetch: (input, init) => globalThis.fetch(input, init),
  language: () => i18n.locale.current || 'en',
  csrf: sharedCsrf,
  currentPath: () => locationPath(globalThis.location),
  announce: (message) => sharedAnnounce(message),
  t: (key) => translate(key),
});

/** API client of the admin application (hooks wired to adminSession). */
export const adminApi: ApiClient = admin.api;

/** Session of the admin application. */
export const adminSession: AdminSession = admin.session;
