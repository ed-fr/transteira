// Navigation guard of the admin application (pure): decides, from the authentication state and
// the access level of the route, whether a screen is rendered, redirected or reported as not
// found. Paths are application paths, without the /admin base path.
//
// - First-run setup required: every route goes to /setup.
// - /setup without setup: /login (or / when authenticated); it stays rendered while the setup
//   flow continues (TOTP enrollment, recovery codes).
// - Protected route while anonymous: /login?next=<path>. During an intermediate login step,
//   back to the screen of the flow that started it.
// - /login while authenticated: the return path (safeNext) or /.
// - Super admin route for another role, or a tenant outside the admin's scope: not found, like
//   the 404 of the server (threat model T-164 for the return path).
import type { AdminMe, AuthOrigin, AuthState } from './machine';

/** Access level of a route. */
export type RouteAccess = 'setup' | 'anonymous' | 'any' | 'auth' | 'super';

/** The navigation to check. */
export interface AccessRequest {
  /** Access level of the matched route. */
  access: RouteAccess;
  /** Application path (without the base path). */
  path: string;
  /** Decoded route parameters. */
  params: Record<string, string>;
  /** Query string, including "?" when present. */
  search?: string;
}

/** Decision of the guard. */
export type AccessDecision =
  | { kind: 'render' }
  | { kind: 'redirect'; to: string }
  | { kind: 'notFound' }
  /** Authentication state not known yet (bootstrap): show a loading indicator. */
  | { kind: 'pending' };

/** Routes of the authentication flows, never used as a return path. */
export const AUTH_ROUTES: readonly string[] = ['/login', '/setup', '/activate'];

const MAX_NEXT_LENGTH = 2048;

/** A "." or ".." path segment, possibly percent-encoded ("%2e", "%2E", ".%2e"...). */
const DOT_SEGMENT = /^(?:\.|%2e){1,2}$/i;

/** Tells whether the path part of value (before "?" or "#") has a "." or ".." segment. */
function hasDotSegment(value: string): boolean {
  const pathname = value.split(/[?#]/)[0] as string;
  return pathname.split('/').some((segment) => DOT_SEGMENT.test(segment));
}

/**
 * Returns next when it is a safe internal application path, otherwise "/". Refused: anything
 * that is not a string starting with a single "/", backslashes, control characters or spaces
 * (raw or percent-encoded), "." and ".." path segments (raw or percent-encoded, "%2e" in any
 * case: the browser would resolve them out of the intended path, possibly out of /admin),
 * overlong values and the authentication routes.
 */
export function safeNext(next: string | null | undefined): string {
  if (typeof next !== 'string' || next.length > MAX_NEXT_LENGTH) {
    return '/';
  }
  let decoded: string;
  try {
    decoded = decodeURIComponent(next);
  } catch {
    return '/';
  }
  for (const value of [next, decoded]) {
    if (
      !value.startsWith('/') ||
      value.startsWith('//') ||
      /[\\\s\u0000-\u001f\u007f]/.test(value) ||
      hasDotSegment(value)
    ) {
      return '/';
    }
  }
  const pathname = (next.split(/[?#]/)[0] as string).replace(/\/+$/, '') || '/';
  return AUTH_ROUTES.includes(pathname.toLowerCase()) ? '/' : next;
}

/** Safe return path read from the next parameter of a query string ("/" when absent). */
export function nextFromSearch(search: string | undefined): string {
  return safeNext(new URLSearchParams(search ?? '').get('next'));
}

/** Path of the login screen with a return path (omitted when it would be "/"). */
export function loginPath(next: string | undefined): string {
  const target = safeNext(next);
  return target === '/' ? '/login' : `/login?next=${encodeURIComponent(target)}`;
}

function flowPath(origin: AuthOrigin, next: string | undefined): string {
  switch (origin) {
    case 'setup':
      return '/setup';
    case 'activation':
      return '/activate';
    case 'login':
      return loginPath(next);
  }
}

function inScope(me: AdminMe, request: AccessRequest): boolean {
  const tenantId = request.params['id'];
  if (tenantId === undefined || !request.path.startsWith('/tenants/')) {
    return true;
  }
  return me.tenants.some((tenant) => tenant.id === tenantId);
}

/** Decides what to do with a navigation. */
export function resolveAccess(state: AuthState, request: AccessRequest): AccessDecision {
  const here = request.path + (request.search ?? '');
  const render: AccessDecision = { kind: 'render' };
  if (state.kind === 'loading') {
    return { kind: 'pending' };
  }
  if (state.kind === 'setup') {
    return request.access === 'setup' ? render : { kind: 'redirect', to: '/setup' };
  }
  const inFlow = state.kind === 'preauth' || state.kind === 'recovery';
  switch (request.access) {
    case 'setup':
      if (inFlow && state.origin === 'setup') {
        return render;
      }
      return { kind: 'redirect', to: state.kind === 'authenticated' ? '/' : '/login' };
    case 'any':
      return render;
    case 'anonymous':
      return state.kind === 'authenticated'
        ? { kind: 'redirect', to: nextFromSearch(request.search) }
        : render;
    case 'auth':
    case 'super':
      if (state.kind === 'anonymous') {
        return { kind: 'redirect', to: loginPath(here) };
      }
      if (inFlow) {
        return { kind: 'redirect', to: flowPath(state.origin, here) };
      }
      if (request.access === 'super' && state.me.role !== 'super_admin') {
        return { kind: 'notFound' };
      }
      return inScope(state.me, request) ? render : { kind: 'notFound' };
  }
}
