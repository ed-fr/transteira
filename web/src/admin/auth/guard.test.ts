import { describe, expect, it } from 'vitest';
import {
  loginPath,
  nextFromSearch,
  resolveAccess,
  safeNext,
  type AccessRequest,
  type RouteAccess,
} from './guard';
import type { AdminMe, AuthState } from './machine';

function admin(role: AdminMe['role'], tenantIds: string[]): AdminMe {
  return {
    id: 'adm_1',
    username: 'a',
    email: 'a@example.com',
    role,
    totpEnabled: true,
    tenants: tenantIds.map((id) => ({ id, name: id, fqdn: `${id}.example.com` })),
    csrfToken: 'c',
  };
}

const superAdmin: AuthState = { kind: 'authenticated', me: admin('super_admin', ['t1', 't2']) };
const delegated: AuthState = { kind: 'authenticated', me: admin('delegated_admin', ['t1']) };
const anonymous: AuthState = { kind: 'anonymous' };

function req(
  access: RouteAccess,
  path: string,
  params: Record<string, string> = {},
  search = '',
): AccessRequest {
  return { access, path, params, search };
}

describe('safeNext', () => {
  it.each([
    '/',
    '/tenants',
    '/tenants/t1/general?tab=2',
    '/admins/adm_1#x',
    '/login-help',
    '/tenants/%C3%A9',
    '/tenants/a.b',
    '/tenants/...',
    '/tenants?q=../x',
    '/tenants#../x',
  ])('accepts %s', (next) => {
    expect(safeNext(next)).toBe(next);
  });

  it.each([
    null,
    undefined,
    '',
    'tenants',
    'https://evil.example.com/',
    'javascript:alert(1)',
    '//evil.example.com',
    '/\\evil.example.com',
    '\\\\evil',
    '/%2F%2Fevil.example.com',
    '/%2fevil',
    '/%5Cevil',
    '/a b',
    '/a\tb',
    '/a\nb',
    '/%0Aevil',
    '/%E0%A4%A',
    '/login',
    '/login/',
    '/LOGIN?next=/x',
    '/setup',
    '/activate#act_x',
    `/${'a'.repeat(2048)}`,
    '/..',
    '/../setup',
    '/tenants/../../api',
    '/tenants/./x',
    '/tenants/.',
    '/tenants/..?a=1',
    '/%2e%2e/api',
    '/%2E%2E/api',
    '/.%2e/api',
    '/%2e./api',
    '/tenants/%2e',
    '/%252e%252e/api',
  ])('refuses %s', (next) => {
    expect(safeNext(next)).toBe('/');
  });
});

describe('nextFromSearch / loginPath', () => {
  it('reads a safe next parameter', () => {
    expect(nextFromSearch('?next=%2Ftenants%3Fa%3D1')).toBe('/tenants?a=1');
    expect(nextFromSearch('?next=https%3A%2F%2Fevil')).toBe('/');
    expect(nextFromSearch('')).toBe('/');
    expect(nextFromSearch(undefined)).toBe('/');
  });
  it('builds the login path', () => {
    expect(loginPath('/tenants?a=1')).toBe('/login?next=%2Ftenants%3Fa%3D1');
    expect(loginPath('/')).toBe('/login');
    expect(loginPath('//evil')).toBe('/login');
    expect(loginPath(undefined)).toBe('/login');
  });
});

describe('resolveAccess', () => {
  it('waits during the bootstrap', () => {
    expect(resolveAccess({ kind: 'loading' }, req('auth', '/'))).toEqual({ kind: 'pending' });
  });

  it('forces /setup while setup is required', () => {
    expect(resolveAccess({ kind: 'setup' }, req('setup', '/setup'))).toEqual({ kind: 'render' });
    for (const access of ['anonymous', 'any', 'auth', 'super'] as const) {
      expect(resolveAccess({ kind: 'setup' }, req(access, '/x'))).toEqual({ kind: 'redirect', to: '/setup' });
    }
  });

  it('handles /setup without setup', () => {
    expect(resolveAccess(anonymous, req('setup', '/setup'))).toEqual({ kind: 'redirect', to: '/login' });
    expect(resolveAccess(superAdmin, req('setup', '/setup'))).toEqual({ kind: 'redirect', to: '/' });
    expect(
      resolveAccess({ kind: 'preauth', step: 'enroll', origin: 'login' }, req('setup', '/setup')),
    ).toEqual({
      kind: 'redirect',
      to: '/login',
    });
    // The setup flow goes on on /setup.
    expect(
      resolveAccess({ kind: 'preauth', step: 'enroll', origin: 'setup' }, req('setup', '/setup')),
    ).toEqual({
      kind: 'render',
    });
    expect(resolveAccess({ kind: 'recovery', codes: [], origin: 'setup' }, req('setup', '/setup'))).toEqual({
      kind: 'render',
    });
  });

  it('always renders "any" routes outside setup', () => {
    for (const state of [
      anonymous,
      superAdmin,
      { kind: 'preauth', step: 'totp', origin: 'login' } as AuthState,
    ]) {
      expect(resolveAccess(state, req('any', '/activate'))).toEqual({ kind: 'render' });
    }
  });

  it('renders /login until authenticated, then goes to the return path', () => {
    expect(resolveAccess(anonymous, req('anonymous', '/login'))).toEqual({ kind: 'render' });
    expect(
      resolveAccess({ kind: 'preauth', step: 'totp', origin: 'login' }, req('anonymous', '/login')),
    ).toEqual({
      kind: 'render',
    });
    expect(
      resolveAccess({ kind: 'recovery', codes: [], origin: 'login' }, req('anonymous', '/login')),
    ).toEqual({
      kind: 'render',
    });
    expect(resolveAccess(superAdmin, req('anonymous', '/login', {}, '?next=%2Ftenants'))).toEqual({
      kind: 'redirect',
      to: '/tenants',
    });
    expect(resolveAccess(superAdmin, req('anonymous', '/login', {}, '?next=%2F%2Fevil'))).toEqual({
      kind: 'redirect',
      to: '/',
    });
    expect(resolveAccess(superAdmin, { access: 'anonymous', path: '/login', params: {} })).toEqual({
      kind: 'redirect',
      to: '/',
    });
  });

  it('sends anonymous visitors of protected routes to the login', () => {
    expect(resolveAccess(anonymous, req('auth', '/tenants/t1/smtp', { id: 't1' }, '?a=1'))).toEqual({
      kind: 'redirect',
      to: '/login?next=%2Ftenants%2Ft1%2Fsmtp%3Fa%3D1',
    });
    expect(resolveAccess(anonymous, req('super', '/'))).toEqual({ kind: 'redirect', to: '/login' });
    expect(resolveAccess(anonymous, { access: 'auth', path: '/account', params: {} })).toEqual({
      kind: 'redirect',
      to: '/login?next=%2Faccount',
    });
  });

  it('sends intermediate steps back to their flow', () => {
    expect(
      resolveAccess({ kind: 'preauth', step: 'totp', origin: 'login' }, req('auth', '/account')),
    ).toEqual({
      kind: 'redirect',
      to: '/login?next=%2Faccount',
    });
    expect(resolveAccess({ kind: 'preauth', step: 'enroll', origin: 'setup' }, req('auth', '/'))).toEqual({
      kind: 'redirect',
      to: '/setup',
    });
    expect(
      resolveAccess({ kind: 'recovery', codes: [], origin: 'activation' }, req('super', '/admins')),
    ).toEqual({
      kind: 'redirect',
      to: '/activate',
    });
  });

  it('reserves super routes to the super admin', () => {
    expect(resolveAccess(superAdmin, req('super', '/admins'))).toEqual({ kind: 'render' });
    expect(resolveAccess(delegated, req('super', '/admins'))).toEqual({ kind: 'notFound' });
    expect(resolveAccess(delegated, req('auth', '/admins/:id', { id: 'adm_9' }))).toEqual({ kind: 'render' });
  });

  it('limits tenant routes to the tenants of the admin', () => {
    expect(resolveAccess(delegated, req('auth', '/tenants/t1/general', { id: 't1' }))).toEqual({
      kind: 'render',
    });
    expect(resolveAccess(delegated, req('auth', '/tenants/t2/general', { id: 't2' }))).toEqual({
      kind: 'notFound',
    });
    expect(resolveAccess(superAdmin, req('auth', '/tenants/t2/general', { id: 't2' }))).toEqual({
      kind: 'render',
    });
    expect(resolveAccess(superAdmin, req('super', '/tenants/t3/general', { id: 't3' }))).toEqual({
      kind: 'notFound',
    });
    expect(resolveAccess(delegated, req('auth', '/tenants'))).toEqual({ kind: 'render' });
  });
});
