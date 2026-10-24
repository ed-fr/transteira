import { afterEach, describe, expect, it, vi } from 'vitest';
import { createCsrfStore } from '../shared/api/csrf.svelte';
import { adminApi, adminSession, createAdminApi, locationPath } from './api';

function problem(status: number, code: string): Response {
  return new Response(JSON.stringify({ title: code, status, code }), {
    status,
    headers: { 'Content-Type': 'application/problem+json' },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('locationPath', () => {
  it('strips the base path and keeps the query string', () => {
    expect(locationPath({ pathname: '/admin/tenants/t1', search: '?a=1' })).toBe('/tenants/t1?a=1');
    expect(locationPath({ pathname: '/admin', search: '' })).toBe('/');
    expect(locationPath({ pathname: '/elsewhere', search: '' })).toBe('/');
    expect(locationPath(undefined)).toBe('/');
  });
});

describe('createAdminApi', () => {
  it('passes the base URL; a 401 during the bootstrap leaves the session loading', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async () => problem(401, 'unauthenticated'));
    const { api, session } = createAdminApi({
      fetch,
      language: () => 'fr',
      csrf: createCsrfStore(),
      currentPath: () => '/x',
      baseUrl: '/b',
    });
    await expect(api.request('GET', '/admin/me')).rejects.toMatchObject({ status: 401 });
    expect(String(fetch.mock.calls[0]?.[0])).toBe('/b/admin/me');
    expect(session.state.kind).toBe('loading');
  });
});

describe('shared admin client', () => {
  it('uses the browser fetch, location and announcer', async () => {
    const me = {
      id: 'a',
      username: 'u',
      email: 'u@example.com',
      role: 'super_admin',
      totpEnabled: true,
      tenants: [],
      csrfToken: 'c',
    };
    const responses = [
      new Response(JSON.stringify(me), { status: 200, headers: { 'Content-Type': 'application/json' } }),
      problem(401, 'unauthenticated'),
      new Response(null, { status: 204 }),
    ];
    const fetch = vi.fn(async () => responses.shift() as Response);
    vi.stubGlobal('fetch', fetch);
    vi.stubGlobal('location', { pathname: '/admin/account', search: '' });
    await adminSession.refreshMe();
    expect(adminSession.state.kind).toBe('authenticated');
    await expect(adminApi.request('GET', '/admin/tenants')).rejects.toMatchObject({ status: 401 });
    expect(adminSession.state).toEqual({ kind: 'anonymous', flash: 'sessionExpired', next: '/account' });
    await adminSession.logout();
    expect(adminSession.state).toEqual({ kind: 'anonymous', flash: 'loggedOut' });
    expect(fetch).toHaveBeenCalledTimes(3);
  });
});
