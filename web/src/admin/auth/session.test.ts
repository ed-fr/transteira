import { describe, expect, it, vi } from 'vitest';
import { createApiClient, NetworkError } from '../../shared/api/client';
import { createCsrfStore } from '../../shared/api/csrf.svelte';
import { createAdminApi } from '../api';
import type { AdminMe } from './machine';
import { createAdminSession } from './session.svelte';

const me: AdminMe = {
  id: 'adm_1',
  username: 'superadmin',
  email: 'it-admin@example.com',
  role: 'super_admin',
  totpEnabled: true,
  tenants: [],
  csrfToken: 'csrf-me',
};
const enrollment = {
  secret: 'S',
  otpauthUri: 'otpauth://totp/x',
  qrCodePng: 'iVBO',
  csrfToken: 'csrf-setup',
};

type Reply = Response | (() => Response) | Error;

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

function problem(status: number, code: string): Response {
  return new Response(JSON.stringify({ title: code, status, code }), {
    status,
    headers: { 'Content-Type': 'application/problem+json' },
  });
}

/** Fake server: queued replies per "METHOD /path". */
function harness(routes: Record<string, Reply[]>, path = '/tenants?a=1') {
  const calls: { key: string; init: RequestInit }[] = [];
  const fetch = vi.fn<typeof globalThis.fetch>(async (input, init) => {
    const key = `${init?.method} ${String(input).replace('/api/v1', '')}`;
    calls.push({ key, init: init as RequestInit });
    const reply = routes[key]?.shift();
    if (reply === undefined) {
      throw new Error(`unexpected ${key}`);
    }
    if (reply instanceof Error) {
      throw reply;
    }
    return typeof reply === 'function' ? reply() : reply;
  });
  const csrf = createCsrfStore();
  const announce = vi.fn();
  const currentPath = vi.fn(() => path);
  const { api, session } = createAdminApi({
    fetch,
    language: () => 'en',
    csrf,
    currentPath,
    announce,
    t: (key) => `t:${key}`,
  });
  return { api, session, csrf, calls, announce, currentPath };
}

describe('bootstrap', () => {
  it('goes to setup when required, without fetching the profile', async () => {
    const h = harness({ 'GET /admin/setup': [json(200, { setupRequired: true })] });
    expect(h.session.state).toEqual({ kind: 'loading' });
    await h.session.bootstrap();
    expect(h.session.state).toEqual({ kind: 'setup' });
    expect(h.calls).toHaveLength(1);
  });

  it('authenticates with the profile and stores its CSRF token', async () => {
    const h = harness({
      'GET /admin/setup': [json(200, { setupRequired: false })],
      'GET /admin/me': [json(200, me)],
    });
    await h.session.bootstrap();
    expect(h.session.state).toEqual({ kind: 'authenticated', me });
    expect(h.session.me).toEqual(me);
    expect(h.csrf.current).toBe('csrf-me');
    expect(h.session.error).toBeUndefined();
  });

  it('becomes anonymous on 401 without a flash', async () => {
    const h = harness({
      'GET /admin/setup': [json(200, { setupRequired: false })],
      'GET /admin/me': [problem(401, 'unauthenticated')],
    });
    await h.session.bootstrap();
    expect(h.session.state).toEqual({ kind: 'anonymous' });
  });

  it('keeps loading and exposes an unexpected error', async () => {
    const h = harness({ 'GET /admin/setup': [new TypeError('offline'), json(200, { setupRequired: true })] });
    await expect(h.session.bootstrap()).rejects.toBeInstanceOf(NetworkError);
    expect(h.session.state.kind).toBe('loading');
    expect(h.session.error).toBeInstanceOf(NetworkError);
    await h.session.bootstrap();
    expect(h.session.error).toBeUndefined();

    const failing = harness({
      'GET /admin/setup': [json(200, { setupRequired: false })],
      'GET /admin/me': [problem(500, 'internal-error')],
    });
    await expect(failing.session.bootstrap()).rejects.toMatchObject({ status: 500 });
  });
});

describe('setup flow', () => {
  it('creates the super admin, enrolls TOTP, shows the codes then authenticates', async () => {
    const h = harness({
      'GET /admin/setup': [json(200, { setupRequired: true })],
      'POST /admin/setup': [json(201, enrollment)],
      'POST /admin/me/totp/confirm': [json(200, { recoveryCodes: ['rc-1', 'rc-2'], csrfToken: 'csrf-full' })],
      'GET /admin/me': [json(200, me)],
    });
    await h.session.bootstrap();
    await h.session.setup({
      username: 'superadmin',
      email: 'it-admin@example.com',
      password: 'p',
      setupToken: 'stp',
    });
    expect(h.session.state).toEqual({ kind: 'preauth', step: 'enroll', origin: 'setup', enrollment });
    expect(h.csrf.current).toBe('csrf-setup');
    await h.session.confirmEnrollment('123456');
    expect(h.calls[2]?.init.body).toBe('{"code":"123456"}');
    expect(h.session.state).toEqual({ kind: 'recovery', codes: ['rc-1', 'rc-2'], origin: 'setup', me });
    await h.session.acknowledgeCodes();
    expect(h.session.state).toEqual({ kind: 'authenticated', me });
  });

  it('fetches the profile on acknowledgement when it could not be loaded before', async () => {
    const h = harness({
      'POST /admin/me/totp': [json(200, enrollment)],
      'POST /admin/me/totp/confirm': [json(200, { recoveryCodes: ['rc-1'] })],
      'GET /admin/me': [problem(500, 'internal-error'), json(200, me)],
    });
    h.session.dispatch({ type: 'LOGIN_STATE', status: 'totp_enrollment_required', origin: 'activation' });
    await h.session.startEnrollment();
    expect(h.calls[0]?.init.body).toBeNull();
    expect(h.session.state).toEqual({ kind: 'preauth', step: 'enroll', origin: 'activation', enrollment });
    await h.session.confirmEnrollment('000000');
    expect(h.session.state).toEqual({ kind: 'recovery', codes: ['rc-1'], origin: 'activation' });
    await h.session.acknowledgeCodes();
    expect(h.session.state).toEqual({ kind: 'authenticated', me });
  });

  it('acknowledging outside the recovery step does nothing', async () => {
    const h = harness({});
    await h.session.acknowledgeCodes();
    expect(h.session.state.kind).toBe('loading');
  });
});

describe('login flow', () => {
  it('asks the second factor then authenticates', async () => {
    const h = harness({
      'POST /admin/auth/login': [json(200, { status: 'totp_required', csrfToken: 'csrf-pre' })],
      'POST /admin/auth/totp': [json(200, { status: 'authenticated', csrfToken: 'csrf-full' })],
      'GET /admin/me': [json(200, me)],
    });
    h.session.dispatch({ type: 'ME_401' });
    await h.session.login({ username: 'a', password: 'b' });
    expect(h.session.state).toEqual({ kind: 'preauth', step: 'totp', origin: 'login' });
    expect(h.csrf.current).toBe('csrf-pre');
    await h.session.verifyTotp({ recoveryCode: 'rc-1' });
    expect(h.calls[1]?.init.body).toBe('{"recoveryCode":"rc-1"}');
    expect((h.calls[1]?.init.headers as Headers).get('X-CSRF-Token')).toBe('csrf-pre');
    expect(h.session.state).toEqual({ kind: 'authenticated', me });
  });

  it('rethrows invalid credentials without ending anything', async () => {
    const h = harness({ 'POST /admin/auth/login': [problem(401, 'invalid-credentials')] });
    h.session.dispatch({ type: 'ME_401' });
    await expect(h.session.login({ username: 'a', password: 'b' })).rejects.toMatchObject({
      code: 'invalid-credentials',
    });
    expect(h.session.state).toEqual({ kind: 'anonymous' });
  });

  it('shows the unsupported step for unknown statuses', async () => {
    const h = harness({
      'POST /admin/auth/login': [json(200, { status: 'password_change_required', csrfToken: 'c' })],
    });
    await h.session.login({ username: 'a', password: 'b' });
    expect(h.session.state).toEqual({ kind: 'preauth', step: 'unsupported', origin: 'login' });
  });

  it('activates an account', async () => {
    const h = harness({
      'POST /admin/activation': [
        json(200, { status: 'totp_enrollment_required', csrfToken: 'c' }),
        json(200, { status: 'authenticated', csrfToken: 'c' }),
      ],
      'GET /admin/me': [problem(401, 'unauthenticated')],
    });
    await h.session.activate({ activationToken: 'act_1', password: 'p' });
    expect(h.session.state).toEqual({ kind: 'preauth', step: 'enroll', origin: 'activation' });
    // A profile refused after an "authenticated" status: back to anonymous.
    await h.session.activate({ activationToken: 'act_1', password: 'p' });
    expect(h.session.state).toEqual({ kind: 'anonymous' });
  });
});

describe('profile fetch failure after an authentication', () => {
  it('keeps the fresh session, exposes the error and recovers with retry()', async () => {
    const h = harness({
      'POST /admin/auth/login': [json(200, { status: 'authenticated', csrfToken: 'csrf-full' })],
      'GET /admin/me': [new TypeError('offline'), problem(503, 'unavailable'), json(200, me)],
    });
    h.session.dispatch({ type: 'ME_401' });
    await expect(h.session.login({ username: 'a', password: 'b' })).rejects.toBeInstanceOf(NetworkError);
    expect(h.session.state).toEqual({ kind: 'loading', origin: 'login' });
    expect(h.session.error).toBeInstanceOf(NetworkError);
    expect(h.csrf.current).toBe('csrf-full');
    await expect(h.session.retry()).rejects.toMatchObject({ status: 503 });
    expect(h.session.error).toMatchObject({ status: 503 });
    await h.session.retry();
    expect(h.session.error).toBeUndefined();
    expect(h.session.state).toEqual({ kind: 'authenticated', me });
    // Only the profile was fetched again, never the setup status.
    expect(h.calls.map((c) => c.key)).not.toContain('GET /admin/setup');
  });

  it('goes back to anonymous when the retried profile is refused', async () => {
    const h = harness({
      'POST /admin/auth/totp': [json(200, { status: 'authenticated', csrfToken: 'csrf-full' })],
      'GET /admin/me': [problem(500, 'internal-error'), problem(401, 'unauthenticated')],
    });
    const onReset = vi.fn();
    h.session.onReset(onReset);
    h.session.dispatch({ type: 'LOGIN_STATE', status: 'totp_required', origin: 'login' });
    await expect(h.session.verifyTotp({ code: '123456' })).rejects.toMatchObject({ status: 500 });
    expect(h.session.error).toBeDefined();
    await h.session.retry();
    expect(h.session.state).toEqual({ kind: 'anonymous' });
    expect(h.session.error).toBeUndefined();
    expect(h.csrf.current).toBeUndefined();
    expect(onReset).toHaveBeenCalledTimes(1);
  });

  it('sets the error when the profile fails after the recovery codes', async () => {
    const h = harness({
      'POST /admin/me/totp/confirm': [json(200, { recoveryCodes: ['rc-1'] })],
      'GET /admin/me': [problem(500, 'internal-error'), problem(502, 'bad-gateway'), json(200, me)],
    });
    h.session.dispatch({ type: 'ENROLLMENT', enrollment, origin: 'setup' });
    await h.session.confirmEnrollment('000000');
    expect(h.session.error).toBeUndefined();
    await expect(h.session.acknowledgeCodes()).rejects.toMatchObject({ status: 502 });
    expect(h.session.state).toEqual({ kind: 'loading', origin: 'setup' });
    expect(h.session.error).toMatchObject({ status: 502 });
    await h.session.retry();
    expect(h.session.state).toEqual({ kind: 'authenticated', me });
  });

  it('clears a stale error when a new authentication starts', async () => {
    let errorDuringFetch: unknown = 'unset';
    const h = harness({
      'POST /admin/activation': [
        json(200, { status: 'authenticated', csrfToken: 'c' }),
        json(200, { status: 'authenticated', csrfToken: 'c' }),
      ],
      'GET /admin/me': [
        problem(500, 'internal-error'),
        () => {
          errorDuringFetch = h.session.error;
          return json(200, me);
        },
      ],
    });
    await expect(h.session.activate({ activationToken: 'act_1', password: 'p' })).rejects.toMatchObject({
      status: 500,
    });
    await h.session.activate({ activationToken: 'act_1', password: 'p' });
    expect(errorDuringFetch).toBeUndefined();
    expect(h.session.state).toEqual({ kind: 'authenticated', me });
  });

  it('runs the bootstrap again when no fresh session waits for its profile', async () => {
    const h = harness({
      'GET /admin/setup': [new TypeError('offline'), json(200, { setupRequired: true })],
    });
    await expect(h.session.bootstrap()).rejects.toBeInstanceOf(NetworkError);
    await h.session.retry();
    expect(h.session.state).toEqual({ kind: 'setup' });
    expect(h.session.error).toBeUndefined();
  });
});

describe('session expiry (onUnauthenticated)', () => {
  it('ends a full session with a return path and clears the memory', async () => {
    const h = harness({
      'GET /admin/me': [json(200, me)],
      'GET /admin/tenants': [problem(401, 'unauthenticated')],
    });
    const listener = vi.fn();
    const remove = h.session.onReset(listener);
    const other = vi.fn();
    h.session.onReset(other);
    await h.session.refreshMe();
    await expect(h.api.get('/admin/tenants')).rejects.toMatchObject({ status: 401 });
    expect(h.session.state).toEqual({ kind: 'anonymous', flash: 'sessionExpired', next: '/tenants?a=1' });
    expect(h.csrf.current).toBeUndefined();
    expect(listener).toHaveBeenCalledOnce();
    remove();
    h.session.dispatch({ type: 'ME_OK', me });
    h.session.handleUnauthenticated();
    expect(listener).toHaveBeenCalledOnce();
    expect(other).toHaveBeenCalledTimes(2);
  });

  it('expires an intermediate step', async () => {
    const h = harness({ 'POST /admin/auth/totp': [problem(401, 'unauthenticated')] });
    h.session.dispatch({ type: 'LOGIN_STATE', status: 'totp_required' });
    await expect(h.session.verifyTotp({ code: '123456' })).rejects.toMatchObject({ status: 401 });
    expect(h.session.state).toEqual({ kind: 'anonymous', flash: 'stepExpired' });
  });

  it('is ignored while loading, in setup or anonymous', () => {
    const h = harness({});
    h.session.handleUnauthenticated();
    expect(h.session.state).toEqual({ kind: 'loading' });
    h.session.dispatch({ type: 'SETUP_STATUS', setupRequired: true });
    h.session.handleUnauthenticated();
    expect(h.session.state).toEqual({ kind: 'setup' });
    expect(h.currentPath).not.toHaveBeenCalled();
  });

  it('a refreshed profile refused ends the session once', async () => {
    const h = harness({ 'GET /admin/me': [json(200, me), problem(401, 'unauthenticated')] });
    await h.session.refreshMe();
    expect(await h.session.refreshMe()).toBeUndefined();
    expect(h.session.state).toEqual({ kind: 'anonymous', flash: 'sessionExpired', next: '/tenants?a=1' });
  });
});

describe('logout', () => {
  it('revokes the session, clears the memory and announces it', async () => {
    const h = harness({
      'GET /admin/me': [json(200, me)],
      'POST /admin/auth/logout': [new Response(null, { status: 204 })],
    });
    const listener = vi.fn();
    h.session.onReset(listener);
    await h.session.refreshMe();
    await h.session.logout();
    expect((h.calls[1]?.init.headers as Headers).get('X-CSRF-Token')).toBe('csrf-me');
    expect(h.session.state).toEqual({ kind: 'anonymous', flash: 'loggedOut' });
    expect(h.csrf.current).toBeUndefined();
    expect(listener).toHaveBeenCalledOnce();
    expect(h.announce).toHaveBeenCalledWith('t:admin.flash.loggedOut');
  });

  it('treats a 401 as done, without a session expired message', async () => {
    const h = harness({
      'GET /admin/me': [json(200, me)],
      'POST /admin/auth/logout': [problem(401, 'unauthenticated')],
    });
    const listener = vi.fn();
    h.session.onReset(listener);
    await h.session.refreshMe();
    await h.session.logout();
    expect(h.session.state).toEqual({ kind: 'anonymous', flash: 'loggedOut' });
    expect(listener).toHaveBeenCalledOnce();
  });

  it('keeps the session when the server cannot be reached', async () => {
    const h = harness({
      'GET /admin/me': [json(200, me)],
      'POST /admin/auth/logout': [new TypeError('offline')],
    });
    await h.session.refreshMe();
    await expect(h.session.logout()).rejects.toBeInstanceOf(NetworkError);
    expect(h.session.state).toEqual({ kind: 'authenticated', me });
    expect(h.csrf.current).toBe('csrf-me');
    expect(h.announce).not.toHaveBeenCalled();
  });

  it('does not announce without announce or t', async () => {
    const csrf = createCsrfStore();
    const fetch = vi.fn<typeof globalThis.fetch>(async () => new Response(null, { status: 204 }));
    const api = createApiClient({ fetch, language: () => 'en', csrfToken: () => csrf.current });
    const session = createAdminSession({ api, csrf, currentPath: () => '/' });
    await session.logout();
    expect(session.state).toEqual({ kind: 'anonymous', flash: 'loggedOut' });
  });
});

describe('CSRF recovery', () => {
  it('reloads the profile and retries the request once', async () => {
    const h = harness({
      'GET /admin/me': [json(200, me), json(200, { ...me, csrfToken: 'csrf-rotated' })],
      'POST /admin/tenants': [problem(403, 'csrf-invalid'), json(201, { id: 't1' })],
    });
    await h.session.refreshMe();
    const res = await h.api.request('POST', '/admin/tenants', { body: { name: 'A' } });
    expect(res.status).toBe(201);
    expect(h.calls.map((c) => c.key)).toEqual([
      'GET /admin/me',
      'POST /admin/tenants',
      'GET /admin/me',
      'POST /admin/tenants',
    ]);
    expect((h.calls[3]?.init.headers as Headers).get('X-CSRF-Token')).toBe('csrf-rotated');
  });

  it('does not retry unless authenticated', async () => {
    const h = harness({ 'POST /admin/auth/login': [problem(403, 'csrf-invalid')] });
    await expect(h.session.login({ username: 'a', password: 'b' })).rejects.toMatchObject({
      code: 'csrf-invalid',
    });
    expect(h.calls).toHaveLength(1);
    expect(await h.session.recoverCsrf()).toBe(false);
  });

  it('answers false when the profile cannot be reloaded', async () => {
    const h = harness({
      'GET /admin/me': [json(200, me), problem(500, 'internal-error'), problem(401, 'unauthenticated')],
    });
    await h.session.refreshMe();
    expect(await h.session.recoverCsrf()).toBe(false);
    expect(await h.session.recoverCsrf()).toBe(false);
    expect(h.session.state.kind).toBe('anonymous');
  });

  it('answers false without a CSRF token', async () => {
    const csrf = createCsrfStore();
    const fetch = vi.fn<typeof globalThis.fetch>(async () => json(200, { ...me, csrfToken: '' }));
    const api = createApiClient({ fetch, language: () => 'en', csrfToken: () => csrf.current });
    const session = createAdminSession({ api, csrf, currentPath: () => '/' });
    await session.refreshMe();
    expect(await session.recoverCsrf()).toBe(false);
  });
});

describe('late profile answers (epoch)', () => {
  /** A session whose GET /admin/me answers when the test resolves it. */
  function deferred() {
    const csrf = createCsrfStore();
    const pending: ((res: Response | Error) => void)[] = [];
    const fetch = vi.fn<typeof globalThis.fetch>((input, init) => {
      if (String(input).endsWith('/admin/me')) {
        return new Promise<Response>((resolve, reject) => {
          pending.push((res) => (res instanceof Error ? reject(res) : resolve(res)));
        });
      }
      void init;
      return Promise.resolve(new Response(null, { status: 204 }));
    });
    const api = createApiClient({ fetch, language: () => 'en', csrfToken: () => csrf.current });
    const session = createAdminSession({ api, csrf, currentPath: () => '/' });
    return { session, csrf, answer: (res: Response | Error) => pending.shift()?.(res) };
  }

  it('ignores a profile that arrives after a logout', async () => {
    const d = deferred();
    d.session.dispatch({ type: 'ME_OK', me });
    const refresh = d.session.refreshMe();
    await d.session.logout();
    d.answer(json(200, { ...me, csrfToken: 'csrf-late' }));
    expect(await refresh).toBeUndefined();
    expect(d.session.state).toEqual({ kind: 'anonymous', flash: 'loggedOut' });
  });

  it('ignores a failure that arrives after the session ended', async () => {
    const d = deferred();
    d.session.dispatch({ type: 'ME_OK', me });
    const refresh = d.session.refreshMe();
    d.session.endLocally();
    d.answer(new TypeError('offline'));
    expect(await refresh).toBeUndefined();
    expect(d.session.state).toEqual({ kind: 'anonymous', flash: 'loggedOut' });
  });

  it('does not end a newer session when an older profile fetch of a fresh session ends late', async () => {
    const d = deferred();
    d.session.dispatch({ type: 'LOGIN_STATE', status: 'authenticated', origin: 'login' });
    const first = d.session.retry();
    d.session.endLocally();
    d.answer(problem(401, 'unauthenticated'));
    await first;
    expect(d.session.state).toEqual({ kind: 'anonymous', flash: 'loggedOut' });
  });
});

describe('endLocally', () => {
  it('goes back to anonymous and clears the CSRF token and the stores, without the server', async () => {
    const h = harness({ 'GET /admin/me': [json(200, me)] });
    const listener = vi.fn();
    h.session.onReset(listener);
    await h.session.refreshMe();
    h.session.endLocally();
    expect(h.session.state).toEqual({ kind: 'anonymous', flash: 'loggedOut' });
    expect(h.csrf.current).toBeUndefined();
    expect(listener).toHaveBeenCalledOnce();
    expect(h.calls).toHaveLength(1);
    expect(h.announce).not.toHaveBeenCalled();
  });
});
