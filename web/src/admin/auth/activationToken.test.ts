import { afterEach, describe, expect, it, vi } from 'vitest';
import { createRouter, type Route, type RouterEnv } from '../../shared/router/router.svelte';
import { captureActivationToken, takeActivationToken, type ActivationCaptureEnv } from './activationToken';

const TOKEN = 'act_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v';
const ACTIVATE = '/admin/activate';

function fakeEnv(pathname: string, hash: string, search = '') {
  const location = { pathname, search, hash };
  const history = {
    state: { kept: true },
    replaceState: vi.fn((_state: unknown, _unused: string, url?: string | URL | null) => {
      const next = String(url);
      const at = next.indexOf('?');
      location.pathname = at === -1 ? next : next.slice(0, at);
      location.search = at === -1 ? '' : next.slice(at);
      location.hash = '';
    }),
  };
  return { env: { location, history } satisfies ActivationCaptureEnv, location, history };
}

afterEach(() => {
  takeActivationToken();
});

describe('captureActivationToken', () => {
  it('keeps the token once and removes the fragment right away', () => {
    const fake = fakeEnv(ACTIVATE, `#${TOKEN}`, '?lang=fr');
    captureActivationToken(fake.env, ACTIVATE);
    expect(fake.history.replaceState).toHaveBeenCalledWith({ kept: true }, '', `${ACTIVATE}?lang=fr`);
    expect(fake.location.hash).toBe('');
    expect(takeActivationToken()).toBe(TOKEN);
    expect(takeActivationToken()).toBeNull();
  });

  it('accepts a trailing slash on the activation path', () => {
    const fake = fakeEnv(`${ACTIVATE}/`, `#${TOKEN}`);
    captureActivationToken(fake.env, ACTIVATE);
    expect(fake.location.hash).toBe('');
    expect(takeActivationToken()).toBe(TOKEN);
  });

  it('removes a malformed fragment without keeping anything', () => {
    const fake = fakeEnv(ACTIVATE, '#act_short');
    captureActivationToken(fake.env, ACTIVATE);
    expect(fake.history.replaceState).toHaveBeenCalledOnce();
    expect(fake.location.hash).toBe('');
    expect(takeActivationToken()).toBeNull();
  });

  it('leaves other pages and an empty fragment untouched', () => {
    const other = fakeEnv('/admin/tenants', `#${TOKEN}`);
    captureActivationToken(other.env, ACTIVATE);
    expect(other.history.replaceState).not.toHaveBeenCalled();
    expect(other.location.hash).toBe(`#${TOKEN}`);

    const empty = fakeEnv(ACTIVATE, '');
    captureActivationToken(empty.env, ACTIVATE);
    expect(empty.history.replaceState).not.toHaveBeenCalled();
    expect(takeActivationToken()).toBeNull();
  });

  it('runs before the router, whose current location never holds the token', () => {
    const fake = fakeEnv(ACTIVATE, `#${TOKEN}`);
    captureActivationToken(fake.env, ACTIVATE);
    const activate: Route<string> = { pattern: '/activate', component: 'Activate', titleKey: 'x' };
    const env: RouterEnv = {
      location: fake.location,
      history: { pushState: vi.fn(), replaceState: vi.fn() },
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    };
    const router = createRouter({
      routes: [activate],
      notFound: activate,
      base: '/admin',
      env,
      t: (key) => key,
      afterRender: () => Promise.resolve(),
    });
    expect(router.current.path).toBe('/activate');
    expect(router.current.hash).toBe('');
    expect(takeActivationToken()).toBe(TOKEN);
  });
});
