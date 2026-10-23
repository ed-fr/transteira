import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from './api';
import { createCsrfStore, csrf } from './csrf.svelte';
import { setLocale } from '../i18n/i18n.svelte';

describe('csrf store', () => {
  it('holds, replaces and clears the token in memory', () => {
    const store = createCsrfStore();
    expect(store.current).toBeUndefined();
    store.set('a');
    expect(store.current).toBe('a');
    store.set('');
    expect(store.current).toBeUndefined();
    store.set('b');
    store.clear();
    expect(store.current).toBeUndefined();
    store.set('c');
    store.set(undefined);
    expect(store.current).toBeUndefined();
  });
});

describe('shared api client', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    csrf.clear();
  });

  it('uses the current language, the shared CSRF store and stores returned tokens', async () => {
    const fetch = vi.fn(
      async () =>
        new Response(JSON.stringify({ csrfToken: 'fresh' }), {
          headers: { 'Content-Type': 'application/json' },
        }),
    );
    vi.stubGlobal('fetch', fetch);
    const before = await api.request('GET', '/deposit-sessions/current');
    expect(before.status).toBe(200);
    let headers = (fetch.mock.calls[0] as unknown as [string, RequestInit])[1].headers as Headers;
    expect(headers.get('Accept-Language')).toBe('en');
    expect(csrf.current).toBe('fresh');

    await setLocale('fr');
    await api.request('POST', '/x');
    headers = (fetch.mock.calls[1] as unknown as [string, RequestInit])[1].headers as Headers;
    expect(headers.get('Accept-Language')).toBe('fr');
    expect(headers.get('X-CSRF-Token')).toBe('fresh');
  });
});
