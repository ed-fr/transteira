// The shared API client of the applications: browser fetch, current UI language and the
// in-memory CSRF store (updated from csrfToken members of the answers).
import { i18n } from '../i18n/i18n.svelte';
import { createApiClient, type ApiClient } from './client';
import { csrf } from './csrf.svelte';

/** Shared API client (/api/v1). */
export const api: ApiClient = createApiClient({
  fetch: (input, init) => globalThis.fetch(input, init),
  language: () => i18n.locale.current || 'en',
  csrfToken: () => csrf.current,
  onCsrfToken: (token) => csrf.set(token),
});
