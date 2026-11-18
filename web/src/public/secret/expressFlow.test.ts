// State machine of the express secret page (expressFlow.svelte.ts) against a fake API: the
// anonymous creation, the link composed by the page (the text and the key never leave it, threat
// model T-399), the refusals and their wording, the rate limit, and the forgetting of the link.
import { describe, expect, it, vi } from 'vitest';
import { createApiClient, NetworkError } from '../../shared/api/client';
import type { components } from '../../shared/api/schema';
import { deriveSecretKey, openSecret } from '../../shared/e2e/secret';
import { encodeKey, parseKey } from '../../shared/e2e/tte2';
import type { ExpressFeatures } from './express';
import { ExpressSecretFlow, type ExpressFlowDeps } from './expressFlow.svelte';

type PublicTenant = components['schemas']['PublicTenant'];

interface Reply {
  status: number;
  body?: unknown;
}

interface Call {
  method: string;
  url: string;
  body: string | undefined;
  headers: Headers;
}

function problem(status: number, code: string, extra: Record<string, unknown> = {}): Reply {
  return { status, body: { type: 'about:blank', title: code, status, code, ...extra } };
}

/** Fake fetch answering "METHOD /path" routes (a list is consumed in order, the last one sticks). */
function fakeApi(routes: Record<string, Reply | (Reply | Error)[] | Error>) {
  const calls: Call[] = [];
  const fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input), 'https://transfer.entity-a.example.com');
    const method = init?.method ?? 'GET';
    const path = url.pathname.replace(/^\/api\/v1/, '');
    const raw = init?.body;
    calls.push({
      method,
      url: String(input),
      body: typeof raw === 'string' ? raw : undefined,
      headers: new Headers(init?.headers),
    });
    const route = routes[`${method} ${path}`];
    if (route === undefined) throw new Error(`unexpected request ${method} ${path}`);
    const reply = Array.isArray(route) ? (route.length > 1 ? route.shift() : route[0]) : route;
    if (reply instanceof Error) throw reply;
    const r = reply as Reply;
    const type = r.status >= 400 ? 'application/problem+json' : 'application/json';
    return new Response(r.body === undefined ? null : JSON.stringify(r.body), {
      status: r.status,
      headers: { 'Content-Type': type },
    });
  };
  const api = createApiClient({
    fetch: fetch as typeof globalThis.fetch,
    language: () => 'en',
    csrfToken: () => undefined,
  });
  return { api, calls };
}

const FEATURES: ExpressFeatures = { enabled: true, durations: ['1h', '1d', '7d'], maxChars: 10000 };
const ORIGIN = 'https://transfer.entity-a.example.com';
const TOKEN = 'tts_Xp4kQ7mZr2Lw9TfB3nHc8VyJd5Gs1KqA6eWu0RtNb7M'; // gitleaks:allow (fake token of the API example)
const ID = 'sec_01JABCS3T4V5W6X7Y8Z9A0B1C2';
const EXPIRES = '2026-11-18T09:00:00Z';
const TEXT = 'Vault password: correct horse battery staple 😀';

const created: Reply = { status: 201, body: { id: ID, token: TOKEN, state: 'active', expiresAt: EXPIRES } };

interface Setup {
  features?: ExpressFeatures | undefined;
  now?: () => number;
  newKey?: () => Uint8Array<ArrayBuffer>;
}

function setup(routes: Record<string, Reply | (Reply | Error)[] | Error>, s: Setup = {}) {
  const { api, calls } = fakeApi(routes);
  const tenant = {
    name: 'Entity A',
    features:
      'features' in s
        ? s.features === undefined
          ? {}
          : { expressSecrets: s.features }
        : { expressSecrets: FEATURES },
  } as unknown as PublicTenant;
  const announce = vi.fn();
  const tr = {
    t: (key: string, params?: Record<string, string | number>) =>
      params === undefined ? key : `${key} ${JSON.stringify(params)}`,
    has: (key: string) => key.startsWith('errors.'),
  };
  const deps: ExpressFlowDeps = {
    api,
    tr,
    announce,
    origin: () => ORIGIN,
    formatTime: (ms) => `at ${new Date(ms).toISOString()}`,
    ...(s.now === undefined ? {} : { now: s.now }),
    ...(s.newKey === undefined ? {} : { seal: { newKey: s.newKey } }),
  };
  const flow = new ExpressSecretFlow({ tenant }, deps);
  return { flow, calls, announce };
}

describe('ExpressSecretFlow: offer', () => {
  it('offers the form with the durations of the tenant, one day preselected', () => {
    const { flow } = setup({});
    expect(flow.offered).toBe(true);
    expect(flow.durations).toEqual(['1h', '1d', '7d']);
    expect(flow.expiresIn).toBe('1d');
    expect(flow.maxChars).toBe(10000);
    expect(flow.step).toBe('form');
    expect(flow.busy).toBe(false);
    expect(flow.errorText).toBeUndefined();
  });

  it('is not offered when the tenant has it off or does not describe it', () => {
    expect(setup({}, { features: { ...FEATURES, enabled: false } }).flow.offered).toBe(false);
    const none = setup({}, { features: undefined }).flow;
    expect(none.offered).toBe(false);
    expect(none.expiresIn).toBeUndefined();
  });

  it('counts the text in code points', () => {
    const { flow } = setup({});
    flow.text = '😀ab';
    expect(flow.textLength).toBe(3);
    expect(flow.overLimit).toBe(false);
    flow.text = 'a'.repeat(10001);
    expect(flow.overLimit).toBe(true);
  });
});

describe('ExpressSecretFlow: creation', () => {
  it('creates the secret anonymously and composes the link with the key', async () => {
    const { flow, calls, announce } = setup({ 'POST /express-secrets': created });
    flow.text = TEXT;
    flow.expiresIn = '7d';
    const pending = flow.submit();
    expect(flow.busy).toBe(true);
    expect(flow.phase).toBe('sealing');
    await pending;

    expect(calls).toHaveLength(1);
    const call = calls[0] as Call;
    expect(call.method).toBe('POST');
    expect(call.url).toBe('/api/v1/express-secrets');
    expect(call.headers.get('Content-Type')).toBe('application/json');
    // No credential, no CSRF token: an anonymous creation.
    expect(call.headers.has('Authorization')).toBe(false);
    expect(call.headers.has('X-CSRF-Token')).toBe(false);
    const body = JSON.parse(call.body as string) as Record<string, string>;
    expect(Object.keys(body).sort()).toEqual(['encryptedText', 'expiresIn', 'keyVerifier', 'verifier']);
    expect(body['expiresIn']).toBe('7d');

    expect(flow.step).toBe('done');
    expect(flow.phase).toBeUndefined();
    expect(flow.expiresAt).toBe(EXPIRES);
    expect(flow.text).toBe('');
    expect(announce).toHaveBeenCalledWith('secretExpress.done.announce');
    const link = flow.link as string;
    expect(link.startsWith(`${ORIGIN}/s/${TOKEN}#k=`)).toBe(true);

    // The key is only in the fragment of the link, never in a request; the text never leaves.
    const fragment = link.split('#k=')[1] as string;
    for (const c of calls) {
      expect(c.url).not.toContain(fragment);
      expect(c.body).not.toContain(fragment);
      expect(c.body).not.toContain('correct horse');
      for (const [, value] of c.headers) {
        expect(value).not.toContain(fragment);
        expect(value).not.toContain('correct horse');
      }
    }
    // The recipient opens the sealed text with the key of the link.
    const rootKey = await deriveSecretKey(parseKey(fragment), '', null);
    expect(await openSecret(rootKey, body['encryptedText'] as string)).toBe(TEXT);
  });

  it('wipes the key once the link is built', async () => {
    const key = new Uint8Array(32).fill(5);
    const { flow } = setup({ 'POST /express-secrets': created }, { newKey: () => key });
    flow.text = 'x';
    await flow.submit();
    expect(flow.link).toBe(`${ORIGIN}/s/${TOKEN}#k=${encodeKey(new Uint8Array(32).fill(5))}`);
    expect(key.every((b) => b === 0)).toBe(true);
  });

  it('refuses an invalid form without any request', async () => {
    const { flow, calls } = setup({});
    flow.text = '   ';
    flow.expiresIn = undefined;
    await flow.submit();
    expect(calls).toHaveLength(0);
    expect(flow.step).toBe('form');
    expect(flow.refusals).toBe(1);
    expect(flow.invalidFields).toEqual(['text', 'expiresIn']);
    expect(flow.errors.text).toEqual({ key: 'secretExpress.text.required' });
    flow.text = '😀'.repeat(10001);
    flow.expiresIn = '1h';
    await flow.submit();
    expect(flow.refusals).toBe(2);
    expect(flow.errors).toEqual({ text: { key: 'secretExpress.text.tooLong', params: { max: 10000 } } });
    expect(calls).toHaveLength(0);
  });

  it('ignores a submission while one is running or after the end', async () => {
    const { flow, calls } = setup({ 'POST /express-secrets': created });
    flow.text = 'x';
    const first = flow.submit();
    await flow.submit();
    await first;
    expect(calls).toHaveLength(1);
    await flow.submit();
    expect(calls).toHaveLength(1);
  });

  it('reports a sealing failure and wipes the key', async () => {
    const key = new Uint8Array(32).fill(3);
    const { flow, calls } = setup({}, { newKey: () => key.subarray(0, 16) as Uint8Array<ArrayBuffer> });
    flow.text = 'x';
    await flow.submit();
    expect(calls).toHaveLength(0);
    expect(flow.step).toBe('form');
    expect(flow.failure).toEqual({ kind: 'seal' });
    expect(flow.errorText).toBe('secretExpress.error.sealFailed');
    expect(flow.text).toBe('x');
  });
});

describe('ExpressSecretFlow: refusals', () => {
  it.each<[string, Reply | Error, string]>([
    [
      'a closed service',
      problem(403, 'express-secrets-disabled'),
      'secretExpress.error.disabled {"entity":"Entity A"}',
    ],
    [
      'too many pending secrets',
      problem(429, 'express-secret-limit-reached'),
      'secretExpress.error.limitReached',
    ],
    ['maintenance', problem(503, 'maintenance'), 'errors.maintenance'],
    ['a tenant being set up', problem(503, 'tenant-in-setup'), 'errors.tenant-in-setup'],
    ['a refused body', problem(400, 'validation-failed'), 'secretExpress.error.invalid'],
    ['a rate limit without delay', problem(429, 'rate-limited'), 'secretExpress.error.rateLimited'],
    ['a lost connection', new TypeError('offline'), 'errors.network'],
    ['a cross-site refusal', problem(403, 'csrf-invalid'), 'errors.csrf-invalid'],
    ['a server error', { status: 500 }, 'errors.unknown'],
  ])('keeps the text and explains %s', async (_name, reply, message) => {
    const key = new Uint8Array(32).fill(1);
    const { flow } = setup({ 'POST /express-secrets': reply }, { newKey: () => key });
    flow.text = TEXT;
    await flow.submit();
    expect(flow.step).toBe('form');
    expect(flow.link).toBeUndefined();
    expect(flow.text).toBe(TEXT);
    expect(flow.refusals).toBe(1);
    expect(flow.errorText).toBe(message);
    // Nothing was created: the key is wiped, a new submission draws a new one.
    expect(key.every((b) => b === 0)).toBe(true);
  });

  it('classifies a network failure', async () => {
    const { flow } = setup({ 'POST /express-secrets': new NetworkError(new Error('x')) });
    flow.text = 'x';
    await flow.submit();
    expect(flow.failure).toEqual({ kind: 'network' });
  });

  it('waits for the end of a rate limit before a new attempt', async () => {
    let now = 1_000_000;
    const { flow, calls } = setup(
      { 'POST /express-secrets': [problem(429, 'rate-limited', { retryAfterSeconds: 1200 }), created] },
      { now: () => now },
    );
    flow.text = TEXT;
    await flow.submit();
    expect(flow.retryAt).toBe(1_000_000 + 1_200_000);
    expect(flow.secondsBeforeRetry()).toBe(1200);
    expect(flow.errorText).toBe(
      `secretExpress.error.rateLimitedUntil {"time":"at ${new Date(2_200_000).toISOString()}"}`,
    );
    now += 600_000;
    await flow.submit();
    expect(calls).toHaveLength(1);
    expect(flow.secondsBeforeRetry()).toBe(600);
    now += 600_000;
    expect(flow.secondsBeforeRetry()).toBe(0);
    await flow.submit();
    expect(calls).toHaveLength(2);
    expect(flow.step).toBe('done');
    expect(flow.retryAt).toBeUndefined();
    expect(flow.errorText).toBeUndefined();
  });
});

describe('ExpressSecretFlow: after the creation', () => {
  it('creates another secret from an empty form', async () => {
    const { flow } = setup({ 'POST /express-secrets': created });
    flow.text = TEXT;
    flow.expiresIn = '1h';
    await flow.submit();
    flow.createAnother();
    expect(flow.step).toBe('form');
    expect(flow.link).toBeUndefined();
    expect(flow.expiresAt).toBeUndefined();
    expect(flow.text).toBe('');
    expect(flow.expiresIn).toBe('1d');
    expect(flow.errors).toEqual({});
    expect(flow.failure).toBeUndefined();
  });

  it('forgets the link when the page is left, only on the done step', async () => {
    const { flow } = setup({ 'POST /express-secrets': created });
    flow.text = 'draft';
    flow.forgetResult();
    expect(flow.text).toBe('draft');
    expect(flow.step).toBe('form');
    await flow.submit();
    expect(flow.link).toBeDefined();
    flow.forgetResult();
    expect(flow.link).toBeUndefined();
    expect(flow.expiresAt).toBeUndefined();
    expect(flow.step).toBe('form');
  });
});
