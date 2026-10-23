import { describe, expect, it, vi } from 'vitest';
import {
  ApiProblem,
  NetworkError,
  buildUrl,
  createApiClient,
  expandPath,
  type ApiClientDeps,
} from './client';

function jsonResponse(status: number, body: unknown, type = 'application/json'): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': type } });
}

type FetchMock = ReturnType<typeof vi.fn<typeof fetch>>;

function call(fetch: FetchMock, index = 0): [string, RequestInit] {
  return fetch.mock.calls[index] as unknown as [string, RequestInit];
}

function client(response: () => Response | Promise<Response>, extra: Partial<ApiClientDeps> = {}) {
  const fetchMock: FetchMock = vi.fn<typeof fetch>(async () => response());
  const api = createApiClient({ fetch: fetchMock, language: () => 'fr', csrfToken: () => 'tok', ...extra });
  return { fetch: fetchMock, api };
}

describe('buildUrl', () => {
  it('appends defined query parameters only', () => {
    expect(buildUrl('/api/v1', '/x', { a: 1, b: undefined, c: true })).toBe('/api/v1/x?a=1&c=true');
    expect(buildUrl('/api/v1', '/x')).toBe('/api/v1/x');
    expect(buildUrl('/api/v1', '/x', { q: 'a b&c' })).toBe('/api/v1/x?q=a+b%26c');
  });
});

describe('expandPath', () => {
  it('encodes path parameters', () => {
    expect(expandPath('/downloads/{linkToken}/files/{fileId}', { linkToken: 'a/b', fileId: 3 })).toBe(
      '/downloads/a%2Fb/files/3',
    );
    expect(expandPath('/tenant', undefined)).toBe('/tenant');
  });

  it('refuses missing or empty parameters', () => {
    expect(() => expandPath('/downloads/{linkToken}', {})).toThrow('missing path parameter linkToken');
    expect(() => expandPath('/downloads/{linkToken}', { linkToken: '' })).toThrow();
    expect(() => expandPath('/downloads/{linkToken}', undefined)).toThrow();
  });
});

describe('request', () => {
  it('sends language, Accept, CSRF token on unsafe methods and decodes JSON', async () => {
    const { fetch, api } = client(() => jsonResponse(201, { ok: true }));
    const res = await api.request<{ ok: boolean }>('POST', '/deposit-sessions', {
      body: { email: 'a' },
      headers: { 'Idempotency-Key': 'k' },
    });
    expect(res.status).toBe(201);
    expect(res.data.ok).toBe(true);
    const [url, init] = call(fetch);
    const headers = init.headers as Headers;
    expect(url).toBe('/api/v1/deposit-sessions');
    expect(init.method).toBe('POST');
    expect(init.body).toBe('{"email":"a"}');
    expect(headers.get('Accept')).toBe('application/json');
    expect(headers.get('Accept-Language')).toBe('fr');
    expect(headers.get('X-CSRF-Token')).toBe('tok');
    expect(headers.get('Content-Type')).toBe('application/json');
    expect(headers.get('Idempotency-Key')).toBe('k');
    expect(init.credentials).toBe('same-origin');
    expect(init.signal).toBeNull();
  });

  it.each(['PUT', 'PATCH', 'DELETE'] as const)('sends the CSRF token on %s', async (method) => {
    const { fetch, api } = client(() => new Response(null, { status: 204 }));
    await api.request(method, '/x');
    expect((call(fetch)[1].headers as Headers).get('X-CSRF-Token')).toBe('tok');
    expect(call(fetch)[1].body).toBeNull();
  });

  it.each(['GET', 'HEAD'] as const)('omits the CSRF token on %s', async (method) => {
    const { fetch, api } = client(() => new Response(null, { status: 204 }), { baseUrl: '/b' });
    const res = await api.request(method, '/t');
    expect(res.data).toBeUndefined();
    const [url, init] = call(fetch);
    expect(url).toBe('/b/t');
    expect((init.headers as Headers).has('X-CSRF-Token')).toBe(false);
  });

  it('omits an absent or empty CSRF token', async () => {
    for (const token of [undefined, '']) {
      const { fetch, api } = client(() => new Response(null, { status: 204 }), { csrfToken: () => token });
      await api.request('POST', '/x');
      expect((call(fetch)[1].headers as Headers).has('X-CSRF-Token')).toBe(false);
    }
  });

  it('passes the abort signal', async () => {
    const { fetch, api } = client(() => new Response(null, { status: 204 }));
    const controller = new AbortController();
    await api.request('GET', '/x', { signal: controller.signal });
    expect(call(fetch)[1].signal).toBe(controller.signal);
  });

  it('hands csrfToken members to onCsrfToken', async () => {
    const onCsrfToken = vi.fn();
    const { api } = client(() => jsonResponse(200, { csrfToken: 'new' }), { onCsrfToken });
    await api.request('GET', '/deposit-sessions/current');
    expect(onCsrfToken).toHaveBeenCalledWith('new');

    const ignored = vi.fn();
    for (const body of [{ csrfToken: '' }, { csrfToken: 3 }, null, [1]]) {
      const c = client(() => jsonResponse(200, body), { onCsrfToken: ignored });
      await c.api.request('GET', '/x');
    }
    expect(ignored).not.toHaveBeenCalled();
    // Without a callback, the token is simply ignored.
    await client(() => jsonResponse(200, { csrfToken: 'x' })).api.request('GET', '/x');
  });

  it('accepts JSON media types with parameters and tolerates invalid JSON', async () => {
    const ok = await client(() => jsonResponse(200, { a: 1 }, 'Application/JSON; charset=utf-8')).api.request(
      'GET',
      '/x',
    );
    expect(ok.data).toEqual({ a: 1 });
    const bad = await client(
      () => new Response('{', { status: 200, headers: { 'Content-Type': 'application/json' } }),
    ).api.request('GET', '/x');
    expect(bad.data).toBeUndefined();
    const head = await client(() => jsonResponse(200, { a: 1 })).api.request('HEAD', '/x');
    expect(head.data).toBeUndefined();
  });

  it('treats 304 as success', async () => {
    const res = await client(() => new Response(null, { status: 304 })).api.request('GET', '/x');
    expect(res.status).toBe(304);
  });
});

describe('problems', () => {
  it('decodes every extension member', async () => {
    const problem = {
      type: 'about:blank',
      title: 'Locked',
      status: 429,
      code: 'transfer-locked',
      attemptsRemaining: 0,
      retryAfterSeconds: 60,
      errors: [{ field: '/email', code: 'invalid-email' }],
      maxTransferBytes: 10,
      files: ['a'],
    };
    const { api } = client(() => jsonResponse(429, problem, 'application/problem+json; charset=utf-8'));
    const err = (await api.request('POST', '/x').catch((e: unknown) => e)) as ApiProblem;
    expect(err).toBeInstanceOf(ApiProblem);
    expect(err.name).toBe('ApiProblem');
    expect(err.status).toBe(429);
    expect(err.code).toBe('transfer-locked');
    expect(err.message).toBe('Locked');
    expect(err.attemptsRemaining).toBe(0);
    expect(err.retryAfterSeconds).toBe(60);
    expect(err.errors?.[0]?.field).toBe('/email');
    expect(err.maxTransferBytes).toBe(10);
    expect(err.files).toEqual(['a']);
  });

  it('prefers the detail as message', async () => {
    const { api } = client(() =>
      jsonResponse(
        404,
        { title: 'Not found', detail: 'No such transfer', status: 404, code: 'not-found' },
        'application/problem+json',
      ),
    );
    const err = (await api.request('GET', '/x').catch((e: unknown) => e)) as ApiProblem;
    expect(err.message).toBe('No such transfer');
  });

  it('reports non-problem errors, invalid problem bodies and non-object bodies', async () => {
    for (const response of [
      () => new Response('oops', { status: 502 }),
      () => new Response('{', { status: 500, headers: { 'Content-Type': 'application/problem+json' } }),
      () => jsonResponse(500, ['x'], 'application/problem+json'),
      () => jsonResponse(500, 'x', 'application/problem+json'),
    ]) {
      const err = (await client(response)
        .api.request('GET', '/x')
        .catch((e: unknown) => e)) as ApiProblem;
      expect(err).toBeInstanceOf(ApiProblem);
      expect(err.code).toBeUndefined();
      expect(err.problem).toBeUndefined();
      expect(err.attemptsRemaining).toBeUndefined();
      expect(err.retryAfterSeconds).toBeUndefined();
      expect(err.errors).toBeUndefined();
      expect(err.maxTransferBytes).toBeUndefined();
      expect(err.files).toBeUndefined();
      expect(err.message).toMatch(/^HTTP 50[02]$/);
    }
  });

  it('wraps fetch failures in NetworkError', async () => {
    const offline = client(() => {
      throw new TypeError('offline');
    });
    const err = (await offline.api.request('GET', '/x').catch((e: unknown) => e)) as NetworkError;
    expect(err).toBeInstanceOf(NetworkError);
    expect(err.name).toBe('NetworkError');
    expect(err.cause).toBeInstanceOf(TypeError);
    expect(err.aborted).toBe(false);

    const aborted = client(() => {
      throw new DOMException('aborted', 'AbortError');
    });
    const abortErr = (await aborted.api.request('GET', '/x').catch((e: unknown) => e)) as NetworkError;
    expect(abortErr.aborted).toBe(true);
  });
});

describe('typed methods', () => {
  it('expand path parameters and pass query, body and headers', async () => {
    const { fetch, api } = client(() => jsonResponse(200, { name: 'Entity A' }));
    const tenant = await api.get('/tenant');
    expect(tenant.data.name).toBe('Entity A');
    expect(call(fetch, 0)[0]).toBe('/api/v1/tenant');

    await api.get('/downloads/{linkToken}', { path: { linkToken: 'tok en' } });
    expect(call(fetch, 1)[0]).toBe('/api/v1/downloads/tok%20en');

    await api.get('/admin/tenants/{tenantId}/transfers', { path: { tenantId: 't1' }, params: { limit: 5 } });
    expect(call(fetch, 2)[0]).toBe('/api/v1/admin/tenants/t1/transfers?limit=5');

    await api.post('/deposit-sessions', { body: { email: 'a@entity-a.example.com' } });
    expect(call(fetch, 3)[1].method).toBe('POST');
    expect(call(fetch, 3)[1].body).toBe('{"email":"a@entity-a.example.com"}');

    await api.delete('/deposit-sessions/current');
    expect(call(fetch, 4)[1].method).toBe('DELETE');

    await api.patch('/admin/system/settings', { body: { diskAlertThreshold: 0.9 } });
    expect(call(fetch, 5)[1].method).toBe('PATCH');
    expect((call(fetch, 5)[1].headers as Headers).get('Content-Type')).toBe('application/merge-patch+json');

    await api.put('/admin/system/maintenance', { body: { enabled: true } });
    expect(call(fetch, 6)[1].method).toBe('PUT');
    expect((call(fetch, 6)[1].headers as Headers).get('Content-Type')).toBe('application/json');

    await api.request('PATCH', '/x', {
      headers: { 'content-type': 'application/merge-patch+json' },
      body: {},
    });
    expect((call(fetch, 7)[1].headers as Headers).get('Content-Type')).toBe('application/merge-patch+json');
  });
});
