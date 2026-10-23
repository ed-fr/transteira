import { describe, expect, it } from 'vitest';
import { createXhrTransport, parseIntHeader, type XhrLike } from './transport-xhr';
import { TransportError } from './tus';

class FakeXhr implements XhrLike {
  method = '';
  url = '';
  headers: Record<string, string> = {};
  body: Blob | null | undefined;
  status = 0;
  responseHeaders: Record<string, string> = {};
  aborted = false;
  onload: (() => void) | null = null;
  onerror: (() => void) | null = null;
  ontimeout: (() => void) | null = null;
  onabort: (() => void) | null = null;
  upload: { onprogress: ((event: { loaded: number }) => void) | null } = { onprogress: null };

  open(method: string, url: string): void {
    this.method = method;
    this.url = url;
  }
  setRequestHeader(name: string, value: string): void {
    this.headers[name] = value;
  }
  getResponseHeader(name: string): string | null {
    return this.responseHeaders[name] ?? null;
  }
  send(body?: Blob | null): void {
    this.body = body;
  }
  abort(): void {
    this.aborted = true;
    this.onabort?.();
  }
  respond(status: number, headers: Record<string, string> = {}): void {
    this.status = status;
    this.responseHeaders = headers;
    this.onload?.();
  }
}

function harness(token: string | null = 'csrf-1') {
  const xhrs: FakeXhr[] = [];
  const transport = createXhrTransport({
    csrfToken: () => token ?? undefined,
    createXhr: () => {
      const x = new FakeXhr();
      xhrs.push(x);
      return x;
    },
  });
  const last = (): FakeXhr => {
    const x = xhrs.at(-1);
    if (x === undefined) throw new Error('no request');
    return x;
  };
  return { transport, xhrs, last };
}

describe('parseIntHeader', () => {
  it('parses non-negative integers only', () => {
    expect(parseIntHeader('42')).toBe(42);
    expect(parseIntHeader(' 7 ')).toBe(7);
    expect(parseIntHeader(null)).toBeUndefined();
    expect(parseIntHeader('-1')).toBeUndefined();
    expect(parseIntHeader('1.5')).toBeUndefined();
    expect(parseIntHeader('Wed, 21 Oct 2026 07:28:00 GMT')).toBeUndefined();
  });
});

describe('XHR transport', () => {
  it('HEAD sends Tus-Resumable without CSRF and reads the offsets', async () => {
    const { transport, last } = harness();
    const p = transport.head('/api/v1/uploads/u1');
    expect(last()).toMatchObject({ method: 'HEAD', url: '/api/v1/uploads/u1', body: null });
    expect(last().headers).toEqual({ 'Tus-Resumable': '1.0.0' });
    last().respond(200, { 'Upload-Offset': '123', 'Upload-Length': '456' });
    await expect(p).resolves.toEqual({ status: 200, offset: 123, length: 456 });
  });

  it('HEAD errors carry Retry-After', async () => {
    const { transport, last } = harness();
    const p = transport.head('/u');
    last().respond(429, { 'Retry-After': '9' });
    await expect(p).resolves.toEqual({ status: 429, retryAfterSeconds: 9 });
  });

  it('PATCH sends the chunk with its headers and reports progress', async () => {
    const { transport, last } = harness();
    const body = new Blob(['hello']);
    const progress: number[] = [];
    const p = transport.patch('/u', 10, body, { onProgress: (n) => progress.push(n) });
    const xhr = last();
    expect(xhr.method).toBe('PATCH');
    expect(xhr.body).toBe(body);
    expect(xhr.headers).toEqual({
      'Tus-Resumable': '1.0.0',
      'X-CSRF-Token': 'csrf-1',
      'Content-Type': 'application/offset+octet-stream',
      'Upload-Offset': '10',
    });
    xhr.upload.onprogress?.({ loaded: 3 });
    xhr.upload.onprogress?.({ loaded: 5 });
    xhr.respond(204, { 'Upload-Offset': '15' });
    await expect(p).resolves.toEqual({ status: 204, offset: 15 });
    expect(progress).toEqual([3, 5]);
  });

  it('PATCH errors carry Retry-After and omit the CSRF header without a token', async () => {
    const { transport, last } = harness(null);
    const p = transport.patch('/u', 0, new Blob(['x']));
    expect(last().headers['X-CSRF-Token']).toBeUndefined();
    last().respond(503, { 'Retry-After': '30' });
    await expect(p).resolves.toEqual({ status: 503, retryAfterSeconds: 30 });
  });

  it('DELETE terminates with the CSRF token', async () => {
    const { transport, last } = harness();
    const p = transport.terminate('/u');
    expect(last()).toMatchObject({ method: 'DELETE', body: null });
    expect(last().headers['X-CSRF-Token']).toBe('csrf-1');
    last().respond(204);
    await expect(p).resolves.toEqual({ status: 204 });
  });

  it('rejects network errors, timeouts and status 0', async () => {
    const { transport, last } = harness();
    const a = transport.head('/u');
    last().onerror?.();
    await expect(a).rejects.toEqual(new TransportError('network error'));
    const b = transport.head('/u');
    last().ontimeout?.();
    await expect(b).rejects.toMatchObject({ message: 'timeout', aborted: false });
    const c = transport.head('/u');
    last().respond(0);
    await expect(c).rejects.toBeInstanceOf(TransportError);
  });

  it('aborts through the signal', async () => {
    const { transport, last } = harness();
    const controller = new AbortController();
    const p = transport.patch('/u', 0, new Blob(['x']), { signal: controller.signal });
    controller.abort();
    await expect(p).rejects.toMatchObject({ name: 'TransportError', aborted: true });
    expect(last().aborted).toBe(true);
  });

  it('rejects at once when the signal is already aborted', async () => {
    const { transport, xhrs } = harness();
    const controller = new AbortController();
    controller.abort();
    await expect(transport.head('/u', controller.signal)).rejects.toMatchObject({ aborted: true });
    expect(xhrs).toHaveLength(0);
  });

  it('defaults to the global XMLHttpRequest', async () => {
    const created: FakeXhr[] = [];
    const original = (globalThis as Record<string, unknown>).XMLHttpRequest;
    (globalThis as Record<string, unknown>).XMLHttpRequest = class extends FakeXhr {
      constructor() {
        super();
        created.push(this);
      }
    };
    try {
      const transport = createXhrTransport({ csrfToken: () => undefined });
      const p = transport.terminate('/u');
      created[0]?.respond(204);
      await expect(p).resolves.toEqual({ status: 204 });
    } finally {
      (globalThis as Record<string, unknown>).XMLHttpRequest = original;
    }
  });
});
