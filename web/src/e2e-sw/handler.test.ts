import { describe, expect, it, vi } from 'vitest';
import {
  ATTACHMENT_CSP,
  EntryRegistry,
  MAX_ARCHIVE_FILES,
  attachmentHeaders,
  contentDisposition,
  handleMessage,
  observe,
  parseRegistration,
  routeRequest,
  type ReplyPort,
  type WorkerContext,
} from './handler';
import { DownloadFailure } from '../shared/e2e/ciphertext';
import { E2EError } from '../shared/e2e/errors';
import {
  ENTRY_TTL_MS,
  MAX_PENDING,
  type SwEntry,
  type SwFile,
  type SwReply,
} from '../shared/e2e/sw-protocol';
import { zipSize } from '../shared/e2e/zip';
import {
  fakeServer,
  fixture,
  readAll,
  readError,
  readZip,
  type EncryptedFile,
  type Fixture,
} from '../shared/e2e/download.test-helper';
import { firstDifference } from '../shared/e2e/tte2-helpers.test-helper';
import type { FetchLike } from '../shared/e2e/ciphertext';

const ORIGIN = 'https://transfer.entity-a.example.com';
const ID = 'AAAAAAAAAAAAAAAAAAAAAA';

function port(): ReplyPort & { replies: SwReply[] } {
  const replies: SwReply[] = [];
  return { replies, postMessage: (m: SwReply) => void replies.push(m) } as ReplyPort & { replies: SwReply[] };
}

function context(fetchFn: FetchLike, now = 1000): WorkerContext & { clock: { now: number } } {
  const clock = { now };
  return {
    clock,
    origin: ORIGIN,
    registry: new EntryRegistry(),
    fetch: fetchFn,
    now: () => clock.now,
    sleep: () => new Promise<void>(() => undefined),
  };
}

function swFile(fx: Fixture, f: EncryptedFile, name = `f${f.index}.bin`): SwFile {
  return { url: f.url, key: fx.key, index: f.index, name, size: f.plain.length, sha256: f.sha256 };
}

/** A body whose cancellation fails. */
function unCancellable(): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    cancel() {
      throw new Error('cannot cancel');
    },
  });
}

function get(path: string, init: RequestInit = {}): Request {
  return new Request(ORIGIN + path, init);
}

describe('EntryRegistry', () => {
  const entry = { kind: 'archive', name: 'a.zip', files: [] } as unknown as SwEntry;

  it('serves an entry once', async () => {
    const r = new EntryRegistry();
    const p = port();
    const held = r.add(ID, entry, p, 0);
    expect(held).toBeDefined();
    expect(r.add(ID, entry, p, 0)).toBeUndefined();
    expect(r.size).toBe(1);
    expect(r.take(ID, 1)).toEqual({ entry, port: p });
    await held;
    expect(r.take(ID, 1)).toBeUndefined();
  });

  it('expires entries after the TTL and tells their page', async () => {
    const r = new EntryRegistry();
    const p = port();
    const held = r.add(ID, entry, p, 0);
    expect(r.take(ID, ENTRY_TTL_MS)).toBeUndefined();
    await held;
    expect(r.size).toBe(0);
    expect(p.replies).toEqual([{ type: 'failed', code: 'unavailable' }]);
  });

  it('expires one entry on demand, only if it is still the same', () => {
    const r = new EntryRegistry();
    const p = port();
    r.add(ID, entry, p, 0);
    r.expire(ID, { ...entry });
    expect(r.size).toBe(1);
    r.expire('other', entry);
    r.expire(ID, entry);
    expect(r.size).toBe(0);
    expect(p.replies).toEqual([{ type: 'failed', code: 'unavailable' }]);
    expect(r.take(ID, 0)).toBeUndefined();
  });

  it('drops the oldest entries beyond the maximum and tells their page', async () => {
    const r = new EntryRegistry(1000, 2);
    const pa = port();
    const pb = port();
    const first = r.add('a', entry, pa, 0);
    r.add('b', entry, pb, 0);
    r.add('c', entry, port(), 0);
    await first;
    expect(pa.replies).toEqual([{ type: 'failed', code: 'unavailable' }]);
    expect(pb.replies).toEqual([]);
    expect(r.size).toBe(2);
    expect(r.take('a', 0)).toBeUndefined();
    expect(r.take('c', 0)).toBeDefined();
    expect(MAX_PENDING).toBeGreaterThan(10);
  });
});

describe('parseRegistration', () => {
  it('accepts a file and an archive, sanitizing names', async () => {
    const fx = await fixture([10, 20]);
    const file = { ...swFile(fx, fx.files[0]!), name: 'a<b>.txt' };
    expect(parseRegistration({ type: 'register', id: ID, entry: { kind: 'file', file } })).toEqual({
      id: ID,
      entry: { kind: 'file', file: { ...file, name: 'a_b_.txt' } },
    });
    const files = [swFile(fx, fx.files[0]!, 'dir/a.txt'), swFile(fx, fx.files[1]!, 'b.txt')];
    expect(
      parseRegistration({ type: 'register', id: ID, entry: { kind: 'archive', name: 't.zip', files } }),
    ).toEqual({ id: ID, entry: { kind: 'archive', name: 't.zip', files } });
  });

  it('rejects anything else', async () => {
    const fx = await fixture([10]);
    const good = swFile(fx, fx.files[0]!);
    const raw = new Uint8Array(32);
    const aes = await crypto.subtle.importKey('raw', raw, 'AES-GCM', true, ['encrypt']);
    const bad: unknown[] = [
      null,
      'x',
      { type: 'other', id: ID, entry: { kind: 'file', file: good } },
      { type: 'register', id: 'short', entry: { kind: 'file', file: good } },
      { type: 'register', id: ID, entry: null },
      { type: 'register', id: ID, entry: { kind: 'file', file: null } },
      { type: 'register', id: ID, entry: { kind: 'other', name: 'x', files: [good] } },
      { type: 'register', id: ID, entry: { kind: 'archive', name: 1, files: [good] } },
      { type: 'register', id: ID, entry: { kind: 'archive', name: 'x', files: 'no' } },
      { type: 'register', id: ID, entry: { kind: 'archive', name: 'x', files: [] } },
      {
        type: 'register',
        id: ID,
        entry: { kind: 'archive', name: 'x', files: Array(MAX_ARCHIVE_FILES + 1).fill(good) },
      },
      { type: 'register', id: ID, entry: { kind: 'archive', name: 'x', files: [good, { ...good }] } },
      {
        type: 'register',
        id: ID,
        entry: { kind: 'archive', name: 'x', files: [good, { ...good, name: 'F0.BIN' }] },
      },
      { type: 'register', id: ID, entry: { kind: 'archive', name: 'x', files: [{ ...good, name: '../a' }] } },
      { type: 'register', id: ID, entry: { kind: 'archive', name: 'x', files: [{ ...good, name: 'á' }] } },
    ];
    const fileVariants: Partial<Record<keyof SwFile, unknown>>[] = [
      { url: 'https://evil.example/api/v1/downloads/x' },
      { url: '/api/v1/tenant/assets/logo' },
      { url: 3 },
      { key: raw },
      { key: aes },
      { index: -1 },
      { index: 1.5 },
      { index: 2 ** 32 },
      { index: '0' },
      { name: 3 },
      { size: -1 },
      { size: '1' },
      { size: 2 ** 53 },
      { sha256: 'A'.repeat(64) },
      { sha256: 1 },
    ];
    for (const v of fileVariants) {
      bad.push({ type: 'register', id: ID, entry: { kind: 'file', file: { ...good, ...v } } });
    }
    for (const data of bad) expect(parseRegistration(data), JSON.stringify(data)).toBeUndefined();
    // An extractable HKDF key is refused too.
    const extractableKey = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey']);
    Object.defineProperty(extractableKey, 'extractable', { value: true });
    expect(
      parseRegistration({
        type: 'register',
        id: ID,
        entry: { kind: 'file', file: { ...good, key: extractableKey } },
      }),
    ).toBeUndefined();
  });
});

describe('handleMessage', () => {
  it('registers, acknowledges and stays alive until the entry is taken', async () => {
    const fx = await fixture([10]);
    const ctx = context(fakeServer(fx.files));
    const p = port();
    let settled = false;
    const done = handleMessage(
      { type: 'register', id: ID, entry: { kind: 'file', file: swFile(fx, fx.files[0]!) } },
      [p],
      ctx,
    ).then(() => (settled = true));
    expect(p.replies).toEqual([{ type: 'registered' }]);
    await Promise.resolve();
    expect(settled).toBe(false);
    ctx.registry.take(ID, ctx.now());
    await done;
    expect(settled).toBe(true);
  });

  it('stops waiting after the TTL, drops the entry and tells the page', async () => {
    const fx = await fixture([10]);
    const ctx = context(fakeServer(fx.files));
    const sleep = vi.fn(() => Promise.resolve());
    ctx.sleep = sleep;
    const p = port();
    await handleMessage(
      { type: 'register', id: ID, entry: { kind: 'file', file: swFile(fx, fx.files[0]!) } },
      [p],
      ctx,
    );
    expect(sleep).toHaveBeenCalledWith(ENTRY_TTL_MS);
    expect(ctx.registry.size).toBe(0);
    expect(p.replies).toEqual([{ type: 'registered' }, { type: 'failed', code: 'unavailable' }]);
  });

  it('rejects invalid or duplicate registrations and ignores messages without port', async () => {
    const fx = await fixture([10]);
    const ctx = context(fakeServer(fx.files));
    const msg = { type: 'register', id: ID, entry: { kind: 'file', file: swFile(fx, fx.files[0]!) } };
    const p = port();
    await handleMessage({ type: 'nope' }, [p], ctx);
    void handleMessage(msg, [p], ctx);
    await handleMessage(msg, [p], ctx);
    expect(p.replies).toEqual([{ type: 'rejected' }, { type: 'registered' }, { type: 'rejected' }]);
    await handleMessage(msg, [], ctx);
  });
});

describe('contentDisposition and attachmentHeaders', () => {
  it('encodes like the server', () => {
    expect(contentDisposition('report.pdf')).toBe(
      `attachment; filename="report.pdf"; filename*=UTF-8''report.pdf`,
    );
    expect(contentDisposition('été "1"\\.txt')).toBe(
      `attachment; filename="_t_ _1__.txt"; filename*=UTF-8''%C3%A9t%C3%A9%20%221%22%5C.txt`,
    );
    expect(contentDisposition('')).toBe(`attachment; filename="download"; filename*=UTF-8''download`);
    expect(contentDisposition('a\u0001~|')).toBe(`attachment; filename="a_~|"; filename*=UTF-8''a%01~|`);
  });

  it('forces a download', () => {
    const h = attachmentHeaders('a.html', 12);
    expect(Object.fromEntries(h)).toEqual({
      'content-type': 'application/octet-stream',
      'content-disposition': `attachment; filename="a.html"; filename*=UTF-8''a.html`,
      'content-length': '12',
      'x-content-type-options': 'nosniff',
      'cache-control': 'no-store',
      'content-security-policy': ATTACHMENT_CSP,
    });
  });
});

describe('observe', () => {
  it('reports done, failures and cancellation', async () => {
    const p = port();
    expect(await readAll(observe(new Blob([new Uint8Array([1, 2])]).stream(), p))).toEqual(
      new Uint8Array([1, 2]),
    );
    expect(p.replies).toEqual([{ type: 'done' }]);

    const failing = new ReadableStream<Uint8Array>({
      pull(c) {
        c.error(new E2EError('auth'));
      },
    });
    const q = port();
    expect(await readError(observe(failing, q))).toBeInstanceOf(E2EError);
    expect(q.replies).toEqual([{ type: 'failed', code: 'corrupt' }]);

    const r = port();
    const cancel = vi.fn();
    const endless = new ReadableStream<Uint8Array>({ pull: (c) => c.enqueue(new Uint8Array(1)), cancel });
    const reader = observe(endless, r).getReader();
    await reader.read();
    await reader.cancel('user');
    expect(cancel).toHaveBeenCalledWith('user');
    expect(r.replies).toEqual([{ type: 'failed', code: 'cancelled' }]);

    const stubborn = new ReadableStream<Uint8Array>({
      pull: (c) => c.enqueue(new Uint8Array(1)),
      cancel() {
        throw new Error('cannot cancel');
      },
    });
    const sr = observe(stubborn, port()).getReader();
    await sr.read();
    await sr.cancel();
  });
});

describe('routeRequest', () => {
  it('ignores what is not a GET of the origin under /e2e/', async () => {
    const ctx = context(fakeServer([]));
    expect(routeRequest(get('/d/tok'), ctx)).toBeUndefined();
    expect(routeRequest(get('/e2e-sw.js'), ctx)).toBeUndefined();
    expect(routeRequest(get(`/e2e/${ID}`, { method: 'POST' }), ctx)).toBeUndefined();
    expect(routeRequest(new Request(`https://evil.example/e2e/${ID}`), ctx)).toBeUndefined();
  });

  it('answers 204 for an unknown id (the page stays as it is)', async () => {
    const ctx = context(fakeServer([]));
    const resp = await routeRequest(get(`/e2e/${ID}`), ctx)!;
    expect(resp.status).toBe(204);
    expect(resp.body).toBeNull();
    expect(resp.headers.get('cache-control')).toBe('no-store');
    expect(resp.headers.get('x-content-type-options')).toBe('nosniff');
  });

  it('streams a decrypted file, once', async () => {
    const fx = await fixture([200_000]);
    const server = fakeServer(fx.files);
    const ctx = context(server);
    const p = port();
    ctx.registry.add(ID, { kind: 'file', file: swFile(fx, fx.files[0]!, 'plan.pdf') }, p, ctx.now());
    const resp = await routeRequest(get(`/e2e/${ID}`), ctx)!;
    expect(resp.status).toBe(200);
    expect(resp.headers.get('content-length')).toBe('200000');
    expect(resp.headers.get('content-type')).toBe('application/octet-stream');
    expect(resp.headers.get('content-disposition')).toContain('filename="plan.pdf"');
    expect(p.replies).toEqual([{ type: 'started' }]);
    expect(firstDifference(await readAll(resp.body!), fx.files[0]!.plain)).toBe(-1);
    expect(p.replies).toEqual([{ type: 'started' }, { type: 'done' }]);
    expect(server.calls[0]!.init).toEqual({
      credentials: 'same-origin',
      redirect: 'error',
      cache: 'no-store',
    });
    expect((await routeRequest(get(`/e2e/${ID}`), ctx)!).status).toBe(204);
  });

  it('errors the stream on a fingerprint or size mismatch, or a tampered ciphertext', async () => {
    const fx = await fixture([100_000]);
    const f = fx.files[0]!;
    const cases: [Partial<SwFile>, Uint8Array | undefined][] = [
      [{ sha256: '0'.repeat(64) }, undefined],
      [{ size: 99_999 }, undefined],
      [
        {},
        (() => {
          const c = f.ciphertext.slice();
          c[c.length - 1]! ^= 1;
          return c;
        })(),
      ],
      [{}, f.ciphertext.slice(0, f.ciphertext.length - 20)],
      [{ index: 1 }, undefined],
    ];
    for (const [patch, body] of cases) {
      const server =
        body === undefined
          ? fakeServer(fx.files)
          : fakeServer(fx.files, {
              [f.url]: async () =>
                new Response(new Blob([new Uint8Array(body)]).stream(), {
                  headers: { 'Content-Type': 'application/octet-stream' },
                }),
            });
      const ctx = context(server);
      const p = port();
      ctx.registry.add(ID, { kind: 'file', file: { ...swFile(fx, f), ...patch } }, p, ctx.now());
      const resp = await routeRequest(get(`/e2e/${ID}`), ctx)!;
      expect(resp.status).toBe(200);
      await readError(resp.body!);
      expect(p.replies).toEqual([{ type: 'started' }, { type: 'failed', code: 'corrupt' }]);
    }
  });

  it('answers 204 and reports the reason when the ciphertext cannot be fetched', async () => {
    const fx = await fixture([10]);
    const f = fx.files[0]!;
    const cases: [() => Promise<Response>, string][] = [
      [() => Promise.reject(new TypeError('offline')), 'network'],
      [async () => new Response('x', { status: 401 }), 'unavailable'],
      [async () => new Response('x', { status: 410 }), 'unavailable'],
      [async () => new Response('x', { status: 500 }), 'network'],
      [async () => new Response('<html>', { headers: { 'Content-Type': 'text/html' } }), 'corrupt'],
      [
        async () => new Response(null, { headers: { 'Content-Type': 'application/octet-stream' } }),
        'corrupt',
      ],
      [async () => new Response('x', { headers: {} }), 'corrupt'],
      [async () => new Response(null, { status: 404 }), 'unavailable'],
      [async () => new Response(null), 'corrupt'],
      [async () => new Response(null, { headers: { 'Content-Type': 'text/html' } }), 'corrupt'],
      [async () => new Response(unCancellable(), { status: 500 }), 'network'],
      [async () => new Response(unCancellable(), { headers: { 'Content-Type': 'text/plain' } }), 'corrupt'],
    ];
    for (const [answer, code] of cases) {
      const ctx = context(fakeServer(fx.files, { [f.url]: answer }));
      const p = port();
      ctx.registry.add(ID, { kind: 'file', file: swFile(fx, f) }, p, ctx.now());
      const resp = await routeRequest(get(`/e2e/${ID}`), ctx)!;
      expect(resp.status).toBe(204);
      expect(p.replies).toEqual([{ type: 'failed', code }]);
    }
  });

  it('streams an archive of decrypted files with an exact length', async () => {
    const fx = await fixture([70_000, 0, 130_000]);
    const ctx = context(fakeServer(fx.files));
    const p = port();
    const names = ['dir/a.bin', 'empty', 'dir/sub/b.bin'];
    const files = fx.files.map((f, i) => swFile(fx, f, names[i]));
    ctx.registry.add(ID, { kind: 'archive', name: 'transfer.zip', files }, p, ctx.now());
    const resp = await routeRequest(get(`/e2e/${ID}`), ctx)!;
    const expected = zipSize(files);
    expect(resp.headers.get('content-length')).toBe(String(expected));
    expect(resp.headers.get('content-disposition')).toContain('filename="transfer.zip"');
    const zip = await readAll(resp.body!);
    expect(zip.length).toBe(expected);
    const entries = readZip(zip);
    expect(entries.map((e) => e.name)).toEqual(names);
    entries.forEach((e, i) => expect(firstDifference(e.data, fx.files[i]!.plain)).toBe(-1));
    expect(p.replies).toEqual([{ type: 'started' }, { type: 'done' }]);
  });

  it('fails the archive when a later file is unavailable or altered', async () => {
    const fx = await fixture([10, 20]);
    const second = fx.files[1]!;
    for (const [override, code] of [
      [async () => new Response('x', { status: 403 }), 'unavailable'],
      [
        async () =>
          new Response(new Blob([fx.files[0]!.ciphertext]).stream(), {
            headers: { 'Content-Type': 'application/octet-stream' },
          }),
        'corrupt',
      ],
    ] as const) {
      const ctx = context(fakeServer(fx.files, { [second.url]: override }));
      const p = port();
      const files = fx.files.map((f) => swFile(fx, f));
      ctx.registry.add(ID, { kind: 'archive', name: 'transfer.zip', files }, p, ctx.now());
      const resp = await routeRequest(get(`/e2e/${ID}`), ctx)!;
      const err = await readError(resp.body!);
      expect(p.replies).toEqual([{ type: 'started' }, { type: 'failed', code }]);
      if (code === 'unavailable') expect(err).toBeInstanceOf(DownloadFailure);
    }
  });
});
