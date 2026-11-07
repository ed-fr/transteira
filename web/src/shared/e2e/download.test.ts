import { describe, expect, it, vi } from 'vitest';
import {
  ACTIVATION_TIMEOUT_MS,
  E2EDownloadError,
  E2EDownloader,
  MEMORY_LIMIT,
  START_TIMEOUT_MS,
  browserDeps,
  byteCap,
  type ChannelLike,
  type DownloadDeps,
  type DownloadFile,
  type RegistrationLike,
  type WorkerLike,
} from './download';
import { fakeServer, fixture, readZip, type EncryptedFile } from './download.test-helper';
import { firstDifference } from './tte2-helpers.test-helper';
import { SW_SCOPE, SW_URL, type RegisterMessage, type SwReply } from './sw-protocol';
import type { FetchLike } from './ciphertext';

function file(f: EncryptedFile, name = `f${f.index}.bin`): DownloadFile {
  return { url: f.url, index: f.index, name, size: f.plain.length, sha256: f.sha256 };
}

/** Fake browser: timers run by hand, saved blobs and navigations recorded. */
function deps(overrides: Partial<DownloadDeps> = {}) {
  const saved: { blob: Blob; name: string }[] = [];
  const navigations: string[] = [];
  const timers = new Map<number, () => void>();
  let next = 1;
  const ports: ChannelLike['port1'][] = [];
  const d: DownloadDeps = {
    serviceWorker: undefined,
    fetch: fakeServer([]),
    navigate: (url) => void navigations.push(url),
    saveBlob: (blob, name) => void saved.push({ blob, name }),
    channel: () => {
      const port1: ChannelLike['port1'] = { onmessage: null, close: vi.fn() };
      ports.push(port1);
      return { port1, port2: { fake: 'port2' } as unknown as Transferable };
    },
    random: () => new Uint8Array(16).fill(7),
    setTimeout: (handler) => {
      const id = next++;
      timers.set(id, handler);
      return id;
    },
    clearTimeout: (id) => void timers.delete(id as number),
    ...overrides,
  };
  return { d, saved, navigations, timers, ports, fire: () => [...timers.values()].forEach((h) => h()) };
}

/** Fake active Service Worker answering each registration with the scripted replies. */
function worker(script: (msg: RegisterMessage, reply: (r: SwReply) => void) => void, state = 'activated') {
  const posted: { msg: RegisterMessage; transfer: Transferable[] }[] = [];
  let ports: ChannelLike['port1'][] = [];
  const listeners: (() => void)[] = [];
  const w: WorkerLike & {
    state: string;
    setPorts(p: ChannelLike['port1'][]): void;
    change(s: string): void;
  } = {
    state,
    setPorts: (p) => (ports = p),
    change(s) {
      this.state = s;
      listeners.forEach((l) => l());
    },
    postMessage(msg, transfer) {
      posted.push({ msg, transfer });
      const p = ports[ports.length - 1]!;
      script(msg, (r) => p.onmessage?.({ data: r }));
    },
    addEventListener: (_type, listener) => void listeners.push(listener),
  };
  return { w, posted };
}

function container(reg: RegistrationLike | Promise<RegistrationLike>) {
  return { register: vi.fn(() => Promise.resolve(reg)) };
}

const registration = (
  w: WorkerLike,
  slot: 'active' | 'installing' | 'waiting' = 'active',
): RegistrationLike => ({
  active: null,
  installing: null,
  waiting: null,
  [slot]: w,
});

async function codeOf(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (err) {
    expect(err).toBeInstanceOf(E2EDownloadError);
    return (err as E2EDownloadError).code;
  }
  return 'ok';
}

describe('E2EDownloader with a Service Worker', () => {
  it('registers the worker once, posts the entry and navigates to it', async () => {
    const fx = await fixture([10, 20]);
    const { w, posted } = worker((_m, reply) => {
      reply({ type: 'registered' });
    });
    const sw = container(registration(w));
    const env = deps({ serviceWorker: sw });
    w.setPorts(env.ports);
    const dl = new E2EDownloader(env.d);
    const done = dl.downloadFile(fx.key, file(fx.files[0]!, 'a/b?.txt'));
    await vi.waitFor(() => expect(env.navigations).toHaveLength(1));
    expect(env.navigations[0]).toBe(`${SW_SCOPE}BwcHBwcHBwcHBwcHBwcHBw`);
    expect(posted[0]!.msg).toEqual({
      type: 'register',
      id: 'BwcHBwcHBwcHBwcHBwcHBw',
      entry: { kind: 'file', file: { ...file(fx.files[0]!), key: fx.key, name: 'file' } },
    });
    expect(posted[0]!.transfer).toHaveLength(1);
    env.ports[0]!.onmessage?.({ data: { type: 'started' } });
    expect(env.timers.size).toBe(0);
    env.ports[0]!.onmessage?.({ data: { type: 'done' } });
    await done;
    expect(env.ports[0]!.close).toHaveBeenCalled();

    const archive = dl.downloadArchive(fx.key, [file(fx.files[0]!, 'd/a'), file(fx.files[1]!, 'b')]);
    await vi.waitFor(() => expect(env.navigations).toHaveLength(2));
    expect(posted[1]!.msg.entry).toMatchObject({ kind: 'archive', name: 'transfer.zip' });
    env.ports[1]!.onmessage?.({ data: { type: 'done' } });
    await archive;
    expect(sw.register).toHaveBeenCalledTimes(1);
    expect(sw.register).toHaveBeenCalledWith(SW_URL, { scope: SW_SCOPE });
  });

  it('reports the failures of the worker', async () => {
    const fx = await fixture([10]);
    for (const [reply, code] of [
      [{ type: 'rejected' }, 'corrupt'],
      [{ type: 'failed', code: 'unavailable' }, 'unavailable'],
      [{ type: 'failed', code: 'cancelled' }, 'cancelled'],
    ] as [SwReply, string][]) {
      const { w } = worker((_m, r) => r(reply));
      const env = deps({ serviceWorker: container(registration(w)) });
      w.setPorts(env.ports);
      expect(await codeOf(new E2EDownloader(env.d).downloadFile(fx.key, file(fx.files[0]!)))).toBe(code);
    }
  });

  it('gives up when the worker does not start the download', async () => {
    const fx = await fixture([10]);
    const { w } = worker((_m, r) => r({ type: 'registered' }));
    const env = deps({ serviceWorker: container(registration(w)) });
    w.setPorts(env.ports);
    const p = new E2EDownloader(env.d).downloadFile(fx.key, file(fx.files[0]!));
    await vi.waitFor(() => expect(env.timers.size).toBe(1));
    env.fire();
    // Unavailable: the page reloads the transfer (the access may have expired meanwhile).
    expect(await codeOf(p)).toBe('unavailable');
    expect(START_TIMEOUT_MS).toBe(30_000);
  });

  it('serializes the downloads: the next one navigates only once the previous one started or failed', async () => {
    const fx = await fixture([10, 20]);
    const { w, posted } = worker((_m, reply) => reply({ type: 'registered' }));
    const env = deps({ serviceWorker: container(registration(w)) });
    w.setPorts(env.ports);
    const dl = new E2EDownloader(env.d);
    const started: string[] = [];
    const first = dl.downloadFile(fx.key, file(fx.files[0]!), { onStarted: () => started.push('first') });
    const second = dl.downloadFile(fx.key, file(fx.files[1]!), { onStarted: () => started.push('second') });
    const third = dl.downloadArchive(fx.key, [file(fx.files[0]!)], 'x.zip', {
      onStarted: () => started.push('third'),
    });
    await vi.waitFor(() => expect(env.navigations).toHaveLength(1));
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(posted).toHaveLength(1);
    env.ports[0]!.onmessage?.({ data: { type: 'started' } });
    env.ports[0]!.onmessage?.({ data: { type: 'started' } });
    expect(started).toEqual(['first']);
    await vi.waitFor(() => expect(env.navigations).toHaveLength(2));
    // The second fails before it starts: the third goes on.
    env.ports[1]!.onmessage?.({ data: { type: 'failed', code: 'network' } });
    expect(await codeOf(second)).toBe('network');
    await vi.waitFor(() => expect(env.navigations).toHaveLength(3));
    env.ports[2]!.onmessage?.({ data: { type: 'started' } });
    env.ports[2]!.onmessage?.({ data: { type: 'done' } });
    env.ports[0]!.onmessage?.({ data: { type: 'done' } });
    await Promise.all([first, third]);
    expect(started).toEqual(['first', 'third']);
  });

  it('waits for an installing worker to activate', async () => {
    const fx = await fixture([10]);
    const { w } = worker((_m, r) => r({ type: 'done' }), 'installing');
    const env = deps({ serviceWorker: container(registration(w, 'installing')) });
    w.setPorts(env.ports);
    const p = new E2EDownloader(env.d).downloadFile(fx.key, file(fx.files[0]!));
    await vi.waitFor(() => expect(env.timers.size).toBe(1));
    w.change('installed');
    expect(env.timers.size).toBe(1);
    w.change('activated');
    await p;
    expect(env.timers.size).toBe(0);
  });
});

describe('E2EDownloader in memory', () => {
  async function memory(sizes: number[], fetchFn?: (files: EncryptedFile[]) => FetchLike) {
    const fx = await fixture(sizes);
    const env = deps({ fetch: fetchFn ? fetchFn(fx.files) : fakeServer(fx.files) });
    return { fx, env, dl: new E2EDownloader(env.d) };
  }

  it('decrypts a file and an archive without Service Worker', async () => {
    const { fx, env, dl } = await memory([150_000, 3]);
    await dl.downloadFile(fx.key, file(fx.files[0]!, 'été.pdf'));
    expect(env.saved[0]!.name).toBe('été.pdf');
    expect(env.saved[0]!.blob.type).toBe('application/octet-stream');
    const got = new Uint8Array(await env.saved[0]!.blob.arrayBuffer());
    expect(firstDifference(got, fx.files[0]!.plain)).toBe(-1);

    await dl.downloadArchive(
      fx.key,
      [file(fx.files[0]!, 'd/a.bin'), file(fx.files[1]!, 'b.bin')],
      'x<y>.zip',
    );
    expect(env.saved[1]!.name).toBe('x_y_.zip');
    const entries = readZip(new Uint8Array(await env.saved[1]!.blob.arrayBuffer()));
    expect(entries.map((e) => e.name)).toEqual(['d/a.bin', 'b.bin']);
    expect(firstDifference(entries[1]!.data, fx.files[1]!.plain)).toBe(-1);
  });

  it('falls back when the registration fails or the worker never activates', async () => {
    const fx = await fixture([10]);
    const failing = { register: vi.fn(() => Promise.reject(new Error('SecurityError'))) };
    const env = deps({ serviceWorker: failing, fetch: fakeServer(fx.files) });
    await new E2EDownloader(env.d).downloadFile(fx.key, file(fx.files[0]!));
    expect(env.saved).toHaveLength(1);

    const none = deps({
      serviceWorker: container(registration(null as unknown as WorkerLike)),
      fetch: fakeServer(fx.files),
    });
    await new E2EDownloader(none.d).downloadFile(fx.key, file(fx.files[0]!));
    expect(none.saved).toHaveLength(1);

    const { w } = worker(() => undefined, 'installing');
    const slow = deps({ serviceWorker: container(registration(w, 'waiting')), fetch: fakeServer(fx.files) });
    const p = new E2EDownloader(slow.d).downloadFile(fx.key, file(fx.files[0]!));
    await vi.waitFor(() => expect(slow.timers.size).toBe(1));
    slow.fire();
    await p;
    expect(slow.saved).toHaveLength(1);
    expect(ACTIVATION_TIMEOUT_MS).toBeGreaterThan(0);

    const { w: dead } = worker(() => undefined, 'installing');
    const redundant = deps({
      serviceWorker: container(registration(dead, 'installing')),
      fetch: fakeServer(fx.files),
    });
    const q = new E2EDownloader(redundant.d).downloadFile(fx.key, file(fx.files[0]!));
    await vi.waitFor(() => expect(redundant.timers.size).toBe(1));
    dead.change('redundant');
    await q;
    expect(redundant.saved).toHaveLength(1);
  });

  it('reports the start of a download in memory and serializes them', async () => {
    const { fx, env, dl } = await memory([10, 20]);
    const events: string[] = [];
    await Promise.all([
      dl.downloadFile(fx.key, file(fx.files[0]!), { onStarted: () => events.push('a') }),
      dl.downloadArchive(fx.key, [file(fx.files[1]!)], undefined, { onStarted: () => events.push('b') }),
    ]);
    expect(events).toEqual(['a', 'b']);
    expect(env.saved.map((x) => x.name)).toEqual(['f0.bin', 'transfer.zip']);
  });

  it('caps the ciphertext read in memory at the largest valid stream size', async () => {
    let pulled = 0;
    const { fx, dl } = await memory([100], (files) =>
      fakeServer(files, {
        [files[0]!.url]: async () =>
          new Response(
            new ReadableStream<Uint8Array>({
              pull(c) {
                // An endless answer: the cap must stop reading it.
                pulled += 1000;
                c.enqueue(new Uint8Array(1000));
              },
            }),
            { headers: { 'Content-Type': 'application/octet-stream' } },
          ),
      }),
    );
    expect(await codeOf(dl.downloadFile(fx.key, file(fx.files[0]!)))).toBe('corrupt');
    expect(pulled).toBeLessThan(100_000);
  });

  it('errors a stream longer than its cap', async () => {
    const out = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(new Uint8Array(6));
        c.enqueue(new Uint8Array(6));
        c.close();
      },
    }).pipeThrough(byteCap(10));
    const reader = out.getReader();
    expect((await reader.read()).value).toHaveLength(6);
    await expect(reader.read()).rejects.toMatchObject({ code: 'corrupt' });
    const exact = new Response(new Blob([new Uint8Array(10)]).stream().pipeThrough(byteCap(10)));
    expect((await exact.arrayBuffer()).byteLength).toBe(10);
  });

  it('refuses archive entry names the Service Worker would refuse', async () => {
    const { fx, dl, env } = await memory([10, 10]);
    for (const names of [
      ['a', 'A'],
      ['../a', 'b'],
      ['', 'b'],
    ]) {
      const files = names.map((n, i) => file(fx.files[i]!, n));
      expect(await codeOf(dl.downloadArchive(fx.key, files))).toBe('corrupt');
    }
    expect(await codeOf(dl.downloadArchive(fx.key, []))).toBe('corrupt');
    expect(env.saved).toHaveLength(0);
  });

  it('refuses what is too large for memory', async () => {
    const { fx, dl, env } = await memory([10, 10]);
    const big = { ...file(fx.files[0]!), size: MEMORY_LIMIT + 1 };
    expect(await codeOf(dl.downloadFile(fx.key, big))).toBe('unsupported-browser');
    const half = { ...file(fx.files[0]!), size: MEMORY_LIMIT / 2 + 1 };
    expect(await codeOf(dl.downloadArchive(fx.key, [half, { ...half, name: 'b' }]))).toBe(
      'unsupported-browser',
    );
    expect(env.saved).toHaveLength(0);
  });

  it('classifies the failures', async () => {
    const { fx, dl } = await memory([100]);
    const f = file(fx.files[0]!);
    expect(await codeOf(dl.downloadFile(fx.key, { ...f, sha256: '0'.repeat(64) }))).toBe('corrupt');
    expect(await codeOf(dl.downloadFile(fx.key, { ...f, size: 99 }))).toBe('corrupt');
    expect(await codeOf(dl.downloadFile(fx.key, { ...f, index: 3 }))).toBe('corrupt');
    expect(await codeOf(dl.downloadFile(fx.key, { ...f, url: '/api/v1/downloads/dl_x/files/none' }))).toBe(
      'unavailable',
    );
    const broken = await memory([100], (files) =>
      fakeServer(files, {
        [files[0]!.url]: async () =>
          new Response(
            new ReadableStream({
              pull: (c) => c.error(new TypeError('connection reset')),
            }),
            { headers: { 'Content-Type': 'application/octet-stream' } },
          ),
      }),
    );
    expect(await codeOf(broken.dl.downloadFile(broken.fx.key, file(broken.fx.files[0]!)))).toBe('network');
    // An unexpected error (here from saveBlob) is reported as network.
    const env = deps({
      fetch: fakeServer(fx.files),
      saveBlob: () => {
        throw new Error('boom');
      },
    });
    expect(await codeOf(new E2EDownloader(env.d).downloadFile(fx.key, f))).toBe('network');
  });

  it('has an error with a stable code', () => {
    expect(new E2EDownloadError('network').message).toBe('e2e download: network');
    expect(new E2EDownloadError('corrupt', 'x').message).toBe('e2e download: corrupt: x');
  });
});

describe('browserDeps', () => {
  it('uses the browser APIs', async () => {
    const assign = vi.fn();
    const click = vi.fn();
    const a = { click, remove: vi.fn(), href: '', download: '', hidden: false };
    const append = vi.fn();
    const created = vi.fn(() => 'blob:x');
    const revoked = vi.fn();
    const timers: (() => void)[] = [];
    const sw = { register: vi.fn() };
    vi.stubGlobal('navigator', { serviceWorker: sw });
    vi.stubGlobal('window', {
      location: { assign },
      setTimeout: (h: () => void) => timers.push(h),
      clearTimeout: vi.fn(),
    });
    vi.stubGlobal('document', { createElement: () => a, body: { append } });
    const realURL = URL;
    vi.stubGlobal(
      'URL',
      Object.assign(class extends realURL {}, { createObjectURL: created, revokeObjectURL: revoked }),
    );
    const fetchSpy = vi.fn(async () => new Response('x'));
    vi.stubGlobal('fetch', fetchSpy);
    try {
      const d = browserDeps();
      expect(d.serviceWorker).toBe(sw);
      d.navigate('/e2e/x');
      expect(assign).toHaveBeenCalledWith('/e2e/x');
      d.saveBlob(new Blob(['x']), 'a.txt');
      expect(a).toMatchObject({ href: 'blob:x', download: 'a.txt', hidden: true });
      expect(click).toHaveBeenCalled();
      timers[0]!();
      expect(revoked).toHaveBeenCalledWith('blob:x');
      await d.fetch('/u', {});
      expect(fetchSpy).toHaveBeenCalledWith('/u', {});
      expect(d.random()).toHaveLength(16);
      const ch = d.channel();
      expect(ch.port1).toBeDefined();
      ch.port1.close();
      d.setTimeout(() => undefined, 1);
      d.clearTimeout(1);
      vi.stubGlobal('navigator', {});
      expect(browserDeps().serviceWorker).toBeUndefined();
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
