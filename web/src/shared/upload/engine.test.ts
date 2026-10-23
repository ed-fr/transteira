import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  classifyStatus,
  conflictDelay,
  createUploadEngine,
  fatalCode,
  retryDelay,
  UploadError,
  type UploadAnnouncement,
  type UploadEngineDeps,
  type UploadFileSpec,
  type UploadSnapshot,
} from './engine';
import { content, FakeServer } from './fake-transport.test-helper';

const CHUNK = 10;

function blob(n: number, seed = 1): Blob {
  return new Blob([content(n, seed) as BlobPart]);
}

interface Harness {
  server: FakeServer;
  cancelTransfer: ReturnType<typeof vi.fn>;
  online: () => void;
  announcements: UploadAnnouncement[];
  snapshots: UploadSnapshot[];
  engine: ReturnType<typeof createUploadEngine>;
}

function setup(
  sizes: number[],
  opts: { offsets?: (number | undefined)[]; deps?: Partial<UploadEngineDeps>; server?: FakeServer } = {},
): Harness {
  const server = opts.server ?? new FakeServer();
  const specs: UploadFileSpec[] = sizes.map((size, i) => {
    const url = `/api/v1/uploads/u${i}`;
    if (!server.uploads.has(url)) server.add(url, size);
    const spec: UploadFileSpec = { name: `f${i}.bin`, file: blob(size, i + 1), uploadUrl: url };
    const offset = opts.offsets?.[i];
    if (offset !== undefined) spec.offset = offset;
    return spec;
  });
  let onlineListener: (() => void) | undefined;
  const cancelTransfer = vi.fn(async () => {});
  const engine = createUploadEngine(specs, {
    transport: server,
    cancelTransfer,
    chunkSize: CHUNK,
    onOnline: (listener) => {
      onlineListener = listener;
      return () => {
        onlineListener = undefined;
      };
    },
    ...opts.deps,
  });
  const announcements: UploadAnnouncement[] = [];
  const snapshots: UploadSnapshot[] = [];
  engine.onAnnounce((a) => announcements.push(a));
  engine.subscribe((s) => snapshots.push(s));
  return { server, cancelTransfer, online: () => onlineListener?.(), announcements, snapshots, engine };
}

const tick = async (ms = 0): Promise<void> => {
  await vi.advanceTimersByTimeAsync(ms);
};

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('pure helpers', () => {
  it('maps fatal statuses to codes', () => {
    expect(fatalCode(401)).toBe('unauthenticated');
    expect(fatalCode(403)).toBe('forbidden');
    expect(fatalCode(404)).toBe('upload-gone');
    expect(fatalCode(410)).toBe('upload-gone');
    expect(fatalCode(413)).toBe('payload-too-large');
    expect(fatalCode(507)).toBe('insufficient-storage');
    expect(fatalCode(415)).toBe('protocol-error');
  });

  it('classifies statuses', () => {
    expect(classifyStatus(409)).toBe('conflict');
    expect(classifyStatus(400)).toBe('conflict');
    expect(classifyStatus(429)).toBe('wait');
    expect(classifyStatus(503)).toBe('wait');
    expect(classifyStatus(408)).toBe('retry');
    expect(classifyStatus(500)).toBe('retry');
    expect(classifyStatus(502)).toBe('retry');
    expect(classifyStatus(507)).toBe('fatal');
    expect(classifyStatus(401)).toBe('fatal');
    expect(classifyStatus(412)).toBe('fatal');
  });

  it('computes conflict delays capped at 10 s', () => {
    expect([0, 1, 2, 3, 4, 5, 9].map(conflictDelay)).toEqual([1000, 1000, 2000, 4000, 8000, 10000, 10000]);
  });

  it('computes exponential retry delays capped at 30 s', () => {
    expect([1, 2, 3, 4, 5, 6, 7, 10].map(retryDelay)).toEqual([
      1000, 2000, 4000, 8000, 16000, 30000, 30000, 30000,
    ]);
    expect(retryDelay(0)).toBe(1000);
  });

  it('builds UploadError messages', () => {
    expect(new UploadError('forbidden', 403).message).toBe('forbidden (HTTP 403)');
    expect(new UploadError('file-missing').message).toBe('file-missing');
    expect(new UploadError('file-missing').status).toBeUndefined();
  });
});

describe('upload engine', () => {
  it('uploads several files sequentially in chunks and reports progress', async () => {
    const h = setup([25, 0, 12], { offsets: [0, 0, undefined] });
    expect(h.engine.getSnapshot()).toMatchObject({ phase: 'idle', totalBytes: 37, uploadedBytes: 0 });
    expect(h.engine.isActive()).toBe(false);
    const done = h.engine.start();
    expect(h.engine.start()).toBe(done);
    expect(h.engine.isActive()).toBe(true);
    await expect(done).resolves.toBe('completed');

    expect(h.server.calls).toEqual([
      'PATCH /api/v1/uploads/u0 0 10',
      'PATCH /api/v1/uploads/u0 10 10',
      'PATCH /api/v1/uploads/u0 20 5',
      'HEAD /api/v1/uploads/u2',
      'PATCH /api/v1/uploads/u2 0 10',
      'PATCH /api/v1/uploads/u2 10 2',
    ]);
    expect(h.server.bytes('/api/v1/uploads/u0')).toEqual(content(25, 1));
    expect(h.server.bytes('/api/v1/uploads/u2')).toEqual(content(12, 3));
    const last = h.engine.getSnapshot();
    expect(last).toMatchObject({ phase: 'completed', uploadedBytes: 37, percent: 100, currentIndex: 3 });
    expect(last.files.every((f) => f.done)).toBe(true);
    expect(h.engine.isActive()).toBe(false);

    // Progress is monotonic and includes the bytes of the request in flight.
    const bytes = h.snapshots.map((s) => s.uploadedBytes);
    expect(bytes).toEqual([...bytes].sort((a, b) => a - b));
    expect(bytes).toContain(5);

    expect(h.announcements.filter((a) => a.kind !== 'progress')).toEqual([
      { kind: 'file-done', index: 0, name: 'f0.bin' },
      { kind: 'file-done', index: 1, name: 'f1.bin' },
      { kind: 'file-done', index: 2, name: 'f2.bin' },
      { kind: 'completed' },
    ]);
    const percents = h.announcements.flatMap((a) => (a.kind === 'progress' ? [a.percent] : []));
    // At most one announcement per 10 % step, never 100 (completed says it).
    expect(new Set(percents.map((p) => Math.floor(p / 10))).size).toBe(percents.length);
    expect(percents.every((p) => p < 100)).toBe(true);
  });

  it('completes an empty transfer at 100 %', async () => {
    const h = setup([0], { offsets: [0] });
    expect(h.engine.getSnapshot().percent).toBe(100);
    await expect(h.engine.start()).resolves.toBe('completed');
    expect(h.server.calls).toEqual([]);
  });

  it('resumes from the server offset after a cut in the middle of a chunk', async () => {
    const h = setup([30], { offsets: [0] });
    h.server.patchFaults.push({ kind: 'ok' }, { kind: 'cut', keep: 4 });
    const done = h.engine.start();
    await tick();
    expect(h.engine.getSnapshot().phase).toBe('retrying');
    expect(h.engine.getSnapshot().retryAt).toBe(Date.now() + 1000);
    expect(h.engine.getSnapshot().uploadedBytes).toBe(10);
    await tick(1000);
    await expect(done).resolves.toBe('completed');
    expect(h.server.calls).toEqual([
      'PATCH /api/v1/uploads/u0 0 10',
      'PATCH /api/v1/uploads/u0 10 10',
      'HEAD /api/v1/uploads/u0',
      'PATCH /api/v1/uploads/u0 14 10',
      'PATCH /api/v1/uploads/u0 24 6',
    ]);
    expect(h.server.bytes('/api/v1/uploads/u0')).toEqual(content(30, 1));
  });

  it('aborts a stalled request after 45 s, asks the server and resumes', async () => {
    const h = setup([20], { offsets: [0] });
    h.server.patchFaults.push({ kind: 'stall', keep: 3 });
    const done = h.engine.start();
    await tick(44_999);
    expect(h.engine.getSnapshot()).toMatchObject({ phase: 'uploading', uploadedBytes: 3 });
    await tick(1);
    expect(h.engine.getSnapshot()).toMatchObject({ phase: 'retrying', uploadedBytes: 0, failures: 1 });
    await tick(1000);
    await expect(done).resolves.toBe('completed');
    expect(h.server.calls).toEqual([
      'PATCH /api/v1/uploads/u0 0 10',
      'HEAD /api/v1/uploads/u0',
      'PATCH /api/v1/uploads/u0 3 10',
      'PATCH /api/v1/uploads/u0 13 7',
    ]);
  });

  it('re-arms the watchdog on every progress event', async () => {
    const h = setup([10], { offsets: [0] });
    h.server.patchFaults.push({
      kind: 'steps',
      steps: [
        [40_000, 2],
        [40_000, 6],
        [40_000, 10],
      ],
    });
    const done = h.engine.start();
    await tick(120_000);
    await expect(done).resolves.toBe('completed');
    expect(h.server.calls).toEqual(['PATCH /api/v1/uploads/u0 0 10']);
  });

  it('applies the stall watchdog to HEAD requests', async () => {
    const h = setup([5]);
    h.server.headFaults.push({ kind: 'stall', keep: 0 });
    const done = h.engine.start();
    await tick(45_000);
    expect(h.engine.getSnapshot().phase).toBe('retrying');
    await tick(1000);
    await expect(done).resolves.toBe('completed');
    expect(h.server.calls.filter((c) => c.startsWith('HEAD'))).toHaveLength(2);
  });

  it('asks the server after a 409 offset conflict and resumes after 1 s', async () => {
    // The server already holds 10 bytes (a previous answer was lost).
    const h2 = setup([20], { offsets: [0] });
    const u = h2.server.uploads.get('/api/v1/uploads/u0');
    if (u === undefined) throw new Error('missing');
    u.offset = 10;
    u.data.set(content(20, 1).slice(0, 10));
    const done = h2.engine.start();
    await tick();
    expect(h2.engine.getSnapshot()).toMatchObject({ phase: 'retrying', failures: 0 });
    await tick(1000);
    await expect(done).resolves.toBe('completed');
    expect(h2.server.calls).toEqual([
      'PATCH /api/v1/uploads/u0 0 10',
      'HEAD /api/v1/uploads/u0',
      'PATCH /api/v1/uploads/u0 10 10',
    ]);
    expect(h2.server.bytes('/api/v1/uploads/u0')).toEqual(content(20, 1));
  });

  it('backs off on repeated lock conflicts without pausing while the server holds the lock', async () => {
    const h = setup([10], { offsets: [0] });
    for (let i = 0; i < 8; i++) h.server.patchFaults.push({ kind: 'status', status: 409 });
    const done = h.engine.start();
    await tick();
    const delays = [1000, 2000, 4000, 8000, 10000, 10000, 10000, 10000];
    for (const d of delays) {
      expect(h.engine.getSnapshot()).toMatchObject({ phase: 'retrying', failures: 0 });
      expect(h.engine.getSnapshot().retryAt).toBe(Date.now() + d);
      await tick(d);
    }
    await expect(done).resolves.toBe('completed');
    expect(h.announcements).not.toContainEqual({ kind: 'paused', reason: 'failures' });
    // PATCH 409 then HEAD for each conflict, then the successful PATCH.
    expect(h.server.calls.filter((c) => c.startsWith('PATCH'))).toHaveLength(9);
  });

  it('counts conflicts as failures once the conflict budget is spent', async () => {
    const h = setup([10], { offsets: [0], deps: { conflictBudgetMs: 5_000, maxFailures: 3 } });
    for (let i = 0; i < 20; i++) h.server.patchFaults.push({ kind: 'status', status: 409 });
    void h.engine.start();
    await tick(); // conflict 1 at 0 s
    await tick(1000); // conflict 2 at 1 s
    await tick(2000); // conflict 3 at 3 s
    expect(h.engine.getSnapshot().failures).toBe(0);
    await tick(4000); // conflict 4 at 7 s: counted
    expect(h.engine.getSnapshot().failures).toBe(1);
    await tick(8000);
    await tick(10000);
    expect(h.engine.getSnapshot()).toMatchObject({ phase: 'paused', pauseReason: 'failures', failures: 3 });
    // resume() starts a new streak.
    h.engine.resume();
    await tick();
    expect(h.engine.getSnapshot()).toMatchObject({ phase: 'retrying', failures: 0 });
    h.engine.stop();
  });

  it('treats a 204 that does not advance as a conflict', async () => {
    const h = setup([10], { offsets: [0] });
    h.server.patchFaults.push({ kind: 'status', status: 204, offset: 0 });
    await expect(h.engine.start()).resolves.toBe('completed');
    expect(h.server.calls).toEqual([
      'PATCH /api/v1/uploads/u0 0 10',
      'HEAD /api/v1/uploads/u0',
      'PATCH /api/v1/uploads/u0 0 10',
    ]);
  });

  it('accepts a 204 without Upload-Offset', async () => {
    const h = setup([10], { offsets: [0] });
    const original = h.server.patch.bind(h.server);
    h.server.patch = async (...args) => {
      const r = await original(...args);
      return { status: r.status };
    };
    await expect(h.engine.start()).resolves.toBe('completed');
    expect(h.engine.getSnapshot().uploadedBytes).toBe(10);
  });

  it('honours Retry-After on 429 without counting a failure', async () => {
    const h = setup([10], { offsets: [0] });
    h.server.patchFaults.push({ kind: 'status', status: 429, retryAfter: 7 });
    const done = h.engine.start();
    await tick();
    expect(h.engine.getSnapshot()).toMatchObject({ phase: 'retrying', failures: 0 });
    await tick(6_999);
    expect(h.server.calls).toHaveLength(1);
    await tick(1);
    await expect(done).resolves.toBe('completed');
  });

  it('honours Retry-After on HEAD and falls back to the backoff delay without it', async () => {
    const h = setup([10]);
    h.server.headFaults.push({ kind: 'status', status: 503, retryAfter: 3 }, { kind: 'status', status: 429 });
    const done = h.engine.start();
    await tick(2_999);
    expect(h.server.calls).toHaveLength(1);
    await tick(1);
    expect(h.server.calls).toHaveLength(2);
    await tick(1000);
    await expect(done).resolves.toBe('completed');
  });

  it('backs off exponentially, then pauses after 10 failures without progress', async () => {
    const h = setup([10], { offsets: [0] });
    for (let i = 0; i < 10; i++) h.server.patchFaults.push({ kind: 'status', status: 500 });
    const done = h.engine.start();
    await tick();
    const delays = [1000, 2000, 4000, 8000, 16000, 30000, 30000, 30000, 30000];
    for (const d of delays) {
      expect(h.engine.getSnapshot().phase).toBe('retrying');
      expect(h.engine.getSnapshot().retryAt).toBe(Date.now() + d);
      await tick(d);
      // HEAD then PATCH (500 again)
    }
    expect(h.engine.getSnapshot()).toMatchObject({ phase: 'paused', pauseReason: 'failures', failures: 10 });
    expect(h.announcements).toContainEqual({ kind: 'paused', reason: 'failures' });
    expect(h.engine.isActive()).toBe(true);
    await tick(600_000);
    expect(h.engine.getSnapshot().phase).toBe('paused');
    h.engine.resume();
    expect(h.engine.getSnapshot()).toMatchObject({ phase: 'uploading', failures: 0 });
    await tick();
    await expect(done).resolves.toBe('completed');
  });

  it('resets the failure counter when the server confirms progress', async () => {
    const h = setup([30], { offsets: [0] });
    h.server.patchFaults.push({ kind: 'status', status: 502 }, { kind: 'cut', keep: 5 });
    const done = h.engine.start();
    await tick();
    expect(h.engine.getSnapshot().failures).toBe(1);
    await tick(1000); // HEAD (offset 0), PATCH cut after 5 bytes
    expect(h.engine.getSnapshot().failures).toBe(2);
    expect(h.engine.getSnapshot().retryAt).toBe(Date.now() + 2000);
    await tick(2000); // HEAD reveals 5 bytes: progress
    await expect(done).resolves.toBe('completed');
    expect(h.engine.getSnapshot().failures).toBe(0);
  });

  it('retries at once on the online event and on resume() while waiting', async () => {
    const h = setup([10], { offsets: [0] });
    h.server.patchFaults.push(
      { kind: 'cut', keep: 0 },
      { kind: 'status', status: 503 },
      { kind: 'cut', keep: 0 },
    );
    const done = h.engine.start();
    await tick();
    expect(h.engine.getSnapshot().phase).toBe('retrying');
    h.online();
    await tick();
    // 503 without Retry-After: waits retryDelay(2)
    expect(h.engine.getSnapshot().phase).toBe('retrying');
    h.engine.resume();
    await tick();
    expect(h.engine.getSnapshot().phase).toBe('retrying');
    h.online();
    await tick();
    await expect(done).resolves.toBe('completed');
    // online while not retrying is ignored
    h.online();
  });

  it('pauses on demand, aborting the request, and resumes from the server offset', async () => {
    const h = setup([20], { offsets: [0] });
    h.server.patchFaults.push({ kind: 'stall', keep: 4 });
    const done = h.engine.start();
    await tick(100);
    expect(h.engine.getSnapshot().uploadedBytes).toBe(4);
    h.engine.pause();
    expect(h.engine.getSnapshot()).toMatchObject({ phase: 'paused', pauseReason: 'user', uploadedBytes: 0 });
    expect(h.announcements).toContainEqual({ kind: 'paused', reason: 'user' });
    h.engine.pause(); // no-op
    await tick(100_000);
    expect(h.server.calls).toHaveLength(1);
    h.engine.resume();
    await tick();
    await expect(done).resolves.toBe('completed');
    expect(h.server.calls).toEqual([
      'PATCH /api/v1/uploads/u0 0 10',
      'HEAD /api/v1/uploads/u0',
      'PATCH /api/v1/uploads/u0 4 10',
      'PATCH /api/v1/uploads/u0 14 6',
    ]);
    expect(h.server.bytes('/api/v1/uploads/u0')).toEqual(content(20, 1));
  });

  it('pauses while waiting for a retry', async () => {
    const h = setup([10], { offsets: [0] });
    h.server.patchFaults.push({ kind: 'status', status: 500 });
    const done = h.engine.start();
    await tick();
    h.engine.pause();
    expect(h.engine.getSnapshot().retryAt).toBeUndefined();
    await tick(10_000);
    expect(h.server.calls).toHaveLength(1);
    h.engine.resume();
    await tick();
    await expect(done).resolves.toBe('completed');
  });

  it('ignores pause and resume when idle or finished', async () => {
    const h = setup([5], { offsets: [0] });
    h.engine.pause();
    h.engine.resume();
    expect(h.engine.getSnapshot().phase).toBe('idle');
    await h.engine.start();
    h.engine.pause();
    h.engine.resume();
    expect(h.engine.getSnapshot().phase).toBe('completed');
  });

  it.each([
    [401, 'unauthenticated'],
    [403, 'forbidden'],
    [404, 'upload-gone'],
    [410, 'upload-gone'],
    [413, 'payload-too-large'],
    [507, 'insufficient-storage'],
    [415, 'protocol-error'],
  ] as const)('fails on PATCH %i with %s', async (status, code) => {
    const h = setup([10], { offsets: [0] });
    h.server.patchFaults.push({ kind: 'status', status });
    const done = h.engine.start();
    await expect(done).rejects.toMatchObject({ name: 'UploadError', code, status });
    expect(h.engine.getSnapshot()).toMatchObject({ phase: 'failed', error: { code } });
    expect(h.announcements).toContainEqual({ kind: 'error', code });
    expect(h.engine.isActive()).toBe(false);
  });

  it('fails on a fatal HEAD status and on a HEAD without Upload-Offset', async () => {
    const h = setup([10]);
    h.server.headFaults.push({ kind: 'status', status: 410 });
    await expect(h.engine.start()).rejects.toMatchObject({ code: 'upload-gone' });

    const h2 = setup([10]);
    h2.server.headFaults.push({ kind: 'status', status: 200 });
    await expect(h2.engine.start()).rejects.toMatchObject({ code: 'protocol-error', status: 200 });
  });

  it('retries a HEAD network error', async () => {
    const h = setup([10]);
    h.server.headFaults.push({ kind: 'cut', keep: 0 }, { kind: 'status', status: 409 });
    const done = h.engine.start();
    await tick(2000);
    await expect(done).resolves.toBe('completed');
    expect(h.server.calls.filter((c) => c.startsWith('HEAD'))).toHaveLength(3);
  });

  it('fails with file-missing when content is needed but absent', async () => {
    const server = new FakeServer();
    server.add('/api/v1/uploads/u', 10, 4);
    const engine = createUploadEngine([{ name: 'a', size: 10, uploadUrl: '/api/v1/uploads/u' }], {
      transport: server,
      cancelTransfer: async () => {},
      onOnline: () => () => {},
    });
    await expect(engine.start()).rejects.toMatchObject({ code: 'file-missing' });
  });

  it('skips files already complete without content', async () => {
    const server = new FakeServer();
    server.add('/api/v1/uploads/v', 0);
    const engine = createUploadEngine(
      [
        { name: 'a', size: 10, uploadUrl: '/api/v1/uploads/u', offset: 10 },
        { name: 'b', uploadUrl: '/api/v1/uploads/v' },
      ],
      {
        transport: server,
        cancelTransfer: async () => {},
        onOnline: () => () => {},
      },
    );
    await expect(engine.start()).resolves.toBe('completed');
    expect(engine.getSnapshot()).toMatchObject({ totalBytes: 10, uploadedBytes: 10 });
    expect(server.calls).toEqual(['HEAD /api/v1/uploads/v']);
  });

  it('wraps unexpected exceptions as protocol errors', async () => {
    const h = setup([10], { offsets: [0] });
    const blobWithBrokenSlice = {
      size: 10,
      slice: () => {
        throw new Error('boom');
      },
    } as unknown as Blob;
    const engine = createUploadEngine(
      [{ name: 'x', file: blobWithBrokenSlice, uploadUrl: '/api/v1/uploads/u0', offset: 0 }],
      {
        transport: h.server,
        cancelTransfer: async () => {},
        onOnline: () => () => {},
      },
    );
    await expect(engine.start()).rejects.toMatchObject({ code: 'protocol-error' });
  });

  it('cancels: aborts the request, abandons the transfer and resolves cancelled', async () => {
    const h = setup([20], { offsets: [0] });
    h.server.patchFaults.push({ kind: 'stall', keep: 2 });
    const done = h.engine.start();
    await tick(10);
    await h.engine.cancel();
    await expect(done).resolves.toBe('cancelled');
    expect(h.cancelTransfer).toHaveBeenCalledOnce();
    expect(h.engine.getSnapshot()).toMatchObject({ phase: 'cancelled', uploadedBytes: 0 });
    expect(h.announcements).toContainEqual({ kind: 'cancelled' });
    await tick(100_000);
    expect(h.server.calls).toHaveLength(1);
    await h.engine.cancel();
    expect(h.cancelTransfer).toHaveBeenCalledOnce();
  });

  it('cancels after a fatal error and does nothing once completed', async () => {
    const h = setup([10], { offsets: [0] });
    h.server.patchFaults.push({ kind: 'status', status: 413 });
    await expect(h.engine.start()).rejects.toBeInstanceOf(UploadError);
    await h.engine.cancel();
    expect(h.cancelTransfer).toHaveBeenCalledOnce();

    const h2 = setup([10], { offsets: [0] });
    await h2.engine.start();
    await h2.engine.cancel();
    expect(h2.cancelTransfer).not.toHaveBeenCalled();
  });

  it('stops without abandoning the transfer', async () => {
    const h = setup([20], { offsets: [0] });
    h.server.patchFaults.push({ kind: 'stall', keep: 2 });
    const done = h.engine.start();
    await tick(10);
    h.engine.stop();
    await expect(done).resolves.toBe('cancelled');
    expect(h.cancelTransfer).not.toHaveBeenCalled();
    expect(h.engine.getSnapshot()).toMatchObject({ phase: 'cancelled', uploadedBytes: 0 });
    expect(h.engine.isActive()).toBe(false);
    expect(h.announcements).not.toContainEqual({ kind: 'cancelled' });
    await tick(100_000);
    expect(h.server.calls).toHaveLength(1);
    h.engine.stop();
    expect(h.engine.getSnapshot().phase).toBe('cancelled');
  });

  it('stops while waiting for a retry, and does nothing once finished', async () => {
    const h = setup([10], { offsets: [0] });
    h.server.patchFaults.push({ kind: 'status', status: 500 });
    void h.engine.start();
    await tick();
    expect(h.engine.getSnapshot().phase).toBe('retrying');
    h.engine.stop();
    await tick(60_000);
    expect(h.server.calls).toHaveLength(1);

    const h2 = setup([10], { offsets: [0] });
    await h2.engine.start();
    h2.engine.stop();
    expect(h2.engine.getSnapshot().phase).toBe('completed');
  });

  it('refuses an unsafe upload URL before sending anything', async () => {
    for (const uploadUrl of ['', 'https://evil.example.org/api/v1/uploads/u', '/api/v1/admin/tenants']) {
      const server = new FakeServer();
      const engine = createUploadEngine([{ name: 'a', file: blob(3), uploadUrl, offset: 0 }], {
        transport: server,
        cancelTransfer: async () => {},
        onOnline: () => () => {},
      });
      await expect(engine.start()).rejects.toMatchObject({ code: 'protocol-error' });
      expect(server.calls).toEqual([]);
    }
  });

  it('cancels before start', async () => {
    const h = setup([10], { offsets: [0] });
    await h.engine.cancel();
    expect(h.cancelTransfer).toHaveBeenCalledOnce();
    expect(h.engine.getSnapshot().phase).toBe('cancelled');
  });

  it('announces slow progress every 30 s even within a 10 % step', async () => {
    const h = setup([1000], { offsets: [0], deps: { chunkSize: 1000 } });
    h.server.patchFaults.push({
      kind: 'steps',
      steps: [
        [20_000, 10],
        [20_000, 20],
        [20_000, 30],
        [20_000, 40],
        [1, 150],
        [1, 160],
        [1, 1000],
      ],
    });
    const done = h.engine.start();
    await tick(100_000);
    await expect(done).resolves.toBe('completed');
    const progress = h.announcements.filter((a) => a.kind === 'progress');
    expect(progress).toEqual([
      { kind: 'progress', percent: 2 },
      { kind: 'progress', percent: 4 },
      { kind: 'progress', percent: 15 },
    ]);
  });

  it('stops notifying unsubscribed listeners', async () => {
    const h = setup([10], { offsets: [0] });
    const seen: UploadSnapshot[] = [];
    const unsubscribe = h.engine.subscribe((s) => seen.push(s));
    const unannounce = h.engine.onAnnounce(() => seen.push(h.engine.getSnapshot()));
    expect(seen).toHaveLength(1);
    unsubscribe();
    unannounce();
    await h.engine.start();
    expect(seen).toHaveLength(1);
  });

  it('listens to the window online event by default', async () => {
    const add = vi.fn();
    const remove = vi.fn();
    vi.stubGlobal('addEventListener', add);
    vi.stubGlobal('removeEventListener', remove);
    try {
      const server = new FakeServer();
      server.add('/api/v1/uploads/u', 10);
      server.patchFaults.push({ kind: 'cut', keep: 0 });
      const engine = createUploadEngine(
        [{ name: 'a', file: blob(10), uploadUrl: '/api/v1/uploads/u', offset: 0 }],
        {
          transport: server,
          cancelTransfer: async () => {},
        },
      );
      const done = engine.start();
      await tick();
      expect(add).toHaveBeenCalledWith('online', expect.any(Function));
      (add.mock.calls[0]?.[1] as () => void)();
      await tick();
      await expect(done).resolves.toBe('completed');
      expect(remove).toHaveBeenCalledWith('online', add.mock.calls[0]?.[1]);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('works without a global event target', async () => {
    const server = new FakeServer();
    server.add('/api/v1/uploads/u', 3);
    const engine = createUploadEngine(
      [{ name: 'a', file: blob(3), uploadUrl: '/api/v1/uploads/u', offset: 0 }],
      {
        transport: server,
        cancelTransfer: async () => {},
      },
    );
    await expect(engine.start()).resolves.toBe('completed');
  });
});
